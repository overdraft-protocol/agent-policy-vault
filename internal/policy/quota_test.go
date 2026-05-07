package policy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestReserveQuota_UnderLimit(t *testing.T) {
	ctx := context.Background()
	m := &memoryQuotaStore{}
	c := Constraints{
		RateLimit: &RateLimitConstraint{MaxPerMinute: 5, MaxPerHour: 10},
		Quotas:    &QuotaConstraint{DailyRequestCap: 20, MonthlyRequestCap: 100},
	}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	violated, err := reserveQuota(ctx, m, "g1", c, now)
	if err != nil {
		t.Fatalf("reserveQuota: %v", err)
	}
	if violated != "" {
		t.Fatalf("unexpected violation: %q", violated)
	}
}

func TestReserveQuota_ExceedMinuteRollsBack(t *testing.T) {
	ctx := context.Background()
	m := &memoryQuotaStore{}
	c := Constraints{
		RateLimit: &RateLimitConstraint{MaxPerMinute: 2},
	}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		v, err := reserveQuota(ctx, m, "g1", c, now)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if v != "" {
			t.Fatalf("iter %d: unexpected %q", i, v)
		}
	}
	v, err := reserveQuota(ctx, m, "g1", c, now)
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if v != "rate_limit_minute" {
		t.Fatalf("want rate_limit_minute, got %q", v)
	}
	// Counters rolled back: only two minute increments should remain.
	m.mu.Lock()
	defer m.mu.Unlock()
	minK, _, _, _ := bucketKeysFor(now)
	key := "g1|" + minK
	if m.values[key] != 2 {
		t.Fatalf("after failed third reserve, minute bucket = %d, want 2", m.values[key])
	}
}

func TestReserveQuota_ConcurrentIncrements(t *testing.T) {
	ctx := context.Background()
	m := &memoryQuotaStore{}
	c := Constraints{
		RateLimit: &RateLimitConstraint{MaxPerMinute: 100},
	}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = reserveQuota(ctx, m, "g-conc", c, now)
		}()
	}
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	minK, _, _, _ := bucketKeysFor(now)
	key := "g-conc|" + minK
	got := m.values[key]
	if got > 100 {
		t.Fatalf("minute bucket %d exceeds cap 100", got)
	}
}

func TestBucketKeysForUTC(t *testing.T) {
	now := time.Date(2026, 3, 9, 15, 4, 0, 0, time.FixedZone("EST", -5*3600))
	min, hr, day, month := bucketKeysFor(now)
	if want := "minute:2026-03-09T20:04"; min != want {
		t.Errorf("minute key = %q, want %q", min, want)
	}
	if want := "hour:2026-03-09T20"; hr != want {
		t.Errorf("hour key = %q, want %q", hr, want)
	}
	if want := "day:2026-03-09"; day != want {
		t.Errorf("day key = %q, want %q", day, want)
	}
	if want := "month:2026-03"; month != want {
		t.Errorf("month key = %q, want %q", month, want)
	}
}
