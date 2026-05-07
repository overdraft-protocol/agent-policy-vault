package policy

import (
	"context"
	"fmt"
	"time"
)

// QuotaStore is the storage surface used by the engine for rate-limit
// and quota counters. The implementation lives in internal/store and
// uses the policy_quota_state table.
type QuotaStore interface {
	// IncrementBucket atomically adds delta to the named bucket and
	// returns the new value. expiresAt is set on the row when the
	// bucket is created (subsequent increments do not extend it).
	IncrementBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error)

	// DecrementBucket atomically subtracts delta. Used to roll back a
	// reservation when an upstream call fails before completion.
	DecrementBucket(ctx context.Context, grantID, bucketKey string, delta int) error

	// PruneExpiredBuckets removes rows whose expires_at has passed.
	PruneExpiredBuckets(ctx context.Context, now time.Time) (int, error)
}

// bucketKeysFor returns the keys to increment for a given grant under
// rate-limit and quota constraints, given the current time.
func bucketKeysFor(now time.Time) (minute, hour, day, month string) {
	utc := now.UTC()
	minute = fmt.Sprintf("minute:%s", utc.Format("2006-01-02T15:04"))
	hour = fmt.Sprintf("hour:%s", utc.Format("2006-01-02T15"))
	day = fmt.Sprintf("day:%s", utc.Format("2006-01-02"))
	month = fmt.Sprintf("month:%s", utc.Format("2006-01"))
	return
}

// bucketExpiry returns when a bucket of the given kind should be
// considered safe to prune. We over-provision by 5 minutes to absorb
// clock skew between writers and the pruner.
func bucketExpiry(now time.Time, kind string) time.Time {
	utc := now.UTC()
	switch kind {
	case "minute":
		return utc.Truncate(time.Minute).Add(time.Minute + 5*time.Minute)
	case "hour":
		return utc.Truncate(time.Hour).Add(time.Hour + 5*time.Minute)
	case "day":
		return utc.Truncate(24*time.Hour).Add(24*time.Hour + 5*time.Minute)
	case "month":
		// Approximate — exactness here only affects pruning.
		return utc.AddDate(0, 1, 0).Add(5 * time.Minute)
	}
	return utc.Add(time.Hour)
}

// reserveQuota increments all relevant counters. If any cap is
// exceeded, it rolls back the increments it already made and returns
// the violated limit name. Callers commit by doing nothing (the
// reservation is durable); on upstream failure they should call
// releaseQuota to restore the counters.
func reserveQuota(ctx context.Context, qs QuotaStore, grantID string, c Constraints, now time.Time) (string, error) {
	if qs == nil {
		return "", nil
	}
	minK, hourK, dayK, monthK := bucketKeysFor(now)

	type incRecord struct {
		key string
		exp time.Time
	}
	var done []incRecord
	rollback := func() {
		for _, r := range done {
			_ = qs.DecrementBucket(ctx, grantID, r.key, 1)
		}
	}

	if rl := c.RateLimit; rl != nil {
		if rl.MaxPerMinute > 0 {
			n, err := qs.IncrementBucket(ctx, grantID, minK, 1, bucketExpiry(now, "minute"))
			if err != nil {
				rollback()
				return "rate_limit", err
			}
			done = append(done, incRecord{minK, bucketExpiry(now, "minute")})
			if n > rl.MaxPerMinute {
				rollback()
				return "rate_limit_minute", nil
			}
		}
		if rl.MaxPerHour > 0 {
			n, err := qs.IncrementBucket(ctx, grantID, hourK, 1, bucketExpiry(now, "hour"))
			if err != nil {
				rollback()
				return "rate_limit", err
			}
			done = append(done, incRecord{hourK, bucketExpiry(now, "hour")})
			if n > rl.MaxPerHour {
				rollback()
				return "rate_limit_hour", nil
			}
		}
	}
	if q := c.Quotas; q != nil {
		if q.DailyRequestCap > 0 {
			n, err := qs.IncrementBucket(ctx, grantID, dayK, 1, bucketExpiry(now, "day"))
			if err != nil {
				rollback()
				return "quota", err
			}
			done = append(done, incRecord{dayK, bucketExpiry(now, "day")})
			if n > q.DailyRequestCap {
				rollback()
				return "quota_daily", nil
			}
		}
		if q.MonthlyRequestCap > 0 {
			n, err := qs.IncrementBucket(ctx, grantID, monthK, 1, bucketExpiry(now, "month"))
			if err != nil {
				rollback()
				return "quota", err
			}
			done = append(done, incRecord{monthK, bucketExpiry(now, "month")})
			if n > q.MonthlyRequestCap {
				rollback()
				return "quota_monthly", nil
			}
		}
	}
	return "", nil
}

// releaseQuota undoes a reservation. Called on upstream error so the
// caller is not penalized for an event they didn't get to use. Errors
// here are swallowed at call site but returned for visibility.
func releaseQuota(ctx context.Context, qs QuotaStore, grantID string, c Constraints, now time.Time) error {
	if qs == nil {
		return nil
	}
	minK, hourK, dayK, monthK := bucketKeysFor(now)
	if rl := c.RateLimit; rl != nil {
		if rl.MaxPerMinute > 0 {
			_ = qs.DecrementBucket(ctx, grantID, minK, 1)
		}
		if rl.MaxPerHour > 0 {
			_ = qs.DecrementBucket(ctx, grantID, hourK, 1)
		}
	}
	if q := c.Quotas; q != nil {
		if q.DailyRequestCap > 0 {
			_ = qs.DecrementBucket(ctx, grantID, dayK, 1)
		}
		if q.MonthlyRequestCap > 0 {
			_ = qs.DecrementBucket(ctx, grantID, monthK, 1)
		}
	}
	return nil
}
