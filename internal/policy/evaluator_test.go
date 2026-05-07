package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// stubResolver returns canned grants and policies. Used so the
// evaluator tests don't need to spin up a SQLite store.
type stubResolver struct {
	grants   []GrantRecord
	policies map[string]*PolicyRecord // key: policyID
	err      error
}

func (s *stubResolver) ListGrantsForSubject(_ context.Context, _, _, _ string) ([]GrantRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.grants, nil
}

func (s *stubResolver) GetPolicyVersion(_ context.Context, _, policyID string, _ int) (*PolicyRecord, error) {
	rec, ok := s.policies[policyID]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// memoryQuotaStore is an in-memory QuotaStore for evaluator tests.
type memoryQuotaStore struct {
	mu     sync.Mutex
	values map[string]int
}

func (m *memoryQuotaStore) IncrementBucket(_ context.Context, grantID, bucket string, delta int, _ time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = make(map[string]int)
	}
	k := grantID + "|" + bucket
	m.values[k] += delta
	return m.values[k], nil
}

func (m *memoryQuotaStore) DecrementBucket(_ context.Context, grantID, bucket string, delta int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := grantID + "|" + bucket
	m.values[k] -= delta
	if m.values[k] < 0 {
		m.values[k] = 0
	}
	return nil
}

func (m *memoryQuotaStore) PruneExpiredBuckets(context.Context, time.Time) (int, error) {
	return 0, nil
}

// mustHash is a test helper that panics on hash failure.
func mustHash(t *testing.T, p *Policy) string {
	t.Helper()
	h, err := CanonicalHash(p)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	return h
}

func newTestPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadPolicy([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}

func newTestEvalCtx(method, path string, body []byte) EvalContext {
	return EvalContext{
		VaultID:       "vault-prod",
		ActorType:     "agent",
		ActorID:       "support-bot",
		MatchedHost:   "api.stripe.com",
		TargetHost:    "api.stripe.com",
		CredentialKey: "STRIPE_API_KEY",
		Method:        method,
		Path:          path,
		Body:          body,
		// Pin time to 12:00 PT so the time_window in validPolicyYAML allows it.
		Now: mustTime("2026-05-07T12:00:00-07:00"),
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func resolverWithPolicy(t *testing.T, p *Policy, grant GrantRecord) *stubResolver {
	t.Helper()
	return &stubResolver{
		grants: []GrantRecord{grant},
		policies: map[string]*PolicyRecord{
			p.Metadata.ID: {
				Policy:      p,
				Version:     1,
				ContentHash: mustHash(t, p),
				Enabled:     true,
			},
		},
	}
}

func TestEvaluate_AllowAndDeny(t *testing.T) {
	p := newTestPolicy(t)
	grant := GrantRecord{
		ID:            "gnt_1",
		VaultID:       "vault-prod",
		SubjectType:   "agent",
		SubjectID:     "support-bot",
		PolicyID:      p.Metadata.ID,
		PolicyVersion: 1,
	}
	r := resolverWithPolicy(t, p, grant)
	eng := NewEngine(r, nil, nil)

	t.Run("allow GET /v1/customers", func(t *testing.T) {
		ec := newTestEvalCtx("GET", "/v1/customers", nil)
		d, err := eng.Evaluate(context.Background(), ec)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !d.Allow {
			t.Fatalf("expected allow, got deny: %+v", d)
		}
		if d.RuleID != "allow-customer-reads" {
			t.Errorf("rule = %q", d.RuleID)
		}
	})

	t.Run("deny POST /v1/customers", func(t *testing.T) {
		ec := newTestEvalCtx("POST", "/v1/customers", nil)
		d, _ := eng.Evaluate(context.Background(), ec)
		if d.Allow {
			t.Fatalf("expected deny, got allow")
		}
		if d.RuleID != "deny-mutations" {
			t.Errorf("rule = %q", d.RuleID)
		}
	})

	t.Run("default deny GET /unmatched", func(t *testing.T) {
		ec := newTestEvalCtx("GET", "/v1/refunds", nil)
		d, _ := eng.Evaluate(context.Background(), ec)
		if d.Allow {
			t.Fatalf("expected default-deny, got allow")
		}
		if d.RuleID != RuleDefaultDeny {
			t.Errorf("rule = %q", d.RuleID)
		}
	})
}

func TestEvaluate_NoGrant(t *testing.T) {
	p := newTestPolicy(t)
	// resolver with NO grants.
	r := &stubResolver{policies: map[string]*PolicyRecord{
		p.Metadata.ID: {Policy: p, Version: 1, ContentHash: mustHash(t, p), Enabled: true},
	}}
	eng := NewEngine(r, nil, nil)
	ec := newTestEvalCtx("GET", "/v1/customers", nil)
	d, _ := eng.Evaluate(context.Background(), ec)
	if d.Allow {
		t.Fatalf("expected deny when no grant exists")
	}
	if d.RuleID != RuleNoGrant {
		t.Errorf("rule = %q, want %q", d.RuleID, RuleNoGrant)
	}
}

func TestEvaluate_HashMismatch(t *testing.T) {
	p := newTestPolicy(t)
	grant := GrantRecord{
		ID: "gnt", SubjectType: "agent", SubjectID: "support-bot",
		PolicyID: p.Metadata.ID, PolicyVersion: 1,
	}
	// Resolver returns a stale hash → tamper detected.
	r := &stubResolver{
		grants: []GrantRecord{grant},
		policies: map[string]*PolicyRecord{
			p.Metadata.ID: {
				Policy:      p,
				Version:     1,
				ContentHash: "sha256:bogus",
				Enabled:     true,
			},
		},
	}
	eng := NewEngine(r, nil, nil)
	d, _ := eng.Evaluate(context.Background(), newTestEvalCtx("GET", "/v1/customers", nil))
	if d.Allow {
		t.Fatalf("expected deny on hash mismatch")
	}
	if d.RuleID != RuleHashMismatch {
		t.Errorf("rule = %q want %q", d.RuleID, RuleHashMismatch)
	}
}

func TestEvaluate_GrantExpired(t *testing.T) {
	p := newTestPolicy(t)
	past := mustTime("2026-05-07T11:00:00-07:00") // before ec.Now (12:00)
	grant := GrantRecord{
		ID: "gnt", SubjectType: "agent", SubjectID: "support-bot",
		PolicyID: p.Metadata.ID, PolicyVersion: 1,
		ExpiresAt: &past,
	}
	r := resolverWithPolicy(t, p, grant)
	eng := NewEngine(r, nil, nil)
	d, _ := eng.Evaluate(context.Background(), newTestEvalCtx("GET", "/v1/customers", nil))
	if d.Allow {
		t.Fatalf("expected deny when grant expired")
	}
	// Expired grants are skipped, so we end up with no-grant.
	if d.RuleID != RuleNoGrant {
		t.Errorf("rule = %q want %q", d.RuleID, RuleNoGrant)
	}
}

func TestEvaluate_TimeWindowDeny(t *testing.T) {
	p := newTestPolicy(t)
	grant := GrantRecord{
		ID: "gnt", SubjectType: "agent", SubjectID: "support-bot",
		PolicyID: p.Metadata.ID, PolicyVersion: 1,
	}
	r := resolverWithPolicy(t, p, grant)
	eng := NewEngine(r, nil, nil)

	ec := newTestEvalCtx("GET", "/v1/customers", nil)
	// Force the request outside the 09:00-17:00 PT window.
	ec.Now = mustTime("2026-05-07T22:00:00-07:00")
	d, _ := eng.Evaluate(context.Background(), ec)
	if d.Allow {
		t.Fatalf("expected deny outside time window")
	}
	if d.RuleID != RuleConstraintTime {
		t.Errorf("rule = %q want %q", d.RuleID, RuleConstraintTime)
	}
}

func TestEvaluate_BodyForbiddenPath(t *testing.T) {
	// Build a policy that allows POST and forbids JSON path $.amount.
	src := `apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: forbid-amount
  vault: prod
spec:
  resources:
    - credential_key: STRIPE_API_KEY
      service_host: api.stripe.com
  rules:
    - id: allow-post-anything
      effect: allow
      methods: [POST]
  constraints:
    body:
      forbidden_json_paths: ["amount"]
`
	p, err := LoadPolicy([]byte(src))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	grant := GrantRecord{
		ID: "gnt", SubjectType: "agent", SubjectID: "support-bot",
		PolicyID: p.Metadata.ID, PolicyVersion: 1,
	}
	r := resolverWithPolicy(t, p, grant)
	eng := NewEngine(r, nil, nil)

	t.Run("body without amount: allow", func(t *testing.T) {
		ec := newTestEvalCtx("POST", "/v1/charges", []byte(`{"description":"x"}`))
		d, _ := eng.Evaluate(context.Background(), ec)
		if !d.Allow {
			t.Fatalf("expected allow, got %+v", d)
		}
	})
	t.Run("body with amount: deny", func(t *testing.T) {
		ec := newTestEvalCtx("POST", "/v1/charges", []byte(`{"amount":1000}`))
		d, _ := eng.Evaluate(context.Background(), ec)
		if d.Allow {
			t.Fatalf("expected deny, got allow")
		}
		if d.RuleID != RuleConstraintBody {
			t.Errorf("rule = %q want %q", d.RuleID, RuleConstraintBody)
		}
	})
}

func TestEvaluate_RateLimit(t *testing.T) {
	src := `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: rl-pol, vault: prod}
spec:
  resources: [{credential_key: STRIPE_API_KEY, service_host: api.stripe.com}]
  rules: [{id: allow-all-reads, effect: allow, methods: [GET]}]
  constraints:
    rate_limit: {max_per_minute: 2}
`
	p, err := LoadPolicy([]byte(src))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	grant := GrantRecord{
		ID: "gnt-rl", SubjectType: "agent", SubjectID: "support-bot",
		PolicyID: p.Metadata.ID, PolicyVersion: 1,
	}
	r := resolverWithPolicy(t, p, grant)
	q := &memoryQuotaStore{}
	eng := NewEngine(r, q, nil)

	ec := newTestEvalCtx("GET", "/v1/customers", nil)
	// First two requests should pass.
	for i := 0; i < 2; i++ {
		d, _ := eng.Evaluate(context.Background(), ec)
		if !d.Allow {
			t.Fatalf("call %d: expected allow, got %+v", i, d)
		}
	}
	// Third should trip rate-limit.
	d, _ := eng.Evaluate(context.Background(), ec)
	if d.Allow {
		t.Fatalf("expected rate-limit deny on call 3")
	}
	if d.RuleID != RuleConstraintRate {
		t.Errorf("rule = %q want %q", d.RuleID, RuleConstraintRate)
	}
}

func TestEvaluate_CumulativeDeny(t *testing.T) {
	// Two grants: one allows GET, the other denies all writes. A POST
	// must be denied by the second even though the first wouldn't match.
	allowGet := mustLoadPolicy(t, `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: allow-get, vault: prod}
spec:
  resources: [{credential_key: STRIPE_API_KEY, service_host: api.stripe.com}]
  rules: [{id: allow-reads, effect: allow, methods: [GET]}]
`)
	denyWrites := mustLoadPolicy(t, `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: deny-writes, vault: prod}
spec:
  resources: [{credential_key: STRIPE_API_KEY, service_host: api.stripe.com}]
  rules: [{id: block-writes, effect: deny, methods: [POST, PUT, DELETE]}]
`)

	r := &stubResolver{
		grants: []GrantRecord{
			{ID: "g1", SubjectType: "agent", SubjectID: "support-bot",
				PolicyID: "allow-get", PolicyVersion: 1},
			{ID: "g2", SubjectType: "agent", SubjectID: "support-bot",
				PolicyID: "deny-writes", PolicyVersion: 1},
		},
		policies: map[string]*PolicyRecord{
			"allow-get":   {Policy: allowGet, Version: 1, ContentHash: mustHash(t, allowGet), Enabled: true},
			"deny-writes": {Policy: denyWrites, Version: 1, ContentHash: mustHash(t, denyWrites), Enabled: true},
		},
	}
	eng := NewEngine(r, nil, nil)
	d, _ := eng.Evaluate(context.Background(), newTestEvalCtx("POST", "/v1/customers", nil))
	if d.Allow {
		t.Fatalf("expected cumulative-deny, got allow")
	}
}

func TestEvaluate_ResolverError(t *testing.T) {
	r := &stubResolver{err: errors.New("db down")}
	eng := NewEngine(r, nil, nil)
	d, _ := eng.Evaluate(context.Background(), newTestEvalCtx("GET", "/v1/customers", nil))
	if d.Allow {
		t.Fatalf("expected fail-closed deny on resolver error")
	}
}

func mustLoadPolicy(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := LoadPolicy([]byte(src))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return p
}
