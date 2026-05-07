package policy

import (
	"strings"
	"testing"
	"time"
)

const validPolicyYAML = `
apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: stripe-readonly-customers
  vault: prod
  description: Read-only Stripe customers
spec:
  resources:
    - credential_key: STRIPE_API_KEY
      service_host: api.stripe.com
  rules:
    - id: allow-customer-reads
      effect: allow
      methods: [GET]
      path_patterns: ["/v1/customers", "/v1/customers/**"]
    - id: deny-mutations
      effect: deny
      methods: [POST, PATCH, DELETE]
  constraints:
    body:
      forbidden_json_paths: ["$.amount"]
    rate_limit:
      max_per_minute: 30
    time_window:
      allowed_hours_local: ["09:00-17:00"]
      timezone: America/Los_Angeles
`

func TestLoadPolicy_RoundTrip(t *testing.T) {
	p, err := LoadPolicy([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.Metadata.ID != "stripe-readonly-customers" {
		t.Errorf("metadata.id = %q", p.Metadata.ID)
	}
	if got := len(p.Spec.Rules); got != 2 {
		t.Errorf("rules: got %d, want 2", got)
	}
	if p.Spec.Constraints.RateLimit.MaxPerMinute != 30 {
		t.Errorf("rate_limit not parsed: %+v", p.Spec.Constraints.RateLimit)
	}
}

func TestLoadPolicy_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"missing apiVersion": `kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow}]}
`,
		"bad apiVersion": `apiVersion: foo/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow}]}
`,
		"bad kind": `apiVersion: policy.agentvault/v1
kind: Foo
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow}]}
`,
		"missing resources": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {rules: [{id: r, effect: allow}]}
`,
		"missing rules": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}]}
`,
		"bad effect": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: maybe}]}
`,
		"bad method": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow, methods: [JUMP]}]}
`,
		"path pattern missing slash": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow, path_patterns: ["nope"]}]}
`,
		"bad time window": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec:
  resources: [{credential_key: K, service_host: h}]
  rules: [{id: r, effect: allow}]
  constraints: {time_window: {allowed_hours_local: ["25:00-26:00"]}}
`,
		"bad timezone": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec:
  resources: [{credential_key: K, service_host: h}]
  rules: [{id: r, effect: allow}]
  constraints: {time_window: {timezone: "Mars/Olympus_Mons", allowed_hours_local: ["09:00-17:00"]}}
`,
		"duplicate rule id": `apiVersion: policy.agentvault/v1
kind: Policy
metadata: {id: x, vault: prod}
spec: {resources: [{credential_key: K, service_host: h}], rules: [{id: r, effect: allow}, {id: r, effect: deny}]}
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicy([]byte(src)); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestLoadPolicy_AcceptsJSON(t *testing.T) {
	js := `{
		"apiVersion":"policy.agentvault/v1",
		"kind":"Policy",
		"metadata":{"id":"json-pol","vault":"prod"},
		"spec":{
			"resources":[{"credential_key":"K","service_host":"api.stripe.com"}],
			"rules":[{"id":"allow-reads","effect":"allow","methods":["GET"]}]
		}
	}`
	p, err := LoadPolicy([]byte(js))
	if err != nil {
		t.Fatalf("json LoadPolicy: %v", err)
	}
	if p.Metadata.ID != "json-pol" {
		t.Errorf("got id %q", p.Metadata.ID)
	}
}

func TestCanonicalHash_Deterministic(t *testing.T) {
	p, err := LoadPolicy([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	h1, err := CanonicalHash(p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// Mutate Status — must NOT affect hash.
	p.Status = PolicyStatus{ContentHash: "stale", AuthoredBy: "someone"}
	h2, err := CanonicalHash(p)
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash drifted with status mutation: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("hash missing prefix: %q", h1)
	}
}

func TestVerifyHash_DetectsTamper(t *testing.T) {
	p, err := LoadPolicy([]byte(validPolicyYAML))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	h, err := CanonicalHash(p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyHash(p, h); err != nil {
		t.Fatalf("VerifyHash unexpected: %v", err)
	}
	// Tamper with a rule.
	p.Spec.Rules[0].Effect = EffectDeny
	if err := VerifyHash(p, h); err == nil {
		t.Errorf("expected tamper detection")
	}
}

func TestLoadGrant_Valid(t *testing.T) {
	src := `
apiVersion: policy.agentvault/v1
kind: Grant
metadata:
  vault: prod
spec:
  subject:
    actor_type: agent
    actor_id: support-bot
  policy_ref:
    id: stripe-readonly-customers
    version: 3
`
	g, err := LoadGrant([]byte(src))
	if err != nil {
		t.Fatalf("LoadGrant: %v", err)
	}
	if g.Spec.Subject.ActorType != SubjectAgent || g.Spec.Subject.ActorID != "support-bot" {
		t.Errorf("subject parse failed: %+v", g.Spec.Subject)
	}
	if g.Spec.PolicyRef.Version != 3 {
		t.Errorf("version = %d", g.Spec.PolicyRef.Version)
	}
}

func TestValidateGrant_RejectsExpiredInPast(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	g := &Grant{
		APIVersion: APIVersionV1,
		Kind:       KindGrant,
		Metadata:   GrantMetadata{Vault: "prod"},
		Spec: GrantSpec{
			Subject:   Subject{ActorType: SubjectAgent, ActorID: "support-bot"},
			PolicyRef: PolicyRef{ID: "stripe-readonly-customers", Version: 1},
			ExpiresAt: &past,
		},
	}
	if err := ValidateGrant(g); err == nil {
		t.Errorf("expected past-expiry rejection")
	}
}
