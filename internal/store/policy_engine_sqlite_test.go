package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/policy"
)

func TestEngineDeniesWhenYAMLSourceTampered(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)

	ns, err := s.GetVault(ctx, "default")
	if err != nil || ns == nil {
		t.Fatalf("GetVault: %v ns=%v", err, ns)
	}

	const yaml = `apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: tamper-test
  vault: default
spec:
  resources:
    - credential_key: KEY
      service_host: api.example.com
  rules:
    - id: allow-get
      effect: allow
      methods: [GET]
      path_patterns: ["/v1/**"]
`
	p, err := policy.LoadPolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	p.Metadata.Version = 1
	p.Metadata.ParentHash = ""
	hash, err := policy.CanonicalHash(p)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}

	_, err = s.InsertPolicyVersion(ctx, PolicyRow{
		VaultID:     ns.ID,
		PolicyID:    p.Metadata.ID,
		Version:     1,
		Enabled:     true,
		YAMLSource:  yaml,
		ContentHash: hash,
		ParentHash:  "",
		Description: p.Metadata.Description,
		AuthoredBy:  "test",
	})
	if err != nil {
		t.Fatalf("InsertPolicyVersion: %v", err)
	}

	ag, err := s.CreateAgent(ctx, "tamper-bot", "c", "member")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := s.GrantVaultRole(ctx, ag.ID, "agent", ns.ID, "member"); err != nil {
		t.Fatalf("GrantVaultRole: %v", err)
	}
	_, err = s.InsertGrant(ctx, GrantRow{
		VaultID:       ns.ID,
		SubjectType:   "agent",
		SubjectID:     ag.ID,
		PolicyID:      p.Metadata.ID,
		PolicyVersion: 1,
		GrantedBy:     "test",
	})
	if err != nil {
		t.Fatalf("InsertGrant: %v", err)
	}

	bridge := NewPolicyBridge(s)
	adapter := policy.NewStoreAdapter(bridge)
	eng := policy.NewEngine(adapter, adapter, adapter)

	ec := policy.EvalContext{
		VaultID:       ns.ID,
		ActorType:     "agent",
		ActorID:       ag.ID,
		MatchedHost:   "api.example.com",
		TargetHost:    "api.example.com",
		CredentialKey: "KEY",
		Method:        "GET",
		Path:          "/v1/x",
		Now:           time.Now(),
	}
	d, err := eng.Evaluate(ctx, ec)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Allow {
		t.Fatalf("expected allow before tamper, got %+v", d)
	}

	// Tamper with something that survives YAML parse (comments do not).
	tampered := strings.Replace(yaml, "allow-get", "allow-get-x", 1)
	_, err = s.db.ExecContext(ctx,
		`UPDATE policies SET yaml_source = ? WHERE vault_id = ? AND policy_id = ?`,
		tampered, ns.ID, p.Metadata.ID)
	if err != nil {
		t.Fatalf("tamper update: %v", err)
	}

	d, err = eng.Evaluate(ctx, ec)
	if err != nil {
		t.Fatalf("Evaluate after tamper: %v", err)
	}
	if d.Allow {
		t.Fatalf("expected deny after tamper, got allow")
	}
	if d.RuleID != policy.RuleHashMismatch {
		t.Fatalf("rule = %q, want %q", d.RuleID, policy.RuleHashMismatch)
	}
}
