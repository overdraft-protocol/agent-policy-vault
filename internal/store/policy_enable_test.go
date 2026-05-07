package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/policy"
)

func TestEnableDisablePolicyLatestAny(t *testing.T) {
	ctx := context.Background()
	s := openTestDB(t)
	ns, err := s.GetVault(ctx, "default")
	if err != nil || ns == nil {
		t.Fatalf("GetVault: %v", err)
	}
	const yaml = `apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: lifecycle-test
  vault: default
spec:
  resources:
    - credential_key: K
      service_host: api.example.com
  rules:
    - id: allow-read
      effect: allow
      methods: [GET]
      path_patterns: ["/**"]
`
	p, err := policy.LoadPolicy([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := policy.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.InsertPolicyVersion(ctx, PolicyRow{
		VaultID:     ns.ID,
		PolicyID:    p.Metadata.ID,
		Version:     1,
		Enabled:     true,
		YAMLSource:  yaml,
		ContentHash: hash,
		ParentHash:  "",
		Description: "",
		AuthoredBy:  "u1",
	})
	if err != nil {
		t.Fatal(err)
	}
	row, err := s.GetLatestPolicy(ctx, ns.ID, p.Metadata.ID)
	if err != nil || row == nil {
		t.Fatalf("GetLatestPolicy: %v row=%v", err, row)
	}
	if !row.Enabled {
		t.Fatal("expected enabled")
	}
	if err := s.DisablePolicy(ctx, ns.ID, p.Metadata.ID); err != nil {
		t.Fatal(err)
	}
	row, err = s.GetLatestPolicy(ctx, ns.ID, p.Metadata.ID)
	if err == nil && row != nil {
		t.Fatal("GetLatestPolicy should miss disabled policy")
	}
	anyRow, err := s.GetLatestPolicyAny(ctx, ns.ID, p.Metadata.ID)
	if err != nil || anyRow == nil {
		t.Fatalf("GetLatestPolicyAny: %v", err)
	}
	if anyRow.Enabled {
		t.Fatal("expected disabled row from GetLatestPolicyAny")
	}
	if err := s.EnablePolicy(ctx, ns.ID, p.Metadata.ID); err != nil {
		t.Fatal(err)
	}
	row, err = s.GetLatestPolicy(ctx, ns.ID, p.Metadata.ID)
	if err != nil || row == nil {
		t.Fatalf("after enable GetLatestPolicy: %v", err)
	}
	if !row.Enabled {
		t.Fatal("expected re-enabled")
	}
	// Enable on missing policy
	if err := s.EnablePolicy(ctx, ns.ID, "no-such-policy"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("want ErrNoRows, got %v", err)
	}
}
