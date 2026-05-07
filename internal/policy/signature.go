package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"
)

// CanonicalHash returns the hex-encoded sha256 of the canonical YAML
// form of the policy (status field excluded — it's server-side only).
// Determinism is critical: this hash is stored on the row and must
// match on every evaluation, so the canonicalization must be stable
// regardless of the original input format (JSON vs YAML, key order).
func CanonicalHash(p *Policy) (string, error) {
	// Project the policy to a stable shape with status stripped and
	// fields in a fixed order via the struct definition. yaml.Marshal
	// emits keys in struct field order — sufficient for stability so
	// long as we never reorder the struct fields without a migration.
	canonical := struct {
		APIVersion string         `yaml:"apiVersion"`
		Kind       string         `yaml:"kind"`
		Metadata   PolicyMetadata `yaml:"metadata"`
		Spec       PolicySpec     `yaml:"spec"`
	}{
		APIVersion: p.APIVersion,
		Kind:       p.Kind,
		Metadata: PolicyMetadata{
			ID:          p.Metadata.ID,
			Vault:       p.Metadata.Vault,
			Version:     p.Metadata.Version,
			ParentHash:  p.Metadata.ParentHash,
			Description: p.Metadata.Description,
		},
		Spec: p.Spec,
	}
	buf, err := yaml.Marshal(&canonical)
	if err != nil {
		return "", fmt.Errorf("policy: canonical marshal: %w", err)
	}
	sum := sha256.Sum256(buf)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// VerifyHash recomputes the canonical hash and compares to expected.
// Returns nil iff they match; otherwise an error suitable for audit.
func VerifyHash(p *Policy, expected string) error {
	got, err := CanonicalHash(p)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("policy hash mismatch: have=%s want=%s", got, expected)
	}
	return nil
}
