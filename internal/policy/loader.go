package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	APIVersionV1 = "policy.agentvault/v1"
	KindPolicy   = "Policy"
	KindGrant    = "Grant"
)

// slugRE matches the same shape as agent and vault names elsewhere in
// the codebase: lowercase alphanumerics and hyphens, 3–64 chars,
// not starting or ending with a hyphen. Reusing the convention keeps
// IDs visually consistent across the system.
var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])?$`)

var (
	validMethods = map[string]struct{}{
		"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "PATCH": {},
		"DELETE": {}, "OPTIONS": {}, "*": {},
	}
)

// LoadPolicy parses YAML or JSON into a Policy and validates it.
// Detects format by leading byte ('{' or '[' = JSON).
func LoadPolicy(src []byte) (*Policy, error) {
	var p Policy
	if err := unmarshalAuto(src, &p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := ValidatePolicy(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadGrant parses YAML or JSON into a Grant and validates it.
func LoadGrant(src []byte) (*Grant, error) {
	var g Grant
	if err := unmarshalAuto(src, &g); err != nil {
		return nil, fmt.Errorf("grant: parse: %w", err)
	}
	if err := ValidateGrant(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

func unmarshalAuto(src []byte, dst any) error {
	trimmed := strings.TrimSpace(string(src))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal(src, dst)
	}
	return yaml.Unmarshal(src, dst)
}

// ValidatePolicy runs structural validation. It does not check
// references (e.g. that the vault exists) — that is the persistence
// layer's responsibility.
func ValidatePolicy(p *Policy) error {
	if p.APIVersion != APIVersionV1 {
		return fmt.Errorf("policy: unsupported apiVersion %q", p.APIVersion)
	}
	if p.Kind != KindPolicy {
		return fmt.Errorf("policy: kind must be %q, got %q", KindPolicy, p.Kind)
	}
	if !slugRE.MatchString(p.Metadata.ID) {
		return fmt.Errorf("policy: invalid metadata.id %q (must be slug)", p.Metadata.ID)
	}
	if !slugRE.MatchString(p.Metadata.Vault) {
		return fmt.Errorf("policy: invalid metadata.vault %q", p.Metadata.Vault)
	}
	if p.Metadata.Version < 0 {
		return fmt.Errorf("policy: metadata.version must be >= 0")
	}
	if len(p.Spec.Resources) == 0 {
		return fmt.Errorf("policy: spec.resources required (at least one)")
	}
	for i, r := range p.Spec.Resources {
		if r.CredentialKey == "" {
			return fmt.Errorf("policy: spec.resources[%d].credential_key required", i)
		}
		if r.ServiceHost == "" {
			return fmt.Errorf("policy: spec.resources[%d].service_host required", i)
		}
	}
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("policy: spec.rules required (at least one)")
	}
	seenRule := make(map[string]struct{}, len(p.Spec.Rules))
	for i, r := range p.Spec.Rules {
		if !slugRE.MatchString(r.ID) {
			return fmt.Errorf("policy: spec.rules[%d].id %q is not a valid slug", i, r.ID)
		}
		if _, dup := seenRule[r.ID]; dup {
			return fmt.Errorf("policy: spec.rules[%d].id %q duplicated", i, r.ID)
		}
		seenRule[r.ID] = struct{}{}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("policy: spec.rules[%d].effect must be allow|deny, got %q", i, r.Effect)
		}
		for _, m := range r.Methods {
			if _, ok := validMethods[strings.ToUpper(m)]; !ok {
				return fmt.Errorf("policy: spec.rules[%d]: invalid method %q", i, m)
			}
		}
		for _, pat := range r.PathPatterns {
			if pat == "" {
				return fmt.Errorf("policy: spec.rules[%d]: empty path_pattern", i)
			}
			if !strings.HasPrefix(pat, "/") {
				return fmt.Errorf("policy: spec.rules[%d]: path_pattern %q must start with /", i, pat)
			}
		}
	}
	if c := p.Spec.Constraints.TimeWindow; c != nil {
		if c.Timezone != "" {
			if _, err := time.LoadLocation(c.Timezone); err != nil {
				return fmt.Errorf("policy: invalid timezone %q: %w", c.Timezone, err)
			}
		}
		for _, w := range c.AllowedHoursLocal {
			if _, _, err := parseHourWindow(w); err != nil {
				return fmt.Errorf("policy: invalid allowed_hours_local %q: %w", w, err)
			}
		}
	}
	if c := p.Spec.Constraints.RateLimit; c != nil {
		if c.MaxPerMinute < 0 || c.MaxPerHour < 0 {
			return fmt.Errorf("policy: rate_limit values must be >= 0")
		}
	}
	if c := p.Spec.Constraints.Quotas; c != nil {
		if c.DailyRequestCap < 0 || c.MonthlyRequestCap < 0 {
			return fmt.Errorf("policy: quotas values must be >= 0")
		}
	}
	if c := p.Spec.Constraints.Body; c != nil {
		if c.MaxBytes < 0 {
			return fmt.Errorf("policy: body.max_bytes must be >= 0")
		}
	}
	return nil
}

// ValidateGrant validates a Grant's structural fields.
func ValidateGrant(g *Grant) error {
	if g.APIVersion != APIVersionV1 {
		return fmt.Errorf("grant: unsupported apiVersion %q", g.APIVersion)
	}
	if g.Kind != KindGrant {
		return fmt.Errorf("grant: kind must be %q, got %q", KindGrant, g.Kind)
	}
	if !slugRE.MatchString(g.Metadata.Vault) {
		return fmt.Errorf("grant: invalid metadata.vault %q", g.Metadata.Vault)
	}
	if g.Spec.Subject.ActorType != SubjectAgent && g.Spec.Subject.ActorType != SubjectUser {
		return fmt.Errorf("grant: subject.actor_type must be agent|user, got %q", g.Spec.Subject.ActorType)
	}
	if g.Spec.Subject.ActorID == "" {
		return fmt.Errorf("grant: subject.actor_id required")
	}
	if !slugRE.MatchString(g.Spec.PolicyRef.ID) {
		return fmt.Errorf("grant: policy_ref.id %q is not a valid slug", g.Spec.PolicyRef.ID)
	}
	if g.Spec.PolicyRef.Version < 0 {
		return fmt.Errorf("grant: policy_ref.version must be >= 0")
	}
	if g.Spec.ExpiresAt != nil && g.Spec.ExpiresAt.Before(time.Now().Add(-time.Minute)) {
		return fmt.Errorf("grant: expires_at is in the past")
	}
	return nil
}

// parseHourWindow parses "HH:MM-HH:MM" into [start, end] minute offsets.
// A wrap-around window (end <= start) is permitted and represents an
// interval that crosses midnight.
func parseHourWindow(w string) (int, int, error) {
	parts := strings.Split(w, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected HH:MM-HH:MM")
	}
	a, err := parseHourMinute(parts[0])
	if err != nil {
		return 0, 0, err
	}
	b, err := parseHourMinute(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

func parseHourMinute(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM")
	}
	var h, m int
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour %q", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute %q", parts[1])
	}
	return h*60 + m, nil
}
