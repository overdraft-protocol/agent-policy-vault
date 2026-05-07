// Package policy implements the Policy Decision Point (PDP) for
// agent-policy-vault. The engine evaluates each proxied request
// against declarative YAML policies bound to agents via Grants and
// returns an Allow/Deny decision before the upstream call is made.
//
// Trust model: policies and grants are mutated only by users
// (ActorType="user") with vault role member or admin. Agents (proxy
// role) cannot create, update, or revoke policies or grants. Every
// policy version is content-addressed (sha256) and chained to its
// parent so tampering is detected on each evaluation.
package policy

import (
	"time"
)

// Effect is the outcome a Rule produces when its match conditions are
// satisfied. The default for a request that matches no rule is Deny —
// the engine is fail-closed.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// SubjectType identifies the principal a Grant binds to.
type SubjectType string

const (
	SubjectAgent SubjectType = "agent"
	SubjectUser  SubjectType = "user"
)

// Policy is a versioned, content-addressed authorization policy. The
// fields under Status are populated by the server on persistence and
// are read-only from clients.
type Policy struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Metadata   PolicyMetadata `yaml:"metadata" json:"metadata"`
	Spec       PolicySpec     `yaml:"spec" json:"spec"`
	Status     PolicyStatus   `yaml:"status,omitempty" json:"status,omitempty"`
}

type PolicyMetadata struct {
	ID          string `yaml:"id" json:"id"`
	Vault       string `yaml:"vault" json:"vault"`
	Version     int    `yaml:"version,omitempty" json:"version,omitempty"`
	ParentHash  string `yaml:"parent_hash,omitempty" json:"parent_hash,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type PolicySpec struct {
	Resources   []Resource  `yaml:"resources" json:"resources"`
	Rules       []Rule      `yaml:"rules" json:"rules"`
	Constraints Constraints `yaml:"constraints,omitempty" json:"constraints,omitempty"`
}

// Resource scopes a Policy to a specific (credential, host) pair. A
// Policy may bind to multiple resources; a single matching resource is
// sufficient for the policy to apply to a request.
type Resource struct {
	CredentialKey string `yaml:"credential_key" json:"credential_key"`
	ServiceHost   string `yaml:"service_host" json:"service_host"`
}

// Rule is a single allow/deny clause. Rules within a policy are
// evaluated in declaration order; the first matching rule decides the
// outcome (first-match-wins).
type Rule struct {
	ID           string   `yaml:"id" json:"id"`
	Effect       Effect   `yaml:"effect" json:"effect"`
	Methods      []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	PathPatterns []string `yaml:"path_patterns,omitempty" json:"path_patterns,omitempty"`
	Description  string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// Constraints are AND-applied to allow decisions. A request that
// matches an allow rule but violates any constraint is denied.
type Constraints struct {
	Body       *BodyConstraint       `yaml:"body,omitempty" json:"body,omitempty"`
	RateLimit  *RateLimitConstraint  `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
	Quotas     *QuotaConstraint      `yaml:"quotas,omitempty" json:"quotas,omitempty"`
	TimeWindow *TimeWindowConstraint `yaml:"time_window,omitempty" json:"time_window,omitempty"`
}

// BodyConstraint inspects the request body. If the body parses as JSON,
// ForbiddenJSONPaths uses gjson-style dot/bracket paths (e.g. $.amount,
// items.0.price). Non-JSON bodies skip this check.
type BodyConstraint struct {
	ForbiddenJSONPaths []string `yaml:"forbidden_json_paths,omitempty" json:"forbidden_json_paths,omitempty"`
	MaxBytes           int64    `yaml:"max_bytes,omitempty" json:"max_bytes,omitempty"`
}

type RateLimitConstraint struct {
	MaxPerMinute int `yaml:"max_per_minute,omitempty" json:"max_per_minute,omitempty"`
	MaxPerHour   int `yaml:"max_per_hour,omitempty" json:"max_per_hour,omitempty"`
}

type QuotaConstraint struct {
	DailyRequestCap   int `yaml:"daily_request_cap,omitempty" json:"daily_request_cap,omitempty"`
	MonthlyRequestCap int `yaml:"monthly_request_cap,omitempty" json:"monthly_request_cap,omitempty"`
}

// TimeWindowConstraint accepts a list of "HH:MM-HH:MM" intervals. A
// request occurring outside any interval (in the named TZ) is denied.
type TimeWindowConstraint struct {
	AllowedHoursLocal []string `yaml:"allowed_hours_local,omitempty" json:"allowed_hours_local,omitempty"`
	Timezone          string   `yaml:"timezone,omitempty" json:"timezone,omitempty"`
}

type PolicyStatus struct {
	ContentHash string    `yaml:"content_hash,omitempty" json:"content_hash,omitempty"`
	AuthoredBy  string    `yaml:"authored_by,omitempty" json:"authored_by,omitempty"`
	AuthoredAt  time.Time `yaml:"authored_at,omitempty" json:"authored_at,omitempty"`
}

// Grant binds a subject to a policy in a vault, with optional expiry
// and conditions. Grants are cumulative-deny: when multiple grants
// apply to a request, ALL must allow.
type Grant struct {
	APIVersion string        `yaml:"apiVersion" json:"apiVersion"`
	Kind       string        `yaml:"kind" json:"kind"`
	Metadata   GrantMetadata `yaml:"metadata" json:"metadata"`
	Spec       GrantSpec     `yaml:"spec" json:"spec"`
	Status     GrantStatus   `yaml:"status,omitempty" json:"status,omitempty"`
}

type GrantMetadata struct {
	ID    string `yaml:"id,omitempty" json:"id,omitempty"`
	Vault string `yaml:"vault" json:"vault"`
}

type GrantSpec struct {
	Subject    Subject         `yaml:"subject" json:"subject"`
	PolicyRef  PolicyRef       `yaml:"policy_ref" json:"policy_ref"`
	ExpiresAt  *time.Time      `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
	Conditions GrantConditions `yaml:"conditions,omitempty" json:"conditions,omitempty"`
}

type Subject struct {
	ActorType SubjectType `yaml:"actor_type" json:"actor_type"`
	ActorID   string      `yaml:"actor_id" json:"actor_id"`
}

type PolicyRef struct {
	ID      string `yaml:"id" json:"id"`
	Version int    `yaml:"version,omitempty" json:"version,omitempty"` // 0 = always-latest
}

type GrantConditions struct {
	RequireHumanApproval bool `yaml:"require_human_approval,omitempty" json:"require_human_approval,omitempty"`
}

type GrantStatus struct {
	GrantedBy string     `yaml:"granted_by,omitempty" json:"granted_by,omitempty"`
	GrantedAt time.Time  `yaml:"granted_at,omitempty" json:"granted_at,omitempty"`
	RevokedAt *time.Time `yaml:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	RevokedBy string     `yaml:"revoked_by,omitempty" json:"revoked_by,omitempty"`
}

// EvalContext is the input to Engine.Evaluate. It is assembled by the
// proxy ingress after credential resolution and before the upstream
// RoundTrip. Body is already materialized (size-limited by
// brokercore.MaxProxyBodyBytes).
type EvalContext struct {
	VaultID       string
	ActorType     string // "user" | "agent"
	ActorID       string
	TargetHost    string
	MatchedHost   string
	CredentialKey string
	Method        string
	Path          string
	RawQuery      string
	Body          []byte
	Now           time.Time
}

// Decision is the engine's verdict. RuleID and PolicyID identify the
// rule/policy that produced the verdict (for allow: the matching allow
// rule; for deny: the deny rule, the constraint that tripped, or the
// reserved sentinel "default-deny" / "no-grant" / "hash-mismatch").
type Decision struct {
	Allow    bool
	Reason   string
	RuleID   string
	PolicyID string
	GrantID  string
}

// SentinelRule values used in Decision.RuleID when no specific rule is
// responsible (e.g. default deny, no applicable grant, tamper).
const (
	RuleDefaultDeny    = "default-deny"
	RuleNoGrant        = "no-grant"
	RuleHashMismatch   = "hash-mismatch"
	RuleGrantExpired   = "grant-expired"
	RuleConstraintBody = "constraint-body"
	RuleConstraintRate = "constraint-rate"
	RuleConstraintQuot = "constraint-quota"
	RuleConstraintTime = "constraint-time"
)
