package policy

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Engine is the public interface ingress code calls to gate a
// proxied request. Implementations must be safe for concurrent use.
type Engine interface {
	// Evaluate returns Allow/Deny for a single request. The caller
	// must NOT make the upstream call when Decision.Allow is false.
	Evaluate(ctx context.Context, ec EvalContext) (Decision, error)

	// OnRequestCompleted is called after the upstream call returns.
	// Implementations may use status to commit/rollback quota
	// reservations (e.g. release on 5xx). Best-effort; errors
	// returned are logged but do not affect the response.
	OnRequestCompleted(ctx context.Context, grantID string, policyID string, version int, statusCode int) error
}

// PolicyResolver fetches policies + grants for evaluation. Decoupled
// from the engine so the SQLite-backed implementation can live in
// internal/store without an import cycle.
type PolicyResolver interface {
	// ListGrantsForSubject returns active (not revoked, not expired)
	// grants for a (vault, subject_type, subject_id) tuple, ordered
	// by granted_at ascending. Caller must filter out grants that no
	// longer apply to the request resource.
	ListGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]GrantRecord, error)

	// GetPolicyVersion returns a specific version. If version <= 0
	// the latest enabled version is returned.
	GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*PolicyRecord, error)
}

// PolicyRecord is the persisted form of a Policy with the columns the
// engine needs for evaluation and tamper-checking.
type PolicyRecord struct {
	Policy      *Policy
	Version     int
	ContentHash string
	Enabled     bool
}

// GrantRecord is the persisted form of a Grant.
type GrantRecord struct {
	ID            string
	VaultID       string
	SubjectType   string
	SubjectID     string
	PolicyID      string
	PolicyVersion int // 0 = always-latest
	ExpiresAt     *time.Time
	Conditions    GrantConditions
	GrantedBy     string
	GrantedAt     time.Time
	RevokedAt     *time.Time
}

// engine is the concrete Engine implementation.
type engine struct {
	resolver PolicyResolver
	quotas   QuotaStore
	audit    AuditSink
	now      func() time.Time
}

// NewEngine wires the engine. quotas and audit may be nil; in that
// case rate-limit/quota constraints and audit emission are no-ops.
func NewEngine(r PolicyResolver, q QuotaStore, a AuditSink) Engine {
	if a == nil {
		a = NopSink()
	}
	return &engine{
		resolver: r,
		quotas:   q,
		audit:    a,
		now:      time.Now,
	}
}

// Evaluate is the main PDP entry point. The contract:
//
//  1. Lookup all active grants for the actor in the vault.
//  2. Filter to grants whose policy applies to (credential, host).
//  3. If none → DENY (no-grant).
//  4. For each applicable grant, load the pinned policy version,
//     verify content_hash, evaluate rules + constraints. ALL must
//     allow (cumulative-deny composition).
//  5. Reserve quota counters; rollback on caller failure via
//     OnRequestCompleted.
//
// Any unexpected error along the way is fail-closed: deny.
func (e *engine) Evaluate(ctx context.Context, ec EvalContext) (Decision, error) {
	if ec.Now.IsZero() {
		ec.Now = e.now()
	}
	if ec.ActorType == "" || ec.ActorID == "" {
		return Decision{Allow: false, Reason: "missing actor", RuleID: RuleDefaultDeny}, nil
	}

	grants, err := e.resolver.ListGrantsForSubject(ctx, ec.VaultID, ec.ActorType, ec.ActorID)
	if err != nil {
		return e.denyAudit(ctx, ec, "", "", "", RuleDefaultDeny, fmt.Sprintf("resolver error: %v", err)), nil
	}

	applicable := make([]appliedGrant, 0, len(grants))
	for _, g := range grants {
		if g.RevokedAt != nil {
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(ec.Now) {
			_ = e.audit.Record(ctx, AuditEvent{
				VaultID:    ec.VaultID,
				EventType:  "decision.deny",
				Subject:    fmt.Sprintf("%s:%s", ec.ActorType, ec.ActorID),
				GrantID:    g.ID,
				RuleID:     RuleGrantExpired,
				Decision:   "deny",
				Reason:     "grant expired",
				OccurredAt: ec.Now,
			})
			continue
		}
		rec, err := e.resolver.GetPolicyVersion(ctx, ec.VaultID, g.PolicyID, g.PolicyVersion)
		if err != nil || rec == nil || rec.Policy == nil {
			return e.denyAudit(ctx, ec, g.ID, g.PolicyID, fmt.Sprintf("v%d", g.PolicyVersion), RuleDefaultDeny,
				fmt.Sprintf("policy fetch failed: %v", err)), nil
		}
		if !rec.Enabled {
			continue
		}
		// Tamper check.
		if err := VerifyHash(rec.Policy, rec.ContentHash); err != nil {
			return e.denyAudit(ctx, ec, g.ID, rec.Policy.Metadata.ID, fmt.Sprintf("v%d", rec.Version), RuleHashMismatch,
				err.Error()), nil
		}
		// Resource scope check.
		if !resourceMatches(rec.Policy, ec.CredentialKey, ec.MatchedHost) {
			continue
		}
		applicable = append(applicable, appliedGrant{Grant: g, Policy: rec.Policy, Version: rec.Version})
	}

	if len(applicable) == 0 {
		return e.denyAudit(ctx, ec, "", "", "", RuleNoGrant,
			fmt.Sprintf("no grant covers credential %q on host %q", ec.CredentialKey, ec.MatchedHost)), nil
	}

	// Cumulative-deny: every applicable grant's policy must allow.
	var primaryAllow Decision
	for i, ag := range applicable {
		d := evaluateRules(ag.Policy, ec)
		if !d.Allow {
			d.GrantID = ag.Grant.ID
			d.PolicyID = ag.Policy.Metadata.ID
			_ = e.audit.Record(ctx, AuditEvent{
				VaultID:    ec.VaultID,
				EventType:  "decision.deny",
				Subject:    fmt.Sprintf("%s:%s", ec.ActorType, ec.ActorID),
				PolicyRef:  fmt.Sprintf("%s@%d", ag.Policy.Metadata.ID, ag.Version),
				GrantID:    ag.Grant.ID,
				RuleID:     d.RuleID,
				Decision:   "deny",
				Reason:     d.Reason,
				OccurredAt: ec.Now,
			})
			return d, nil
		}
		if i == 0 {
			primaryAllow = d
		}
	}

	// Reserve quota counters once, against the first applicable grant
	// (which is also the one whose constraints we attach to the
	// reservation). If multiple grants apply with conflicting limits,
	// the strictest grant's reservation will fail-fast on its own.
	primary := applicable[0]
	if e.quotas != nil {
		violated, err := reserveQuota(ctx, e.quotas, primary.Grant.ID, primary.Policy.Spec.Constraints, ec.Now)
		if err != nil {
			return e.denyAudit(ctx, ec, primary.Grant.ID, primary.Policy.Metadata.ID,
				fmt.Sprintf("v%d", primary.Version), RuleConstraintQuot,
				fmt.Sprintf("quota store error: %v", err)), nil
		}
		if violated != "" {
			ruleID := RuleConstraintQuot
			if strings.HasPrefix(violated, "rate_limit") {
				ruleID = RuleConstraintRate
			}
			return e.denyAudit(ctx, ec, primary.Grant.ID, primary.Policy.Metadata.ID,
				fmt.Sprintf("v%d", primary.Version), ruleID, violated), nil
		}
	}

	// Allow path — emit allow audit at debug volume only when the
	// caller asked for verbose decision logging. We always record
	// denies (above); allow events are written by OnRequestCompleted
	// when status is final.
	return Decision{
		Allow:    true,
		PolicyID: primary.Policy.Metadata.ID,
		GrantID:  primary.Grant.ID,
		RuleID:   primaryAllow.RuleID,
	}, nil
}

func (e *engine) OnRequestCompleted(ctx context.Context, grantID, policyID string, version int, statusCode int) error {
	// On a 5xx the agent didn't get to use the credential; release
	// the reservation so the user isn't unfairly penalized.
	if statusCode >= 500 && statusCode < 600 && grantID != "" && e.quotas != nil {
		// We don't have the policy in hand here; upstream callers
		// can pass it via context if they want exact rollback. As a
		// safe approximation, release the most-likely-incremented
		// buckets (minute + hour + day + month). DecrementBucket is
		// idempotent against missing rows.
		_ = releaseQuota(ctx, e.quotas, grantID,
			Constraints{
				RateLimit: &RateLimitConstraint{MaxPerMinute: 1, MaxPerHour: 1},
				Quotas:    &QuotaConstraint{DailyRequestCap: 1, MonthlyRequestCap: 1},
			}, e.now())
	}
	if grantID != "" && policyID != "" {
		_ = e.audit.Record(ctx, AuditEvent{
			VaultID:    "", // populated by caller via Detail if needed
			EventType:  "decision.allow",
			GrantID:    grantID,
			PolicyRef:  fmt.Sprintf("%s@%d", policyID, version),
			Decision:   "allow",
			Detail:     map[string]any{"upstream_status": statusCode},
			OccurredAt: e.now(),
		})
	}
	return nil
}

func (e *engine) denyAudit(ctx context.Context, ec EvalContext, grantID, policyID, ver, ruleID, reason string) Decision {
	ref := ""
	if policyID != "" {
		ref = policyID
		if ver != "" {
			ref = policyID + "@" + ver
		}
	}
	_ = e.audit.Record(ctx, AuditEvent{
		VaultID:    ec.VaultID,
		EventType:  "decision.deny",
		Subject:    fmt.Sprintf("%s:%s", ec.ActorType, ec.ActorID),
		PolicyRef:  ref,
		GrantID:    grantID,
		RuleID:     ruleID,
		Decision:   "deny",
		Reason:     reason,
		OccurredAt: ec.Now,
	})
	return Decision{Allow: false, Reason: reason, RuleID: ruleID, PolicyID: policyID, GrantID: grantID}
}

type appliedGrant struct {
	Grant   GrantRecord
	Policy  *Policy
	Version int
}

// evaluateRules walks the policy's rules in order, returning the
// outcome of the first matching rule. If no rule matches, default
// deny. Constraints (body, time window) gate allow outcomes; rate +
// quota are handled separately so the caller can reserve atomically.
func evaluateRules(p *Policy, ec EvalContext) Decision {
	// Time window constraint applies to the whole policy regardless
	// of which rule matches, so check once up-front.
	if c := p.Spec.Constraints.TimeWindow; c != nil && len(c.AllowedHoursLocal) > 0 {
		if !inAllowedTimeWindow(ec.Now, c) {
			return Decision{Allow: false, Reason: "outside allowed time window", RuleID: RuleConstraintTime}
		}
	}

	for _, rule := range p.Spec.Rules {
		if !matchMethod(rule, ec.Method) {
			continue
		}
		if !matchPath(rule, ec.Path) {
			continue
		}
		if rule.Effect == EffectDeny {
			return Decision{Allow: false, Reason: "matched deny rule", RuleID: rule.ID}
		}
		// Allow effect — apply body constraint.
		if path, violated := inspectBody(p.Spec.Constraints.Body, ec.Body); violated {
			return Decision{
				Allow:  false,
				Reason: fmt.Sprintf("body violates forbidden path %q", path),
				RuleID: RuleConstraintBody,
			}
		}
		return Decision{Allow: true, RuleID: rule.ID, PolicyID: p.Metadata.ID}
	}
	return Decision{Allow: false, Reason: "no rule matched (default deny)", RuleID: RuleDefaultDeny}
}

func inAllowedTimeWindow(now time.Time, c *TimeWindowConstraint) bool {
	loc := time.UTC
	if c.Timezone != "" {
		if l, err := time.LoadLocation(c.Timezone); err == nil {
			loc = l
		}
	}
	t := now.In(loc)
	mins := t.Hour()*60 + t.Minute()
	for _, w := range c.AllowedHoursLocal {
		a, b, err := parseHourWindow(w)
		if err != nil {
			continue
		}
		if a <= b {
			if mins >= a && mins < b {
				return true
			}
		} else {
			// wrap-around (e.g. 22:00-02:00)
			if mins >= a || mins < b {
				return true
			}
		}
	}
	return false
}
