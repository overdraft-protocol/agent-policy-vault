package policy

import (
	"context"
	"encoding/json"
	"time"
)

// AuditEvent describes a single row written to the policy_audit table.
// EventType is one of:
//
//	policy.create   policy.update   policy.disable
//	grant.create    grant.revoke
//	decision.allow  decision.deny
type AuditEvent struct {
	VaultID    string
	EventType  string
	Subject    string // e.g. "agent:support-bot"
	PolicyRef  string // "<policy_id>@<version>" or empty
	GrantID    string
	RuleID     string
	Decision   string // "allow"|"deny"|""
	Reason     string
	Detail     map[string]any
	ActorID    string
	ActorType  string
	SessionID  string
	OccurredAt time.Time
}

// AuditSink persists audit events. Implementations should be
// non-blocking on the request hot path; the SQLite implementation
// follows the same buffered-channel pattern as requestlog.
type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent) error
}

// MarshalDetail is a convenience helper for handlers writing
// AuditEvent.Detail as JSON before persistence.
func MarshalDetail(detail map[string]any) (string, error) {
	if len(detail) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// nopSink is used in tests and as a safe default when no sink is
// configured. It accepts and discards every event.
type nopSink struct{}

func (nopSink) Record(context.Context, AuditEvent) error { return nil }

// NopSink returns an AuditSink that discards all events.
func NopSink() AuditSink { return nopSink{} }
