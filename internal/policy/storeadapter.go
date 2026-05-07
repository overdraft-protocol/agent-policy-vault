package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StoreAdapter bridges the store-layer types (PolicyRow, GrantRow,
// quota counters, policy_audit) to the policy.* interfaces consumed
// by the engine.
//
// It implements PolicyResolver, QuotaStore and AuditSink so a single
// instance can be passed to NewEngine and to the REST handlers.
type StoreAdapter struct {
	S StoreSurface
}

// StoreSurface is the subset of store.SQLiteStore used by the
// adapter. Defined as an interface here to avoid an import cycle
// between internal/policy and internal/store and to permit fakes in
// tests.
type StoreSurface interface {
	GetLatestPolicy(ctx context.Context, vaultID, policyID string) (*PolicyRowDTO, error)
	GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*PolicyRowDTO, error)
	ListActiveGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]GrantRowDTO, error)

	IncrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error)
	DecrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int) error

	InsertPolicyAudit(ctx context.Context, row PolicyAuditDTO) error
}

// PolicyRowDTO mirrors store.PolicyRow but is redeclared here to keep
// internal/policy independent of internal/store. Callers translate.
type PolicyRowDTO struct {
	PolicyID    string
	Version     int
	Enabled     bool
	YAMLSource  string
	ContentHash string
	ParentHash  string // chain link; may be omitted from yaml_source but required for hash verification
}

// GrantRowDTO mirrors store.GrantRow.
type GrantRowDTO struct {
	ID            string
	VaultID       string
	SubjectType   string
	SubjectID     string
	PolicyID      string
	PolicyVersion int
	ConditionsRaw string
	ExpiresAt     *time.Time
	GrantedBy     string
	GrantedAt     time.Time
	RevokedAt     *time.Time
}

// PolicyAuditDTO mirrors store.PolicyAuditRow input shape.
type PolicyAuditDTO struct {
	VaultID   string
	EventType string
	Subject   string
	PolicyRef string
	GrantID   string
	RuleID    string
	Decision  string
	Reason    string
	Detail    string
	ActorID   string
	ActorType string
	SessionID string
}

// NewStoreAdapter constructs an adapter over the store surface.
func NewStoreAdapter(s StoreSurface) *StoreAdapter { return &StoreAdapter{S: s} }

// --- PolicyResolver ---

func (a *StoreAdapter) ListGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]GrantRecord, error) {
	rows, err := a.S.ListActiveGrantsForSubject(ctx, vaultID, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	out := make([]GrantRecord, 0, len(rows))
	for _, r := range rows {
		var cond GrantConditions
		if r.ConditionsRaw != "" {
			_ = json.Unmarshal([]byte(r.ConditionsRaw), &cond)
		}
		out = append(out, GrantRecord{
			ID:            r.ID,
			VaultID:       r.VaultID,
			SubjectType:   r.SubjectType,
			SubjectID:     r.SubjectID,
			PolicyID:      r.PolicyID,
			PolicyVersion: r.PolicyVersion,
			ExpiresAt:     r.ExpiresAt,
			Conditions:    cond,
			GrantedBy:     r.GrantedBy,
			GrantedAt:     r.GrantedAt,
			RevokedAt:     r.RevokedAt,
		})
	}
	return out, nil
}

func (a *StoreAdapter) GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*PolicyRecord, error) {
	var dto *PolicyRowDTO
	var err error
	if version <= 0 {
		dto, err = a.S.GetLatestPolicy(ctx, vaultID, policyID)
	} else {
		dto, err = a.S.GetPolicyVersion(ctx, vaultID, policyID, version)
	}
	if err != nil {
		return nil, err
	}
	if dto == nil {
		return nil, errors.New("policy not found")
	}
	p, err := LoadPolicy([]byte(dto.YAMLSource))
	if err != nil {
		return nil, fmt.Errorf("policy load: %w", err)
	}
	// Persisted content_hash is computed from metadata.version and
	// metadata.parent_hash assigned server-side; yaml_source is often
	// the raw client document without those fields.
	p.Metadata.Version = dto.Version
	p.Metadata.ParentHash = dto.ParentHash
	return &PolicyRecord{
		Policy:      p,
		Version:     dto.Version,
		ContentHash: dto.ContentHash,
		Enabled:     dto.Enabled,
	}, nil
}

// --- QuotaStore ---

func (a *StoreAdapter) IncrementBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error) {
	return a.S.IncrementQuotaBucket(ctx, grantID, bucketKey, delta, expiresAt)
}

func (a *StoreAdapter) DecrementBucket(ctx context.Context, grantID, bucketKey string, delta int) error {
	return a.S.DecrementQuotaBucket(ctx, grantID, bucketKey, delta)
}

func (a *StoreAdapter) PruneExpiredBuckets(ctx context.Context, now time.Time) (int, error) {
	// The store surface optionally exposes prune; if not, no-op.
	type pruner interface {
		PruneExpiredQuotaBuckets(ctx context.Context, now time.Time) (int, error)
	}
	if p, ok := a.S.(pruner); ok {
		return p.PruneExpiredQuotaBuckets(ctx, now)
	}
	return 0, nil
}

// --- AuditSink ---

func (a *StoreAdapter) Record(ctx context.Context, ev AuditEvent) error {
	detail, err := MarshalDetail(ev.Detail)
	if err != nil {
		return err
	}
	return a.S.InsertPolicyAudit(ctx, PolicyAuditDTO{
		VaultID:   ev.VaultID,
		EventType: ev.EventType,
		Subject:   ev.Subject,
		PolicyRef: ev.PolicyRef,
		GrantID:   ev.GrantID,
		RuleID:    ev.RuleID,
		Decision:  ev.Decision,
		Reason:    ev.Reason,
		Detail:    detail,
		ActorID:   ev.ActorID,
		ActorType: ev.ActorType,
		SessionID: ev.SessionID,
	})
}
