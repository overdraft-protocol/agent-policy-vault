package store

import (
	"context"
	"time"

	"github.com/Infisical/agent-vault/internal/policy"
)

// PolicyBridge is a thin adapter around *SQLiteStore that satisfies
// policy.StoreSurface, translating between the *Row types in this
// package and the *DTO types used by internal/policy.
//
// Defining this bridge in the store package (which already imports
// nothing from internal/policy outside of this file) keeps the type
// translation co-located with the concrete schema knowledge while
// avoiding a cycle: internal/policy never imports internal/store.
type PolicyBridge struct{ S *SQLiteStore }

// NewPolicyBridge wires a *SQLiteStore as a policy.StoreSurface.
func NewPolicyBridge(s *SQLiteStore) *PolicyBridge { return &PolicyBridge{S: s} }

func (b *PolicyBridge) GetLatestPolicy(ctx context.Context, vaultID, policyID string) (*policy.PolicyRowDTO, error) {
	row, err := b.S.GetLatestPolicy(ctx, vaultID, policyID)
	if err != nil || row == nil {
		return nil, err
	}
	return policyRowToDTO(row), nil
}

func (b *PolicyBridge) GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*policy.PolicyRowDTO, error) {
	row, err := b.S.GetPolicyVersion(ctx, vaultID, policyID, version)
	if err != nil || row == nil {
		return nil, err
	}
	return policyRowToDTO(row), nil
}

func (b *PolicyBridge) ListActiveGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]policy.GrantRowDTO, error) {
	rows, err := b.S.ListActiveGrantsForSubject(ctx, vaultID, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	out := make([]policy.GrantRowDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, grantRowToDTO(r))
	}
	return out, nil
}

func (b *PolicyBridge) IncrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error) {
	return b.S.IncrementQuotaBucket(ctx, grantID, bucketKey, delta, expiresAt)
}

func (b *PolicyBridge) DecrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int) error {
	return b.S.DecrementQuotaBucket(ctx, grantID, bucketKey, delta)
}

func (b *PolicyBridge) PruneExpiredQuotaBuckets(ctx context.Context, now time.Time) (int, error) {
	return b.S.PruneExpiredQuotaBuckets(ctx, now)
}

func (b *PolicyBridge) InsertPolicyAudit(ctx context.Context, row policy.PolicyAuditDTO) error {
	return b.S.InsertPolicyAudit(ctx, PolicyAuditRow{
		VaultID:   row.VaultID,
		EventType: row.EventType,
		Subject:   row.Subject,
		PolicyRef: row.PolicyRef,
		GrantID:   row.GrantID,
		RuleID:    row.RuleID,
		Decision:  row.Decision,
		Reason:    row.Reason,
		Detail:    row.Detail,
		ActorID:   row.ActorID,
		ActorType: row.ActorType,
		SessionID: row.SessionID,
	})
}

func policyRowToDTO(r *PolicyRow) *policy.PolicyRowDTO {
	return &policy.PolicyRowDTO{
		PolicyID:    r.PolicyID,
		Version:     r.Version,
		Enabled:     r.Enabled,
		YAMLSource:  r.YAMLSource,
		ContentHash: r.ContentHash,
		ParentHash:  r.ParentHash,
	}
}

func grantRowToDTO(r GrantRow) policy.GrantRowDTO {
	return policy.GrantRowDTO{
		ID:            r.ID,
		VaultID:       r.VaultID,
		SubjectType:   r.SubjectType,
		SubjectID:     r.SubjectID,
		PolicyID:      r.PolicyID,
		PolicyVersion: r.PolicyVersion,
		ConditionsRaw: r.Conditions,
		ExpiresAt:     r.ExpiresAt,
		GrantedBy:     r.GrantedBy,
		GrantedAt:     r.GrantedAt,
		RevokedAt:     r.RevokedAt,
	}
}
