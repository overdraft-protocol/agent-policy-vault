package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PolicyRow is the persisted projection of a Policy. The yaml_source
// column is the canonical source of truth; ContentHash is verified at
// evaluation time to detect tampering.
type PolicyRow struct {
	PK              int64
	VaultID         string
	PolicyID        string
	Version         int
	Enabled         bool
	YAMLSource      string
	ContentHash     string
	ParentHash      string
	Description     string
	SourceTemplate  string
	SourcePublisher string
	AuthoredBy      string
	AuthoredSession string
	AuthoredAt      time.Time
}

// GrantRow is the persisted projection of a Grant.
type GrantRow struct {
	ID            string
	VaultID       string
	SubjectType   string
	SubjectID     string
	PolicyID      string
	PolicyVersion int // 0 = always-latest
	Conditions    string
	ExpiresAt     *time.Time
	GrantedBy     string
	GrantedAt     time.Time
	RevokedAt     *time.Time
	RevokedBy     string
}

// PolicyAuditRow is one row of the policy_audit log.
type PolicyAuditRow struct {
	ID         int64
	VaultID    string
	EventType  string
	Subject    string
	PolicyRef  string
	GrantID    string
	RuleID     string
	Decision   string
	Reason     string
	Detail     string
	ActorID    string
	ActorType  string
	SessionID  string
	OccurredAt time.Time
}

// GrantDecisionStat aggregates allow/deny decision counts for one grant.
type GrantDecisionStat struct {
	GrantID    string
	AllowCount int
	DenyCount  int
}

// ListPolicyAuditOpts filters policy_audit queries.
type ListPolicyAuditOpts struct {
	VaultID   string
	Subject   string
	EventType string
	Since     *time.Time
	Limit     int
}

// PolicyStore is the additional surface added by agent-policy-vault on
// top of agent-vault's Store. Kept as a separate interface so it can be
// composed without forcing every Store implementation to grow.
type PolicyStore interface {
	// Policies
	InsertPolicyVersion(ctx context.Context, row PolicyRow) (PolicyRow, error)
	GetLatestPolicy(ctx context.Context, vaultID, policyID string) (*PolicyRow, error)
	// GetLatestPolicyAny returns the highest-version row regardless of enabled
	// (for admin UI when the policy is disabled).
	GetLatestPolicyAny(ctx context.Context, vaultID, policyID string) (*PolicyRow, error)
	GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*PolicyRow, error)
	ListPolicies(ctx context.Context, vaultID string) ([]PolicyRow, error)
	ListPolicyVersions(ctx context.Context, vaultID, policyID string) ([]PolicyRow, error)
	DisablePolicy(ctx context.Context, vaultID, policyID string) error
	EnablePolicy(ctx context.Context, vaultID, policyID string) error
	NextPolicyVersion(ctx context.Context, vaultID, policyID string) (int, string, error) // returns (version, parent_hash)

	// Grants
	InsertGrant(ctx context.Context, row GrantRow) (GrantRow, error)
	GetGrant(ctx context.Context, vaultID, grantID string) (*GrantRow, error)
	ListGrantsForVault(ctx context.Context, vaultID string) ([]GrantRow, error)
	ListActiveGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]GrantRow, error)
	RevokeGrant(ctx context.Context, vaultID, grantID, revokedBy string) error

	// Policy audit
	InsertPolicyAudit(ctx context.Context, row PolicyAuditRow) error
	ListPolicyAudit(ctx context.Context, opts ListPolicyAuditOpts) ([]PolicyAuditRow, error)
	ListGrantDecisionStats(ctx context.Context, vaultID string) ([]GrantDecisionStat, error)

	// Quota counters (used by policy.QuotaStore adapter)
	IncrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error)
	DecrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int) error
	PruneExpiredQuotaBuckets(ctx context.Context, now time.Time) (int, error)
}

// newGrantID generates an opaque, URL-safe grant identifier.
func newGrantID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return "gnt_" + hex.EncodeToString(b[:])
}

// --- Policies ---

// NextPolicyVersion returns the next version number for a (vault,
// policy_id) pair along with the previous version's content_hash for
// chaining. Returns (1, "") for a brand-new policy_id.
func (s *SQLiteStore) NextPolicyVersion(ctx context.Context, vaultID, policyID string) (int, string, error) {
	var maxVersion sql.NullInt64
	var parentHash sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT version, content_hash FROM policies
		 WHERE vault_id = ? AND policy_id = ?
		 ORDER BY version DESC LIMIT 1`,
		vaultID, policyID).Scan(&maxVersion, &parentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 1, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return int(maxVersion.Int64) + 1, parentHash.String, nil
}

func (s *SQLiteStore) InsertPolicyVersion(ctx context.Context, row PolicyRow) (PolicyRow, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO policies
		 (vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		  description, source_template, source_publisher, authored_by, authored_session)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.VaultID, row.PolicyID, row.Version, boolToInt(row.Enabled),
		row.YAMLSource, []byte(row.ContentHash), nullableBytes(row.ParentHash),
		row.Description, nullableStr(row.SourceTemplate), nullableStr(row.SourcePublisher),
		row.AuthoredBy, nullableStr(row.AuthoredSession),
	)
	if err != nil {
		return PolicyRow{}, err
	}
	pk, _ := res.LastInsertId()
	row.PK = pk
	row.AuthoredAt = time.Now().UTC()
	return row, nil
}

func (s *SQLiteStore) GetLatestPolicy(ctx context.Context, vaultID, policyID string) (*PolicyRow, error) {
	const q = `SELECT pk, vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		       description, COALESCE(source_template,''), COALESCE(source_publisher,''),
		       authored_by, COALESCE(authored_session,''), authored_at
		FROM policies
		WHERE vault_id = ? AND policy_id = ? AND enabled = 1
		ORDER BY version DESC LIMIT 1`
	return scanPolicyRow(s.db.QueryRowContext(ctx, q, vaultID, policyID))
}

func (s *SQLiteStore) GetLatestPolicyAny(ctx context.Context, vaultID, policyID string) (*PolicyRow, error) {
	const q = `SELECT pk, vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		       description, COALESCE(source_template,''), COALESCE(source_publisher,''),
		       authored_by, COALESCE(authored_session,''), authored_at
		FROM policies
		WHERE vault_id = ? AND policy_id = ?
		ORDER BY version DESC LIMIT 1`
	return scanPolicyRow(s.db.QueryRowContext(ctx, q, vaultID, policyID))
}

func (s *SQLiteStore) GetPolicyVersion(ctx context.Context, vaultID, policyID string, version int) (*PolicyRow, error) {
	if version <= 0 {
		return s.GetLatestPolicy(ctx, vaultID, policyID)
	}
	const q = `SELECT pk, vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		       description, COALESCE(source_template,''), COALESCE(source_publisher,''),
		       authored_by, COALESCE(authored_session,''), authored_at
		FROM policies
		WHERE vault_id = ? AND policy_id = ? AND version = ?`
	return scanPolicyRow(s.db.QueryRowContext(ctx, q, vaultID, policyID, version))
}

func (s *SQLiteStore) ListPolicies(ctx context.Context, vaultID string) ([]PolicyRow, error) {
	// Latest version per policy_id.
	const q = `SELECT pk, vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		       description, COALESCE(source_template,''), COALESCE(source_publisher,''),
		       authored_by, COALESCE(authored_session,''), authored_at
		FROM policies p1
		WHERE vault_id = ?
		  AND version = (SELECT MAX(version) FROM policies p2 WHERE p2.vault_id = p1.vault_id AND p2.policy_id = p1.policy_id)
		ORDER BY policy_id`
	rows, err := s.db.QueryContext(ctx, q, vaultID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanPolicyRows(rows)
}

func (s *SQLiteStore) ListPolicyVersions(ctx context.Context, vaultID, policyID string) ([]PolicyRow, error) {
	const q = `SELECT pk, vault_id, policy_id, version, enabled, yaml_source, content_hash, parent_hash,
		       description, COALESCE(source_template,''), COALESCE(source_publisher,''),
		       authored_by, COALESCE(authored_session,''), authored_at
		FROM policies
		WHERE vault_id = ? AND policy_id = ?
		ORDER BY version DESC`
	rows, err := s.db.QueryContext(ctx, q, vaultID, policyID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanPolicyRows(rows)
}

// DisablePolicy marks every version of a policy_id disabled. We do not
// hard-delete because grants may still reference historical versions
// for auditability.
func (s *SQLiteStore) DisablePolicy(ctx context.Context, vaultID, policyID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE policies SET enabled = 0 WHERE vault_id = ? AND policy_id = ? AND enabled = 1`,
		vaultID, policyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// EnablePolicy sets enabled=1 on the highest-version row only (the active tip).
func (s *SQLiteStore) EnablePolicy(ctx context.Context, vaultID, policyID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE policies SET enabled = 1
		 WHERE pk = (
		   SELECT pk FROM policies
		   WHERE vault_id = ? AND policy_id = ?
		   ORDER BY version DESC
		   LIMIT 1
		 )`,
		vaultID, policyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Grants ---

func (s *SQLiteStore) InsertGrant(ctx context.Context, row GrantRow) (GrantRow, error) {
	if row.ID == "" {
		row.ID = newGrantID()
	}
	if row.GrantedAt.IsZero() {
		row.GrantedAt = time.Now().UTC()
	}
	if row.Conditions == "" {
		row.Conditions = "{}"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO grants
		 (id, vault_id, subject_type, subject_id, policy_id, policy_version,
		  conditions, expires_at, granted_by, granted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.VaultID, row.SubjectType, row.SubjectID,
		row.PolicyID, sqlNullableInt(row.PolicyVersion),
		row.Conditions, sqlNullableTime(row.ExpiresAt),
		row.GrantedBy, row.GrantedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return GrantRow{}, err
	}
	return row, nil
}

func (s *SQLiteStore) GetGrant(ctx context.Context, vaultID, grantID string) (*GrantRow, error) {
	const q = `SELECT id, vault_id, subject_type, subject_id, policy_id, COALESCE(policy_version,0),
		         conditions, expires_at, granted_by, granted_at, revoked_at, COALESCE(revoked_by,'')
		 FROM grants WHERE vault_id = ? AND id = ?`
	return scanGrantRow(s.db.QueryRowContext(ctx, q, vaultID, grantID))
}

func (s *SQLiteStore) ListGrantsForVault(ctx context.Context, vaultID string) ([]GrantRow, error) {
	const q = `SELECT id, vault_id, subject_type, subject_id, policy_id, COALESCE(policy_version,0),
		         conditions, expires_at, granted_by, granted_at, revoked_at, COALESCE(revoked_by,'')
		 FROM grants WHERE vault_id = ? ORDER BY granted_at DESC`
	rows, err := s.db.QueryContext(ctx, q, vaultID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanGrantRows(rows)
}

func (s *SQLiteStore) ListActiveGrantsForSubject(ctx context.Context, vaultID, subjectType, subjectID string) ([]GrantRow, error) {
	const q = `SELECT id, vault_id, subject_type, subject_id, policy_id, COALESCE(policy_version,0),
		         conditions, expires_at, granted_by, granted_at, revoked_at, COALESCE(revoked_by,'')
		 FROM grants
		 WHERE vault_id = ? AND subject_type = ? AND subject_id = ? AND revoked_at IS NULL
		 ORDER BY granted_at ASC`
	rows, err := s.db.QueryContext(ctx, q, vaultID, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanGrantRows(rows)
}

func (s *SQLiteStore) RevokeGrant(ctx context.Context, vaultID, grantID, revokedBy string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE grants SET revoked_at = datetime('now'), revoked_by = ?
		 WHERE vault_id = ? AND id = ? AND revoked_at IS NULL`,
		revokedBy, vaultID, grantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- Policy Audit ---

func (s *SQLiteStore) InsertPolicyAudit(ctx context.Context, row PolicyAuditRow) error {
	if row.Detail == "" {
		row.Detail = "{}"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO policy_audit
		 (vault_id, event_type, subject, policy_ref, grant_id, rule_id, decision, reason,
		  detail, actor_id, actor_type, session_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.VaultID, row.EventType, nullableStr(row.Subject), nullableStr(row.PolicyRef),
		nullableStr(row.GrantID), nullableStr(row.RuleID), nullableStr(row.Decision),
		nullableStr(row.Reason), row.Detail,
		nullableStr(row.ActorID), nullableStr(row.ActorType), nullableStr(row.SessionID),
	)
	return err
}

func (s *SQLiteStore) ListPolicyAudit(ctx context.Context, opts ListPolicyAuditOpts) ([]PolicyAuditRow, error) {
	clauses := []string{"vault_id = ?"}
	args := []any{opts.VaultID}
	if opts.Subject != "" {
		clauses = append(clauses, "subject = ?")
		args = append(args, opts.Subject)
	}
	if opts.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, opts.EventType)
	}
	if opts.Since != nil {
		clauses = append(clauses, "occurred_at >= ?")
		args = append(args, opts.Since.UTC().Format(time.RFC3339))
	}
	limit := opts.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, vault_id, event_type, COALESCE(subject,''), COALESCE(policy_ref,''),
		    COALESCE(grant_id,''), COALESCE(rule_id,''), COALESCE(decision,''),
		    COALESCE(reason,''), detail, COALESCE(actor_id,''), COALESCE(actor_type,''),
		    COALESCE(session_id,''), occurred_at
		FROM policy_audit
		WHERE ` + strings.Join(clauses, " AND ") +
		` ORDER BY occurred_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PolicyAuditRow
	for rows.Next() {
		var r PolicyAuditRow
		var occurred string
		if err := rows.Scan(&r.ID, &r.VaultID, &r.EventType, &r.Subject, &r.PolicyRef,
			&r.GrantID, &r.RuleID, &r.Decision, &r.Reason, &r.Detail,
			&r.ActorID, &r.ActorType, &r.SessionID, &occurred); err != nil {
			return nil, err
		}
		r.OccurredAt, _ = time.Parse(time.RFC3339, occurred)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ListGrantDecisionStats(ctx context.Context, vaultID string) ([]GrantDecisionStat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT grant_id,
		        SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) AS allow_count,
		        SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) AS deny_count
		   FROM policy_audit
		  WHERE vault_id = ?
		    AND grant_id != ''
		    AND decision IN ('allow', 'deny')
		  GROUP BY grant_id`,
		vaultID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []GrantDecisionStat
	for rows.Next() {
		var s GrantDecisionStat
		if err := rows.Scan(&s.GrantID, &s.AllowCount, &s.DenyCount); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- Quota counters ---

func (s *SQLiteStore) IncrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int, expiresAt time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO policy_quota_state (grant_id, bucket_key, count, expires_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(grant_id, bucket_key) DO UPDATE SET count = count + ?`,
		grantID, bucketKey, delta, expiresAt.UTC().Format(time.RFC3339), delta)
	if err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT count FROM policy_quota_state WHERE grant_id = ? AND bucket_key = ?`,
		grantID, bucketKey).Scan(&n); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLiteStore) DecrementQuotaBucket(ctx context.Context, grantID, bucketKey string, delta int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE policy_quota_state SET count = MAX(0, count - ?) WHERE grant_id = ? AND bucket_key = ?`,
		delta, grantID, bucketKey)
	return err
}

func (s *SQLiteStore) PruneExpiredQuotaBuckets(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM policy_quota_state WHERE expires_at < ?`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableBytes(s string) any {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func sqlNullableInt(n int) any {
	if n <= 0 {
		return nil
	}
	return n
}

func sqlNullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// parseSQLiteTime parses timestamps written by SQLite (e.g. datetime('now')
// → "2006-01-02 15:04:05") as well as RFC3339 from Go inserts.
func parseSQLiteTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func scanPolicyRow(r *sql.Row) (*PolicyRow, error) {
	var row PolicyRow
	var enabled int
	var contentHash, parentHash []byte
	var authoredAt string
	if err := r.Scan(&row.PK, &row.VaultID, &row.PolicyID, &row.Version, &enabled,
		&row.YAMLSource, &contentHash, &parentHash,
		&row.Description, &row.SourceTemplate, &row.SourcePublisher,
		&row.AuthoredBy, &row.AuthoredSession, &authoredAt); err != nil {
		return nil, err
	}
	row.Enabled = enabled != 0
	row.ContentHash = string(contentHash)
	if len(parentHash) > 0 {
		row.ParentHash = string(parentHash)
	}
	if t, ok := parseSQLiteTime(authoredAt); ok {
		row.AuthoredAt = t
	}
	return &row, nil
}

func scanPolicyRows(rows *sql.Rows) ([]PolicyRow, error) {
	var out []PolicyRow
	for rows.Next() {
		var row PolicyRow
		var enabled int
		var contentHash, parentHash []byte
		var authoredAt string
		if err := rows.Scan(&row.PK, &row.VaultID, &row.PolicyID, &row.Version, &enabled,
			&row.YAMLSource, &contentHash, &parentHash,
			&row.Description, &row.SourceTemplate, &row.SourcePublisher,
			&row.AuthoredBy, &row.AuthoredSession, &authoredAt); err != nil {
			return nil, err
		}
		row.Enabled = enabled != 0
		row.ContentHash = string(contentHash)
		if len(parentHash) > 0 {
			row.ParentHash = string(parentHash)
		}
		if t, ok := parseSQLiteTime(authoredAt); ok {
			row.AuthoredAt = t
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func scanGrantRow(r *sql.Row) (*GrantRow, error) {
	var row GrantRow
	var policyVersion int
	var expiresAt, revokedAt sql.NullString
	var grantedAt string
	if err := r.Scan(&row.ID, &row.VaultID, &row.SubjectType, &row.SubjectID,
		&row.PolicyID, &policyVersion, &row.Conditions,
		&expiresAt, &row.GrantedBy, &grantedAt, &revokedAt, &row.RevokedBy); err != nil {
		return nil, err
	}
	row.PolicyVersion = policyVersion
	if expiresAt.Valid {
		if t, ok := parseSQLiteTime(expiresAt.String); ok {
			row.ExpiresAt = &t
		}
	}
	if revokedAt.Valid {
		if t, ok := parseSQLiteTime(revokedAt.String); ok {
			row.RevokedAt = &t
		}
	}
	if t, ok := parseSQLiteTime(grantedAt); ok {
		row.GrantedAt = t
	}
	return &row, nil
}

func scanGrantRows(rows *sql.Rows) ([]GrantRow, error) {
	var out []GrantRow
	for rows.Next() {
		var row GrantRow
		var policyVersion int
		var expiresAt, revokedAt sql.NullString
		var grantedAt string
		if err := rows.Scan(&row.ID, &row.VaultID, &row.SubjectType, &row.SubjectID,
			&row.PolicyID, &policyVersion, &row.Conditions,
			&expiresAt, &row.GrantedBy, &grantedAt, &revokedAt, &row.RevokedBy); err != nil {
			return nil, err
		}
		row.PolicyVersion = policyVersion
		if expiresAt.Valid {
			if t, ok := parseSQLiteTime(expiresAt.String); ok {
				row.ExpiresAt = &t
			}
		}
		if revokedAt.Valid {
			if t, ok := parseSQLiteTime(revokedAt.String); ok {
				row.RevokedAt = &t
			}
		}
		if t, ok := parseSQLiteTime(grantedAt); ok {
			row.GrantedAt = t
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ConditionsJSON helpers — used by handlers when round-tripping the
// conditions field through JSON. Kept here so callers don't need to
// know the column shape.
func MarshalGrantConditions(c map[string]any) (string, error) {
	if len(c) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("grant conditions marshal: %w", err)
	}
	return string(b), nil
}
