CREATE TABLE grants (
    id              TEXT PRIMARY KEY,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    subject_type    TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    policy_id       TEXT NOT NULL,
    policy_version  INTEGER,
    conditions      TEXT NOT NULL DEFAULT '{}',
    expires_at      TEXT,
    granted_by      TEXT NOT NULL,
    granted_at      TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at      TEXT,
    revoked_by      TEXT
);

CREATE INDEX idx_grants_active ON grants (vault_id, subject_type, subject_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_grants_policy ON grants (vault_id, policy_id);
