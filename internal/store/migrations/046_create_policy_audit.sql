CREATE TABLE policy_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    subject      TEXT,
    policy_ref   TEXT,
    grant_id     TEXT,
    rule_id      TEXT,
    decision     TEXT,
    reason       TEXT,
    detail       TEXT NOT NULL DEFAULT '{}',
    actor_id     TEXT,
    actor_type   TEXT,
    session_id   TEXT,
    occurred_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_policy_audit_vault_time ON policy_audit (vault_id, occurred_at DESC);
CREATE INDEX idx_policy_audit_subject ON policy_audit (vault_id, subject, occurred_at DESC);
CREATE INDEX idx_policy_audit_event ON policy_audit (vault_id, event_type, occurred_at DESC);
