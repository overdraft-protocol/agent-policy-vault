CREATE TABLE policies (
    pk                INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id          TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    policy_id         TEXT NOT NULL,
    version           INTEGER NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    yaml_source       TEXT NOT NULL,
    content_hash      BLOB NOT NULL,
    parent_hash       BLOB,
    description       TEXT NOT NULL DEFAULT '',
    source_template   TEXT,
    source_publisher  TEXT,
    source_signature  BLOB,
    authored_by       TEXT NOT NULL,
    authored_session  TEXT,
    authored_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (vault_id, policy_id, version)
);

CREATE INDEX idx_policies_lookup ON policies (vault_id, policy_id, version DESC);
CREATE INDEX idx_policies_enabled ON policies (vault_id, policy_id) WHERE enabled = 1;
