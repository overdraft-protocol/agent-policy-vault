CREATE TABLE policy_quota_state (
    grant_id    TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    bucket_key  TEXT NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (grant_id, bucket_key)
);

CREATE INDEX idx_policy_quota_expires ON policy_quota_state (expires_at);
