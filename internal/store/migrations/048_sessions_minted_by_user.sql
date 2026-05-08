-- Agent-acting vault-scoped tokens: the proxy principal is an agent row, while
-- minted_by_user_id records which human minted the delegation (audit).

ALTER TABLE sessions ADD COLUMN minted_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_sessions_minted_by_user_id ON sessions(minted_by_user_id);
