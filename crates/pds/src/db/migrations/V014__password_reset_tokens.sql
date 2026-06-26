CREATE TABLE password_reset_tokens (
    token_hash  TEXT NOT NULL,
    did         TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (token_hash),
    FOREIGN KEY (did) REFERENCES accounts (did)
);

CREATE INDEX idx_password_reset_tokens_did ON password_reset_tokens (did);
