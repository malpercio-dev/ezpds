CREATE TABLE plc_operation_tokens (
    token_hash  TEXT NOT NULL,
    did         TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (token_hash),
    FOREIGN KEY (did) REFERENCES accounts (did)
);

CREATE INDEX idx_plc_operation_tokens_did ON plc_operation_tokens (did);
