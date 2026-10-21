-- Email verification tokens gating the confirmEmail / updateEmail flows.
--
-- Same SHA-256-hashed, 1-hour, single-use envelope as password_reset_tokens (V014),
-- plc_operation_tokens (V033), and account_deletion_tokens (V034). The `purpose` column
-- discriminates the two flows that share this shape:
--   * 'confirm' — minted by requestEmailConfirmation, consumed by confirmEmail
--   * 'update'  — minted by requestEmailUpdate,       consumed by updateEmail
-- so a confirmation token can never be redeemed as an email-change authorization or vice
-- versa. Only the plaintext's hash is stored; consumption is atomic and bound to
-- (token_hash, did, purpose).
CREATE TABLE email_tokens (
    token_hash  TEXT NOT NULL,
    did         TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (token_hash),
    FOREIGN KEY (did) REFERENCES accounts (did)
);

CREATE INDEX idx_email_tokens_did ON email_tokens (did);
