-- V007: Pending sessions for pre-DID mobile accounts
--
-- pending_sessions holds session tokens for accounts that have completed
-- mobile provisioning (POST /v1/accounts/mobile) but have not yet created
-- their DID. These tokens authorize the DID-creation step.
--
-- token_hash is SHA-256(session_token) stored as hex; the plaintext token is
-- returned once at provisioning and never stored — matching the pattern used
-- by devices.device_token_hash.
--
-- Once DID creation completes, the pending_accounts row is promoted to accounts
-- and a real sessions row is created; the pending_sessions row is deleted then.

CREATE TABLE pending_sessions (
    id         TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES pending_accounts (id),
    device_id  TEXT NOT NULL REFERENCES devices (id),
    token_hash TEXT NOT NULL,   -- SHA-256(session_token) as hex; token returned once
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- Each pending session must have a distinct token hash (defense-in-depth).
CREATE UNIQUE INDEX idx_pending_sessions_token_hash ON pending_sessions (token_hash);

-- Lookup by account (e.g., validate session for DID creation step).
CREATE INDEX idx_pending_sessions_account_id ON pending_sessions (account_id);
