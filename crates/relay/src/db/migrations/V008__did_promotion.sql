-- V008: DID promotion support
-- Applied in a single transaction by the migration runner.
--
-- 1. Rebuilds the accounts table with nullable password_hash.
--    Mobile-provisioned accounts (via POST /v1/dids) have no password;
--    only accounts created via POST /v1/accounts have a password_hash.
--    SQLite does not support ALTER COLUMN, so a full table rebuild is required.
--
-- 2. Adds pending_did to pending_accounts for retry-safe DID pre-storage.
--    Populated by POST /v1/dids before calling plc.directory (pre-store pattern).
--    If the promotion transaction fails after plc.directory accepts the op,
--    a client retry detects this non-NULL value and skips the directory call.

-- ── Rebuild accounts with nullable password_hash ─────────────────────────────

CREATE TABLE accounts_new (
    did                TEXT NOT NULL,
    email              TEXT NOT NULL,
    password_hash      TEXT,                -- NULL for mobile-provisioned accounts
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    email_confirmed_at TEXT,
    deactivated_at     TEXT,
    PRIMARY KEY (did)
);

INSERT INTO accounts_new
    SELECT did, email, password_hash, created_at, updated_at, email_confirmed_at, deactivated_at
    FROM accounts;

DROP TABLE accounts;

ALTER TABLE accounts_new RENAME TO accounts;

CREATE UNIQUE INDEX idx_accounts_email ON accounts (email);

-- ── Add pending_did to pending_accounts ──────────────────────────────────────

ALTER TABLE pending_accounts ADD COLUMN pending_did TEXT;
