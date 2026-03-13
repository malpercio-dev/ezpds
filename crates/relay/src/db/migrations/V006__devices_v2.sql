-- V006: Rebuild devices table to support device registration via claim code
--
-- The V002 devices table required a NOT NULL DID FK to accounts, which prevents
-- registration before DID assignment. The new schema references pending_accounts.id
-- and adds platform, public_key, and device_token_hash for challenge-response auth.
--
-- Cascade: sessions and oauth_tokens FK to devices; refresh_tokens FKs to sessions.
-- SQLite 3.26+ auto-updates FK references in child tables when a parent is renamed,
-- so renaming devices → devices_v1 also updates sessions and oauth_tokens to reference
-- devices_v1, and renaming sessions → sessions_v1 updates refresh_tokens similarly.
-- All four tables are therefore recreated here. All are empty at this migration (pre-launch).
--
-- IMPORTANT index naming: SQLite indexes follow the table when it is renamed — they
-- retain their original names on the renamed table. Dropping the old tables (which
-- also drops their indexes) must happen BEFORE creating the new tables, otherwise
-- CREATE INDEX fails with "already exists". Drop order: children before parents.

-- Step 1: Rename all affected tables (most-derived first so FK auto-updates cascade
-- in the right direction as parent tables are renamed after their children).
ALTER TABLE refresh_tokens RENAME TO refresh_tokens_v1;
ALTER TABLE oauth_tokens RENAME TO oauth_tokens_v1;
ALTER TABLE sessions RENAME TO sessions_v1;
ALTER TABLE devices RENAME TO devices_v1;

-- Step 2: Drop old tables in children-before-parents order. Each DROP also removes
-- the table's indexes (idx_refresh_tokens_did, idx_oauth_tokens_did, idx_sessions_did,
-- idx_devices_did), clearing the way for the new tables to use the same index names.
-- FK enforcement: at DROP time SQLite only checks for child rows in the table being
-- dropped, not the table's own outbound FKs. All tables are empty (pre-launch).
DROP TABLE refresh_tokens_v1;
DROP TABLE oauth_tokens_v1;
DROP TABLE sessions_v1;
DROP TABLE devices_v1;

-- Step 3: Create new devices with updated schema.
-- account_id references pending_accounts.id (the pre-DID account slot).
-- public_key is stored as provided by the device (used for future challenge-response auth).
-- device_token_hash is SHA-256(device_token); the plaintext token is returned once at
-- registration and never stored.
CREATE TABLE devices (
    id                TEXT NOT NULL,
    account_id        TEXT NOT NULL REFERENCES pending_accounts (id),
    platform          TEXT NOT NULL,   -- ios | android | macos | linux | windows
    public_key        TEXT NOT NULL,   -- device public key for challenge-response auth
    device_token_hash TEXT NOT NULL,   -- SHA-256(device_token) as hex; token returned once
    device_name       TEXT,            -- set by the device after registration
    created_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- Device listing by account (e.g., show all devices for a user).
CREATE INDEX idx_devices_account_id ON devices (account_id);

-- Step 4: Recreate sessions, oauth_tokens, and refresh_tokens with FKs pointing to the
-- new devices/sessions tables. Schemas are identical to V002 except for the FK targets.
CREATE TABLE sessions (
    id         TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    device_id  TEXT NOT NULL REFERENCES devices (id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_sessions_did ON sessions (did);

CREATE TABLE oauth_tokens (
    id         TEXT NOT NULL,
    client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id),
    did        TEXT NOT NULL REFERENCES accounts (did),
    device_id  TEXT REFERENCES devices (id),
    scope      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_oauth_tokens_did ON oauth_tokens (did);

CREATE TABLE refresh_tokens (
    jti               TEXT NOT NULL,
    did               TEXT NOT NULL REFERENCES accounts (did),
    session_id        TEXT NOT NULL REFERENCES sessions (id),
    next_jti          TEXT,
    expires_at        TEXT NOT NULL,
    app_password_name TEXT,
    created_at        TEXT NOT NULL,
    PRIMARY KEY (jti)
);

CREATE INDEX idx_refresh_tokens_did ON refresh_tokens (did);
