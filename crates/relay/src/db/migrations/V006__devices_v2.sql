-- V006: Rebuild devices table to support device registration via claim code
--
-- The V002 devices table required a NOT NULL DID FK to accounts, which prevents
-- registration before DID assignment. The new schema references pending_accounts.id
-- and adds platform, public_key, and device_token_hash for challenge-response auth.
--
-- Cascade: sessions and oauth_tokens FK to devices; refresh_tokens FKs to sessions.
-- SQLite does NOT auto-update FK references in child tables when a parent is renamed
-- (ALTER TABLE RENAME only rewrites references inside trigger and view bodies — not
-- foreign key definitions in other tables). All FK columns still reference the original
-- table names after the rename, which is exactly what we want: after the _v1 tables are
-- dropped and the new tables are created under the same original names, the unchanged FK
-- definitions automatically point to the correct new tables.
-- All four tables are empty at this migration (pre-launch), so no DML-time FK checks fire.
--
-- IMPORTANT index naming: SQLite indexes follow the table when it is renamed — they
-- retain their original names on the renamed table. Dropping the old tables (which
-- also drops their indexes) must happen BEFORE creating the new tables, otherwise
-- CREATE INDEX fails with "already exists". Drop order: children before parents.

-- Step 1: Rename all affected tables (children first so that at each rename the parent
-- table being renamed still exists; FK references in child tables are unchanged by the
-- rename, so their outbound FKs continue pointing to the original name, not the _v1 name).
ALTER TABLE refresh_tokens RENAME TO refresh_tokens_v1;
ALTER TABLE oauth_tokens RENAME TO oauth_tokens_v1;
ALTER TABLE sessions RENAME TO sessions_v1;
ALTER TABLE devices RENAME TO devices_v1;

-- Step 2: Drop old tables in children-before-parents order. Each DROP also removes
-- the table's indexes (idx_refresh_tokens_did, idx_oauth_tokens_did, idx_sessions_did,
-- idx_devices_did), clearing the way for the new tables to use the same index names.
-- FK enforcement at DROP time: SQLite checks only whether child rows reference the table
-- being dropped. Since no FK was updated to reference _v1 names (see above), nothing
-- references the _v1 tables — all FKs still point to the original names. Drop succeeds.
DROP TABLE refresh_tokens_v1;
DROP TABLE oauth_tokens_v1;
DROP TABLE sessions_v1;
DROP TABLE devices_v1;

-- Step 3: Create new devices with updated schema.
-- account_id references pending_accounts.id (the pre-DID account slot).
-- public_key is stored as provided by the device (used for future challenge-response auth).
-- device_token_hash is SHA-256(device_token); the plaintext token is returned once at
-- registration and never stored.
-- device_token_hash is UNIQUE: every registered device receives a distinct token;
-- the uniqueness constraint provides defense-in-depth and documents the invariant.
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

-- Each registered device must have a distinct token hash (defense-in-depth).
CREATE UNIQUE INDEX idx_devices_token_hash ON devices (device_token_hash);

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
