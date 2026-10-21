-- V009: Rebuild sessions for post-promotion auth
-- Applied in a single transaction by the migration runner.
--
-- 1. Makes device_id nullable.
--    V006 made devices transient (deleted at DID promotion), so promoted-account
--    sessions cannot reference a device row. The FK is kept but nullable.
--
-- 2. Adds token_hash for Bearer token authentication.
--    Pattern mirrors pending_sessions: 32 random bytes → base64url token returned
--    to client, SHA-256 hex stored here. Used by require_session in auth.rs.
--
-- SQLite does not support ALTER COLUMN, so a full table rebuild is required.
-- DROP TABLE does not check FK constraints; the refresh_tokens FK to sessions
-- remains valid after the rename.

CREATE TABLE sessions_new (
    id         TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    device_id  TEXT REFERENCES devices (id),  -- nullable: device deleted at promotion
    token_hash TEXT UNIQUE,                    -- SHA-256 hex of raw 32-byte token
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO sessions_new
    SELECT id, did, device_id, NULL, created_at, expires_at
    FROM sessions;

DROP TABLE sessions;

ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX idx_sessions_did ON sessions (did);
