-- V015: Persistent HS256 JWT signing secret
-- Applied in a single transaction by the migration runner.
--
-- Single-row table holding the server's HS256 JWT signing secret, AES-256-GCM
-- encrypted with the signing-key master key (same scheme as oauth_signing_key,
-- V012). Persisting it means issued access/refresh tokens survive restarts and
-- redeploys, instead of being invalidated whenever a fresh ephemeral secret was
-- generated at startup.

-- WITHOUT ROWID: single row, fetched without a key.
CREATE TABLE jwt_signing_secret (
    id               TEXT NOT NULL,  -- UUID identifier
    secret_encrypted TEXT NOT NULL,  -- base64(nonce(12) || ciphertext(32) || tag(16))
    created_at       TEXT NOT NULL,  -- ISO 8601 UTC
    PRIMARY KEY (id)
) WITHOUT ROWID;
