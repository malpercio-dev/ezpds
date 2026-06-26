-- V022: Persistent Iroh node identity (Ed25519 secret key)
-- Applied in a single transaction by the migration runner.
--
-- Single-row table holding the relay's Iroh endpoint secret key, AES-256-GCM
-- encrypted with the signing-key master key (same scheme as oauth_signing_key
-- (V012) and jwt_signing_secret (V015)). Persisting it keeps the relay's Iroh
-- node id stable across restarts and redeploys, so device-cached node ids
-- (published via GET /v1/devices/:id/relay) stay valid instead of being
-- invalidated whenever a fresh ephemeral key was generated at startup.

-- WITHOUT ROWID: single row, fetched without a key.
CREATE TABLE iroh_identity (
    id             TEXT NOT NULL,  -- UUID identifier
    secret_key_encrypted TEXT NOT NULL,  -- base64(nonce(12) || ciphertext(32) || tag(16))
    created_at     TEXT NOT NULL,  -- ISO 8601 UTC
    PRIMARY KEY (id)
) WITHOUT ROWID;
