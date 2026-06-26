-- V012: OAuth token endpoint schema additions
-- Applied in a single transaction by the migration runner.
--
-- Adds DPoP key thumbprint (jkt) to oauth_tokens for DPoP-bound refresh tokens.
-- Creates oauth_signing_key single-row table for the server's persistent ES256 keypair.

-- DPoP key thumbprint — NULL for tokens issued before V012 or without DPoP binding.
ALTER TABLE oauth_tokens ADD COLUMN jkt TEXT;

-- Single-row table for the server's persistent ES256 signing keypair.
-- WITHOUT ROWID: the key is always fetched by its id (primary key lookup).
CREATE TABLE oauth_signing_key (
    id                    TEXT NOT NULL,  -- UUID key identifier
    public_key_jwk        TEXT NOT NULL,  -- JWK JSON string (EC P-256 public key)
    private_key_encrypted TEXT NOT NULL,  -- base64(nonce(12) || ciphertext(32) || tag(16))
    created_at            TEXT NOT NULL,  -- ISO 8601 UTC
    PRIMARY KEY (id)
) WITHOUT ROWID;
