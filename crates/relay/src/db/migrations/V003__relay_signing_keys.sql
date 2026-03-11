-- V003: Relay-level signing keys
-- Applied in a single transaction by the migration runner.
--
-- Relay signing keys are operator-level keys used to sign user repo commits.
-- Unlike signing_keys (V002), these are not tied to a specific account DID.

-- ── Relay Signing Keys ───────────────────────────────────────────────────────

-- WITHOUT ROWID: keys are always fetched by their did:key URI (the primary key).
CREATE TABLE relay_signing_keys (
    id                    TEXT NOT NULL,  -- full did:key:z... URI; derived from public key
    algorithm             TEXT NOT NULL,  -- "p256"
    public_key            TEXT NOT NULL,  -- multibase base58btc compressed point
    private_key_encrypted TEXT NOT NULL,  -- base64(12-byte nonce || 32-byte ciphertext || 16-byte tag)
    created_at            TEXT NOT NULL,  -- ISO 8601 UTC
    PRIMARY KEY (id)
) WITHOUT ROWID;
