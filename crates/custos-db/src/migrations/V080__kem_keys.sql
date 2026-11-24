-- V080: per-account KEM keys for Atproto Spaces (ADR-0043).
-- Applied in a single transaction by the migration runner.
--
-- A KEM key is the account's `#atproto_kem` verification method: syncers combine it with a
-- throwaway key of their own to agree a per-request MAC secret with this host. It never signs,
-- so it lives in its own table rather than in `signing_keys`, where the commit-signer lookup
-- could pick it up. The three homes mirror the signing key's: the pending account during the
-- DID ceremony, a reservation before the account exists, and the promoted account.

-- The promoted account's keys. 'active' is the key the DID document publishes; 'staged' is a
-- replacement waiting for the wallet-signed op (or did.json) that publishes it. At most one of
-- each per account.
CREATE TABLE kem_keys (
    id                    TEXT NOT NULL,
    did                   TEXT NOT NULL REFERENCES accounts (did),
    key_type              TEXT NOT NULL,
    public_key            TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'staged')),
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX idx_kem_keys_did_status ON kem_keys (did, status);

-- `reserveKemKey` reservations, the counterpart of `reserved_signing_keys` (V032): `did` is
-- nullable and UNIQUE for idempotent known-DID reservations; anonymous ones are claimed by `id`.
CREATE TABLE reserved_kem_keys (
    id                    TEXT NOT NULL,
    did                   TEXT UNIQUE,
    key_type              TEXT NOT NULL,
    public_key            TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- The DID ceremony's KEM key, issued with the repo signing key by GET /v1/repo-signing-key and
-- copied into `kem_keys` at promotion. All three NULL until issued.
ALTER TABLE pending_accounts ADD COLUMN kem_key_id TEXT;
ALTER TABLE pending_accounts ADD COLUMN kem_public_key TEXT;
ALTER TABLE pending_accounts ADD COLUMN kem_private_key_encrypted TEXT;
