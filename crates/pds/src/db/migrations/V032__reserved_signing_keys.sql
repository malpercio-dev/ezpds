-- V032: Reserved repo signing keys for inbound account migration
-- Applied in a single transaction by the migration runner.
--
-- Standard account migration asks the destination PDS to reserve the repo signing
-- key before the local account row exists. When the migrating DID is known, `did`
-- makes the reservation idempotent; anonymous reservations are keyed by `id` so a
-- future createAccount migration path can claim them by the returned did:key.

CREATE TABLE reserved_signing_keys (
    id                    TEXT NOT NULL,
    did                   TEXT UNIQUE,
    key_type              TEXT NOT NULL,
    public_key            TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_reserved_signing_keys_did ON reserved_signing_keys (did);
