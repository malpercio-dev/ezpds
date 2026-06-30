-- V029: Transfer-accept device credentials for promoted accounts.
--
-- The original `devices` table is tied to `pending_accounts` and is deleted during DID
-- promotion, so planned device swaps for already-promoted DIDs need a separate durable
-- credential store. `transfer_devices` records the new device that accepted a transfer
-- code; `/v1/devices/:id/pds` accepts either legacy pre-DID device credentials or these
-- promoted-account transfer credentials.

CREATE TABLE transfer_devices (
    id                TEXT NOT NULL,
    did               TEXT NOT NULL REFERENCES accounts (did),
    platform          TEXT NOT NULL,   -- ios | android | macos | linux | windows
    public_key        TEXT NOT NULL,   -- device public key for challenge-response auth
    device_token_hash TEXT NOT NULL,   -- SHA-256(device_token) as hex; token returned once
    created_at        TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_transfer_devices_did ON transfer_devices (did);
CREATE UNIQUE INDEX idx_transfer_devices_token_hash ON transfer_devices (device_token_hash);

ALTER TABLE transfers ADD COLUMN accepted_device_id TEXT REFERENCES transfer_devices (id);
ALTER TABLE transfers ADD COLUMN accepted_at TEXT;
