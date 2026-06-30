-- V030: Transfer completion audit metadata.
--
-- `POST /v1/transfer/complete` makes a planned device swap terminal. The
-- transfer row records when completion happened, and `transfer_audit_events`
-- gives operators a durable audit trail that the source credentials were revoked
-- and the accepted device became the surviving transfer device.

ALTER TABLE transfers ADD COLUMN completed_at TEXT;
ALTER TABLE transfer_devices ADD COLUMN revoked_at TEXT;

CREATE TABLE transfer_audit_events (
    id              TEXT NOT NULL,
    transfer_id     TEXT NOT NULL REFERENCES transfers (id),
    did             TEXT NOT NULL REFERENCES accounts (did),
    event_type      TEXT NOT NULL,
    actor_device_id TEXT,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_transfer_audit_events_transfer_id
    ON transfer_audit_events (transfer_id);

CREATE INDEX idx_transfer_audit_events_did_created_at
    ON transfer_audit_events (did, created_at);
