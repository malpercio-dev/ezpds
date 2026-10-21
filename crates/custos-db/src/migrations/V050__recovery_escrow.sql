-- V050: Escrow storage for the one Shamir share Custos holds.
--
-- `recovery_escrow` replaces `accounts.recovery_share` as the home of the
-- PDS-held Share 2 for accounts on the client-generated share model: one row
-- per account, holding the v2 share envelope AES-256-GCM-wrapped under the
-- master KEK from day one (registered in `SecretFamily::ALL`, so
-- `pds rewrap-master-key` covers it). The legacy column stays untouched until
-- the old-model re-key migration moves existing accounts over.
--
-- Release state is derived, not stored (the `claim_codes`/`transfers`
-- doctrine): `rotated_at` NULL = never replaced since deposit;
-- `release_requested_at`/`release_pending_until` NULL = no escrow release in
-- flight. The release columns are written only by the escrow release flow;
-- depositing a replacement share clears them (a new share voids any pending
-- release of the old one).
CREATE TABLE recovery_escrow (
    did                   TEXT PRIMARY KEY REFERENCES accounts (did),
    share_encrypted       TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    rotated_at            TEXT,
    release_requested_at  TEXT,
    release_pending_until TEXT
) WITHOUT ROWID;

-- Append-only audit trail for escrow lifecycle actions, modeled on
-- `agent_audit_events` (V040): the query layer exposes INSERT and SELECT only,
-- pagination cursors ride the table's rowid (append-only => rowid order =
-- event order), and account deletion is the sole remover. `detail` carries
-- mechanical facts only -- never share material.
--
-- The CHECK reserves the full event vocabulary at the schema level: the
-- deposit/rotate/delete events are written by the owner endpoints; the
-- release_* events belong to the escrow release flow.
CREATE TABLE recovery_audit_events (
    id         TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'deposited', 'rotated', 'deleted',
        'release_requested', 'release_cancelled', 'released')),
    detail     TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_recovery_audit_events_did_created_at
    ON recovery_audit_events (did, created_at);
