-- V040: Agent-action audit log.
--
-- Append-only record of what an auth.md agent identity did, attributed via the
-- `registration_id` claim agent-derived tokens carry. Powers the wallet's
-- per-agent audit trail (`GET /v1/agents/{registration_id}/audit`). Rows are
-- never updated or deleted by the query layer; the table follows the
-- `transfer_audit_events` (V030) conventions.
--
-- `did` is nullable because an anonymous registration has no owning account
-- until a claim ceremony binds one; the FK applies to non-NULL values only.
-- `detail` is a small JSON object of mechanical facts (collection names,
-- op counts, scope lists) -- never request bodies or token material.

CREATE TABLE agent_audit_events (
    id              TEXT NOT NULL,
    registration_id TEXT NOT NULL REFERENCES agent_identities (id),
    did             TEXT REFERENCES accounts (did),
    event_type      TEXT NOT NULL,
    detail          TEXT,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_agent_audit_events_registration_created_at
    ON agent_audit_events (registration_id, created_at);

CREATE INDEX idx_agent_audit_events_did_created_at
    ON agent_audit_events (did, created_at);
