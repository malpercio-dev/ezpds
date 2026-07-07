-- V038: allow an anonymous agent identity to exist without an owning account DID.
--
-- The auth.md `anonymous` registration flow (spec §3.3) registers an agent that has no user
-- identity yet: it receives a pre-claim assertion plus a `claim_token` for an optional later
-- claim ceremony. The V037 schema made `agent_identities.did` NOT NULL with a FK to
-- `accounts(did)`, so such a registration could not be stored. This migration rebuilds the table
-- to make `did` nullable (NULL = anonymous, not yet bound to an account); the FK still applies to
-- non-NULL values, so a bound identity is still checked against `accounts`.
--
-- SQLite cannot drop a column's NOT NULL constraint in place, so `agent_identities` is rebuilt.
-- It is referenced by `agent_claim_attempts(identity_id)`, and neither pragma escape hatch works
-- inside the migration transaction:
--   * `PRAGMA foreign_keys` cannot be toggled mid-transaction, so FK enforcement can't be disabled
--     for the swap.
--   * `PRAGMA defer_foreign_keys` would defer checks to COMMIT, but SQLite tracks deferred
--     violations with a counter, not a re-scan: dropping the old parent implicit-deletes its rows
--     while the child still references the table *name*, incrementing the counter, and the rows in
--     the renamed replacement table never decrement it — so COMMIT still fails.
-- Instead the child rows are cycled through a temp stash — emptied before the parent swap and
-- refilled after — so no child row ever references a missing parent and foreign-key enforcement
-- can stay ON throughout.

CREATE TABLE agent_identities_new (
    id                       TEXT NOT NULL,
    did                      TEXT,
    registration_type        TEXT NOT NULL,
    issuer                   TEXT,
    subject                  TEXT,
    email                    TEXT,
    scopes                   TEXT NOT NULL,
    identity_assertion       TEXT,
    assertion_expires_at     TEXT NOT NULL,
    pre_claim_scopes         TEXT,
    claim_token              TEXT,
    claim_token_expires_at   TEXT,
    status                   TEXT NOT NULL DEFAULT 'active',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    PRIMARY KEY (id),
    CHECK (registration_type IN ('identity_assertion', 'service_auth', 'anonymous')),
    CHECK (status IN ('active', 'claimed', 'revoked')),
    FOREIGN KEY (did) REFERENCES accounts (did)
);

INSERT INTO agent_identities_new
    (id, did, registration_type, issuer, subject, email, scopes, identity_assertion,
     assertion_expires_at, pre_claim_scopes, claim_token, claim_token_expires_at, status,
     created_at, updated_at)
SELECT
    id, did, registration_type, issuer, subject, email, scopes, identity_assertion,
    assertion_expires_at, pre_claim_scopes, claim_token, claim_token_expires_at, status,
    created_at, updated_at
FROM agent_identities;

-- Cycle the child rows out of the way so the parent swap never orphans them.
CREATE TEMP TABLE agent_claim_attempts_stash AS SELECT * FROM agent_claim_attempts;
DELETE FROM agent_claim_attempts;

DROP TABLE agent_identities;
ALTER TABLE agent_identities_new RENAME TO agent_identities;

-- Refill the child against the rebuilt parent (every identity_id still resolves).
INSERT INTO agent_claim_attempts SELECT * FROM agent_claim_attempts_stash;
DROP TABLE agent_claim_attempts_stash;

CREATE INDEX idx_agent_identities_did ON agent_identities (did);
CREATE UNIQUE INDEX idx_agent_identities_claim_token
    ON agent_identities (claim_token)
    WHERE claim_token IS NOT NULL;
CREATE UNIQUE INDEX idx_agent_identities_iss_sub
    ON agent_identities (issuer, subject)
    WHERE issuer IS NOT NULL;
