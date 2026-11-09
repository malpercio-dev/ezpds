-- OAuth grants become agent records, so the owner can see and revoke them in My agents.
--
-- Two new registration types: `connector` (a grant for an MCP resource the operator named in
-- `[oauth] connector_resources`; its tokens carry the record's `registration_id`, so it is
-- audited and refused on owner-only routes) and `oauth_app` (every other grant; listed and
-- revocable, tokens unmarked). Both record the OAuth `client_id`, and an account has at most one
-- live record per (client, type): a re-approval links to it rather than adding a row.
--
-- The new types need the registration_type CHECK widened, which SQLite can only do by rebuilding
-- the table. The V047 rebuild invariant applies: every table with an FK into
-- `agent_identities (id)` — `agent_claim_attempts` and `agent_audit_events` — is cycled through a
-- stash around the swap, the audit stash carrying rowids because its cursors are rowid-based.

CREATE TABLE agent_claim_attempts_stash AS SELECT * FROM agent_claim_attempts;
DELETE FROM agent_claim_attempts;

CREATE TABLE agent_audit_events_stash AS
    SELECT rowid AS orig_rowid, * FROM agent_audit_events;
DELETE FROM agent_audit_events;

CREATE TABLE agent_identities_new (
    id                       TEXT NOT NULL,
    did                      TEXT,
    parent_did               TEXT,
    registration_type        TEXT NOT NULL,
    issuer                   TEXT,
    subject                  TEXT,
    email                    TEXT,
    scopes                   TEXT NOT NULL,
    assertion_expires_at     TEXT NOT NULL,
    pre_claim_scopes         TEXT,
    claim_token_expires_at   TEXT,
    status                   TEXT NOT NULL DEFAULT 'active',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    handle_hint              TEXT,
    claim_token_hash         TEXT,
    client_id                TEXT,
    PRIMARY KEY (id),
    CHECK (registration_type IN
        ('identity_assertion', 'service_auth', 'anonymous', 'child', 'connector', 'oauth_app')),
    CHECK (status IN ('active', 'claimed', 'revoked')),
    CHECK (registration_type = 'child' OR parent_did IS NULL),
    CHECK (registration_type != 'child' OR (did IS NOT NULL AND parent_did IS NOT NULL)),
    -- A grant record always names its client and account; nothing else carries a client_id.
    CHECK ((registration_type IN ('connector', 'oauth_app'))
           = (client_id IS NOT NULL AND did IS NOT NULL)),
    FOREIGN KEY (did) REFERENCES accounts (did),
    FOREIGN KEY (parent_did) REFERENCES accounts (did)
);

INSERT INTO agent_identities_new
    (id, did, parent_did, registration_type, issuer, subject, email, scopes,
     assertion_expires_at, pre_claim_scopes, claim_token_expires_at, status, created_at,
     updated_at, handle_hint, claim_token_hash)
SELECT
    id, did, parent_did, registration_type, issuer, subject, email, scopes,
    assertion_expires_at, pre_claim_scopes, claim_token_expires_at, status, created_at,
    updated_at, handle_hint, claim_token_hash
FROM agent_identities;

DROP TABLE agent_identities;
ALTER TABLE agent_identities_new RENAME TO agent_identities;

INSERT INTO agent_claim_attempts SELECT * FROM agent_claim_attempts_stash;
DROP TABLE agent_claim_attempts_stash;

INSERT INTO agent_audit_events (rowid, id, registration_id, did, event_type, detail, created_at)
    SELECT orig_rowid, id, registration_id, did, event_type, detail, created_at
    FROM agent_audit_events_stash;
DROP TABLE agent_audit_events_stash;

CREATE INDEX idx_agent_identities_did ON agent_identities (did);
CREATE INDEX idx_agent_identities_parent_did ON agent_identities (parent_did);
CREATE UNIQUE INDEX idx_agent_identities_iss_sub
    ON agent_identities (issuer, subject)
    WHERE issuer IS NOT NULL;
CREATE UNIQUE INDEX idx_agent_identities_claim_token_hash
    ON agent_identities (claim_token_hash)
    WHERE claim_token_hash IS NOT NULL;
CREATE UNIQUE INDEX idx_agent_identities_live_grant
    ON agent_identities (did, client_id, registration_type)
    WHERE client_id IS NOT NULL AND status != 'revoked';

-- The record a refresh-token family belongs to. No FK: the refresh read joins the record and
-- refuses a token whose record is revoked or gone, so a dangling id fails closed, and a future
-- `agent_identities` rebuild need not stash this table too.
ALTER TABLE oauth_tokens ADD COLUMN registration_id TEXT;

-- The RFC 8707 resource indicator a client named at PAR, carried to the code it yields so the
-- exchange can tell a connector grant from a plain app grant.
ALTER TABLE pending_oauth_authorizations ADD COLUMN resource TEXT;
ALTER TABLE oauth_authorization_codes ADD COLUMN resource TEXT;
