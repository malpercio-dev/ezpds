-- V037: auth.md agent identity and claim ceremony state.
--
-- Stores agent registrations created by the auth.md flows and the short-lived
-- user-code claim attempts that bind an anonymous/service registration to a
-- local account. Status is derived from explicit state columns rather than from
-- route-local memory so polling, claim completion, and revocation survive
-- restarts.

CREATE TABLE agent_identities (
    id                       TEXT NOT NULL,
    did                      TEXT NOT NULL,
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

CREATE INDEX idx_agent_identities_did ON agent_identities (did);
CREATE INDEX idx_agent_identities_claim_token ON agent_identities (claim_token);
CREATE UNIQUE INDEX idx_agent_identities_iss_sub
    ON agent_identities (issuer, subject)
    WHERE issuer IS NOT NULL;

CREATE TABLE agent_claim_attempts (
    id                    TEXT NOT NULL,
    identity_id           TEXT NOT NULL,
    user_code             TEXT NOT NULL,
    user_code_expires_at  TEXT NOT NULL,
    email                 TEXT,
    status                TEXT NOT NULL DEFAULT 'pending',
    created_at            TEXT NOT NULL,
    PRIMARY KEY (id),
    CHECK (status IN ('pending', 'completed', 'expired')),
    FOREIGN KEY (identity_id) REFERENCES agent_identities (id)
);

CREATE INDEX idx_agent_claim_attempts_user_code ON agent_claim_attempts (user_code);
CREATE INDEX idx_agent_claim_attempts_identity ON agent_claim_attempts (identity_id);
