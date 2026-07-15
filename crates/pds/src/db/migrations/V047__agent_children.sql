-- Sovereign child agents are full local accounts whose recovery authority belongs to the
-- parent's wallet. The agent registration row is the durable ownership and capability link.

CREATE TABLE agent_claim_attempts_stash AS SELECT * FROM agent_claim_attempts;
DELETE FROM agent_claim_attempts;

CREATE TABLE agent_identities_new (
    id                       TEXT NOT NULL,
    did                      TEXT,
    parent_did               TEXT,
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
    CHECK (registration_type IN ('identity_assertion', 'service_auth', 'anonymous', 'child')),
    CHECK (status IN ('active', 'claimed', 'revoked')),
    CHECK (registration_type = 'child' OR parent_did IS NULL),
    CHECK (registration_type != 'child' OR (did IS NOT NULL AND parent_did IS NOT NULL)),
    FOREIGN KEY (did) REFERENCES accounts (did),
    FOREIGN KEY (parent_did) REFERENCES accounts (did)
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

DROP TABLE agent_identities;
ALTER TABLE agent_identities_new RENAME TO agent_identities;
INSERT INTO agent_claim_attempts SELECT * FROM agent_claim_attempts_stash;
DROP TABLE agent_claim_attempts_stash;

CREATE INDEX idx_agent_identities_did ON agent_identities (did);
CREATE INDEX idx_agent_identities_parent_did ON agent_identities (parent_did);
CREATE UNIQUE INDEX idx_agent_identities_claim_token
    ON agent_identities (claim_token)
    WHERE claim_token IS NOT NULL;
CREATE UNIQUE INDEX idx_agent_identities_iss_sub
    ON agent_identities (issuer, subject)
    WHERE issuer IS NOT NULL;

-- Durable local half of child provisioning. The account/handle/repo are reserved while the
-- account is deactivated; publication and final firehose/capability activation can then resume
-- safely after a process or network failure.
CREATE TABLE agent_child_provisionings (
    child_did            TEXT NOT NULL,
    parent_did           TEXT NOT NULL,
    handle               TEXT NOT NULL,
    registration_id      TEXT NOT NULL,
    signed_op            TEXT NOT NULL,
    scopes               TEXT NOT NULL,
    identity_assertion   TEXT NOT NULL,
    assertion_expires_at TEXT NOT NULL,
    genesis_car          BLOB NOT NULL,
    sync_car             BLOB NOT NULL,
    plc_published_at     TEXT,
    finalized_at         TEXT,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    PRIMARY KEY (child_did),
    UNIQUE (handle),
    UNIQUE (registration_id),
    FOREIGN KEY (child_did) REFERENCES accounts (did),
    FOREIGN KEY (parent_did) REFERENCES accounts (did)
);
