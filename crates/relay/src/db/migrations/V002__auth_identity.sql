-- V002: Auth + Identity tables
-- Applied in a single transaction by the migration runner.

-- ── Account & Identity ───────────────────────────────────────────────────────

CREATE TABLE accounts (
    did                TEXT NOT NULL,
    email              TEXT NOT NULL,
    password_hash      TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    email_confirmed_at TEXT,
    deactivated_at     TEXT,
    PRIMARY KEY (did)
);

CREATE UNIQUE INDEX idx_accounts_email ON accounts (email);

-- WITHOUT ROWID: handle is the only access path (handle lookups are always by PK).
CREATE TABLE handles (
    handle     TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    created_at TEXT NOT NULL,
    PRIMARY KEY (handle)
) WITHOUT ROWID;

-- WITHOUT ROWID: DID documents are always fetched by DID (the PK).
CREATE TABLE did_documents (
    did        TEXT NOT NULL,
    document   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (did)
) WITHOUT ROWID;

CREATE TABLE signing_keys (
    id                    TEXT NOT NULL,
    did                   TEXT NOT NULL REFERENCES accounts (did),
    key_type              TEXT NOT NULL,
    public_key            TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- ── Device & Provisioning ────────────────────────────────────────────────────

CREATE TABLE devices (
    id           TEXT NOT NULL,
    did          TEXT NOT NULL REFERENCES accounts (did),
    device_name  TEXT NOT NULL,
    user_agent   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE claim_codes (
    code                 TEXT NOT NULL,
    did                  TEXT NOT NULL REFERENCES accounts (did),
    expires_at           TEXT NOT NULL,
    claimed_at           TEXT,
    claimed_by_device_id TEXT REFERENCES devices (id),
    PRIMARY KEY (code)
);

CREATE INDEX idx_claim_codes_did ON claim_codes (did);

-- ── Sessions & Tokens ────────────────────────────────────────────────────────

CREATE TABLE sessions (
    id         TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    device_id  TEXT NOT NULL REFERENCES devices (id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE refresh_tokens (
    jti               TEXT NOT NULL,
    did               TEXT NOT NULL REFERENCES accounts (did),
    session_id        TEXT NOT NULL REFERENCES sessions (id),
    next_jti          TEXT,
    expires_at        TEXT NOT NULL,
    app_password_name TEXT,
    created_at        TEXT NOT NULL,
    PRIMARY KEY (jti)
);

CREATE INDEX idx_refresh_tokens_did ON refresh_tokens (did);

-- ── OAuth ────────────────────────────────────────────────────────────────────

-- WITHOUT ROWID: OAuth clients are always looked up by client_id (the PK).
CREATE TABLE oauth_clients (
    client_id       TEXT NOT NULL,
    client_metadata TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (client_id)
) WITHOUT ROWID;

CREATE TABLE oauth_authorization_codes (
    code                  TEXT NOT NULL,
    client_id             TEXT NOT NULL REFERENCES oauth_clients (client_id),
    did                   TEXT NOT NULL REFERENCES accounts (did),
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    PRIMARY KEY (code)
);

CREATE TABLE oauth_tokens (
    id         TEXT NOT NULL,
    client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id),
    did        TEXT NOT NULL REFERENCES accounts (did),
    device_id  TEXT REFERENCES devices (id),
    scope      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_oauth_tokens_did ON oauth_tokens (did);

-- WITHOUT ROWID: PAR requests are always fetched or deleted by request_uri (the PK).
CREATE TABLE oauth_par_requests (
    request_uri        TEXT NOT NULL,
    client_id          TEXT NOT NULL REFERENCES oauth_clients (client_id),
    request_parameters TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    PRIMARY KEY (request_uri)
) WITHOUT ROWID;
