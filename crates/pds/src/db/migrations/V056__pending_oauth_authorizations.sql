-- V056: Wallet-confirmed OAuth consent — the pending-authorization primitive.
--
-- A sovereign / migrated account has a NULL password_hash and so cannot pass the
-- password gate on the OAuth consent page (oauth_authorize.rs). This table is the
-- server-side object the consent page creates in place of the password check: a
-- short-lived, single-use request that the wallet approves out-of-band with a
-- device-key-signed envelope (crypto::encode_oauth_consent_envelope), after which the
-- browser completes through the existing authorization-code redirect tail.
--
-- Status is a derived-from-columns state machine (pending → approved → completed, or
-- pending → denied), plus a derived `expired` the read paths compute from `expires_at`
-- rather than persist (no background sweep: lapsed rows are reclaimed opportunistically
-- when the next request is created, matching oauth_par_requests / transfers). Every
-- terminal transition is a guarded single-statement UPDATE, so a replayed approval
-- envelope lands on an already-terminal row and affects zero rows — the request_id
-- binding in the signed envelope plus this single-use row together subsume a separate
-- nonce store.
--
-- `account_did` is deliberately NOT a foreign key to accounts: the row is ephemeral
-- (~5-minute expiry, reclaimed shortly after), the approving DID is already verified
-- against authoritative PLC state at approval time, and omitting the FK keeps this table
-- off the account-purge path (like agent_child_deletions.child_did / admin_audit_events).

CREATE TABLE pending_oauth_authorizations (
    request_id            TEXT NOT NULL,
    user_code             TEXT NOT NULL,
    client_id             TEXT NOT NULL REFERENCES oauth_clients (client_id),
    client_name           TEXT,
    redirect_uri          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL,
    state                 TEXT NOT NULL,
    response_type         TEXT NOT NULL,
    requested_scope       TEXT NOT NULL,
    login_hint            TEXT,
    origin                TEXT,
    ip                    TEXT,
    user_agent            TEXT,
    status                TEXT NOT NULL DEFAULT 'pending',
    account_did           TEXT,
    granted_scope         TEXT,
    created_at            TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    PRIMARY KEY (request_id),
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'completed'))
);

CREATE UNIQUE INDEX idx_pending_oauth_authorizations_user_code
    ON pending_oauth_authorizations (user_code);
CREATE INDEX idx_pending_oauth_authorizations_expires_at
    ON pending_oauth_authorizations (expires_at);

-- Append-only audit trail for the consent ceremony, in the agent_audit_events (V040) /
-- admin_audit_events (V052) mold: INSERT + SELECT only, no UPDATE/DELETE, rowid-cursor
-- pagination. Deliberately no foreign keys — the trail must outlive its ephemeral pending
-- row and the subject account. `detail` is a small JSON object of mechanical facts
-- (client id, granted-scope list, origin) — never signatures, codes, or token material.
CREATE TABLE oauth_consent_audit_events (
    id           TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    account_did  TEXT,
    client_id    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    detail       TEXT,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_oauth_consent_audit_events_request
    ON oauth_consent_audit_events (request_id, created_at);
