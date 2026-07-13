-- V043: Dedicated anti-replay store for sovereign-session signed requests.
--
-- Scope is per account DID: two identities may independently generate the same random nonce, but
-- one identity may consume a given nonce only once. This table is deliberately separate from
-- admin_nonces, whose rows are owned by admin device ids and have different lifecycle semantics.

CREATE TABLE sovereign_session_nonces (
    did     TEXT NOT NULL,
    nonce   TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY (did, nonce),
    FOREIGN KEY (did) REFERENCES accounts (did)
) WITHOUT ROWID;

CREATE INDEX idx_sovereign_session_nonces_seen_at
    ON sovereign_session_nonces (seen_at);
