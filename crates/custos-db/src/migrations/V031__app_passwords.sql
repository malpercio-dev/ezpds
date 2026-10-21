-- V031: App passwords — named credentials for the legacy (non-OAuth) createSession flow.
--
-- Each row is one app password an account has issued: a human-readable `name`, the argon2id
-- PHC hash of the generated secret (the plaintext is surfaced once at creation and never
-- stored), and a `privileged` flag mirroring atproto's `com.atproto.appPass` vs
-- `com.atproto.appPassPrivileged` scopes. createSession verifies a supplied password against
-- these hashes when the main account password does not match; the resulting session's access
-- token carries the app-pass scope instead of full `com.atproto.access`.
--
-- WITHOUT ROWID keyed by (did, name): every access path is either the exact (did, name) pair
-- (create collision / revoke) or the (did) prefix (list / verify-candidates), both served by
-- the primary key. `name` is unique per account — a duplicate INSERT trips the PK and surfaces
-- as a 409 to the caller.
CREATE TABLE app_passwords (
    did           TEXT    NOT NULL REFERENCES accounts (did),
    name          TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    privileged    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL,
    PRIMARY KEY (did, name)
) WITHOUT ROWID;
