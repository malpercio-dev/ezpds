-- Space credentials an authority revoked through `com.atproto.space.notifyCredentialRevoked`.
-- The credential verifier refuses a `jti` listed here for its space. `expires_at` outlives every
-- credential that could carry the jti (the maximum credential lifetime plus clock skew); rows past
-- it are reclaimed by `space_jti_sweep.rs`.
CREATE TABLE space_revoked_credentials (
    space_uri  TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (space_uri, jti)
) WITHOUT ROWID;

CREATE INDEX idx_space_revoked_credentials_expires ON space_revoked_credentials (expires_at);
