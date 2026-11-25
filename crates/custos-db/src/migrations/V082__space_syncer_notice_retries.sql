-- V082: the durable queue for the two notices a space host owes a syncer.
-- Applied in a single transaction by the migration runner.
--
-- A `spaceDeleted` or `registrationExpired` notice is written here in the transaction that
-- causes it (the deletion's tombstone, or the claim of a lapse), so a crash after that commit
-- still delivers it. One row per registration, keyed like `space_notify_registrations`; a
-- deletion replaces a pending notice, an expiry never does. `notice` is the `update` JSON the
-- syncer is sent. `attempts` counts failed tries; `retry_at` and `expires_at` are unix seconds,
-- and the retry window closes at `expires_at` (72 h after the notice was queued).
--
-- The token is the registration's, in plain text: every notice carries it. It is never logged.
-- No account FK: the rows name a space, and account purge deletes an authority's by space.
CREATE TABLE space_syncer_notice_retries (
    space_uri  TEXT NOT NULL REFERENCES spaces (uri),
    endpoint   TEXT NOT NULL,
    token      TEXT NOT NULL,
    notice     TEXT NOT NULL,
    attempts   INTEGER NOT NULL,
    retry_at   INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (space_uri, endpoint, token)
) WITHOUT ROWID;

CREATE INDEX space_syncer_notice_retries_retry_at ON space_syncer_notice_retries (retry_at);
