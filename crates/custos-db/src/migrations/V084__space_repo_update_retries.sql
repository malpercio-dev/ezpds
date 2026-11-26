-- V084: the durable queue for the `notifyRepoUpdate` a repo host owes a foreign space host.
-- Applied in a single transaction by the migration runner.
--
-- Written in the commit's transaction when a local repo's write lands in a space governed
-- elsewhere, so a crash after that commit still delivers it. One row per (repo, space),
-- coalesced to the newest rev: a newer commit replaces the payload and resets the schedule and
-- the window; an older one never replaces a newer. `repo_rev` and `data` (the set hash) are what
-- the notification carries. `attempts` counts failed tries; `retry_at` and `expires_at` are unix
-- seconds, and the retry window closes at `expires_at` (24 h after the newest commit).
CREATE TABLE space_repo_update_retries (
    repo_did   TEXT NOT NULL REFERENCES accounts (did),
    space_uri  TEXT NOT NULL REFERENCES spaces (uri),
    repo_rev   TEXT NOT NULL,
    data       BLOB NOT NULL,
    attempts   INTEGER NOT NULL,
    retry_at   INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (repo_did, space_uri)
) WITHOUT ROWID;

CREATE INDEX space_repo_update_retries_retry_at ON space_repo_update_retries (retry_at);
