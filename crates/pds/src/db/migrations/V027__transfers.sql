-- V027: Planned device-swap transfer sessions.
--
-- Backs POST /v1/transfer/initiate (and the later accept/complete steps). A transfer
-- session lets an authenticated source device hand its account (the promoted DID) to a
-- new device using a short-TTL 6-character code the new device types in.
--
-- State machine: pending → accepted → completing → complete. `expired` is a terminal
-- state a still-pending transfer falls into once `expires_at` passes — set lazily on the
-- next initiate for the same DID (there is no background reaper yet), mirroring the
-- "status derived from timestamps" approach used elsewhere but materialised here because
-- a partial index cannot reference a non-deterministic `datetime('now')` (see below).
--
-- One active transfer per account: enforced by the partial UNIQUE index over `did`
-- restricted to the non-terminal states. Expiry is deliberately NOT in the index
-- predicate — SQLite requires partial-index predicates to be deterministic, and
-- `datetime('now')` is not — so `insert_transfer` first sweeps any expired-but-still-
-- active row for the DID to `expired`, freeing the index slot before inserting the new
-- row. A genuinely still-active (unexpired) transfer instead trips the index → 409.
CREATE TABLE transfers (
    id         TEXT NOT NULL,
    did        TEXT NOT NULL REFERENCES accounts (did),
    code       TEXT NOT NULL,                    -- 6-char uppercase alphanumeric verification code
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending | accepted | completing | complete | expired
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- At most one non-terminal (active) transfer per account. `complete` and `expired` are
-- terminal and excluded from the predicate, so a finished or swept transfer never blocks
-- a new one. The predicate is deterministic (constant status list), as SQLite requires.
CREATE UNIQUE INDEX idx_transfers_active_did
    ON transfers (did)
    WHERE status IN ('pending', 'accepted', 'completing');

-- At most one *active* transfer may hold a given code. The code is the lookup key the
-- new device presents at `/accept`, so an active-code collision across accounts would
-- make that lookup ambiguous. Restricted to the same active states as the per-DID index
-- (terminal `complete`/`expired` rows may freely share a recycled code), this both
-- enforces uniqueness and serves as the accept-time lookup index for active codes.
-- `insert_transfer` regenerates the code and retries when an INSERT trips this index.
CREATE UNIQUE INDEX idx_transfers_active_code
    ON transfers (code)
    WHERE status IN ('pending', 'accepted', 'completing');
