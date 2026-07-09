-- Account-scoped ownership rows for the globally content-addressed blob store.
--
-- `blobs` remains the physical content table keyed by CID (the on-disk file is stored once per
-- CID), but lifecycle metadata (`ref_count`, `temp_until`) is now per `(account_did, cid)` in
-- `blob_owners` — the same split V035 gave repo blocks. This prevents one account's blob GC or
-- account deletion from destroying a file another account's records still reference.
--
-- Rebuild order matters: `blob_owners` must be backfilled from the old rows' `ref_count`/
-- `temp_until` *before* those columns are dropped with the old table. So the old table is
-- renamed aside first, the new physical `blobs` table is created and populated under the
-- original name, `blob_owners` is created (its FK binds to that new `blobs` — SQLite resolves
-- FK parents by name against the schema at child-creation time) and backfilled, and only then
-- is the renamed-aside table dropped; nothing references it, so the drop is inert.

ALTER TABLE blobs RENAME TO blobs_old;

-- Physical content table. `account_did` records the first uploader for diagnostics/back-compat
-- only (FK to accounts removed); `blob_owners` is authoritative for ownership and lifecycle.
CREATE TABLE blobs (
    cid          TEXT PRIMARY KEY,
    account_did  TEXT NOT NULL,
    mime_type    TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    storage_path TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO blobs (cid, account_did, mime_type, size_bytes, storage_path, created_at)
SELECT cid, account_did, mime_type, size_bytes, storage_path, created_at FROM blobs_old;

CREATE TABLE blob_owners (
    cid         TEXT NOT NULL REFERENCES blobs(cid) ON DELETE CASCADE,
    account_did TEXT NOT NULL REFERENCES accounts(did),
    ref_count   INTEGER NOT NULL DEFAULT 0,
    temp_until  TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (account_did, cid)
) WITHOUT ROWID;

-- Every pre-migration row had exactly one recorded owner, so the backfill is lossless for
-- recorded ownership. Historic *implicit* sharing (a second account uploaded the same bytes and
-- the row kept the first uploader) is not reconstructible in SQL; blob GC's reconcile pass heals
-- it by walking every repo and adopting referenced CIDs into `blob_owners` (see blob_gc.rs),
-- which runs before any sweep can touch the file — so no legacy-protected flag is needed here.
INSERT INTO blob_owners (cid, account_did, ref_count, temp_until, created_at)
SELECT cid, account_did, ref_count, temp_until, created_at FROM blobs_old;

DROP TABLE blobs_old;

CREATE INDEX idx_blob_owners_cid ON blob_owners(cid);
CREATE INDEX idx_blob_owners_temp_until ON blob_owners(temp_until) WHERE temp_until IS NOT NULL;
