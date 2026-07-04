-- Account-scoped ownership rows for the globally content-addressed repo block byte store.
--
-- `blocks` remains the physical content table keyed by CID, but ownership/revision metadata is
-- now per `(account_did, cid)`. This prevents account-scoped GC from deleting the only physical
-- copy of a CID another account's repo also references.

-- Rebuild `blocks` so its legacy `account_did` column no longer has a foreign key to accounts.
-- It records the first writer for diagnostics/back-compat only; `block_owners` is authoritative.
CREATE TABLE blocks_new (
    cid         TEXT PRIMARY KEY,
    account_did TEXT NOT NULL,
    bytes       BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rev         TEXT,
    legacy_protected INTEGER NOT NULL DEFAULT 0
);

INSERT INTO blocks_new (cid, account_did, bytes, created_at, rev, legacy_protected)
SELECT cid, account_did, bytes, created_at, rev, 1 FROM blocks;

DROP TABLE blocks;
ALTER TABLE blocks_new RENAME TO blocks;

CREATE TABLE block_owners (
    cid         TEXT NOT NULL REFERENCES blocks(cid) ON DELETE CASCADE,
    account_did TEXT NOT NULL REFERENCES accounts(did),
    rev         TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (account_did, cid)
) WITHOUT ROWID;

-- Backfill the ownership rows that were explicit in the old schema. Historic implicit shared
-- references cannot be reconstructed from SQL alone, so migrated physical rows are marked
-- legacy-protected and are not deleted by per-account GC even if no explicit owner remains.
INSERT INTO block_owners (cid, account_did, rev, created_at)
SELECT cid, account_did, rev, created_at FROM blocks;

CREATE INDEX idx_block_owners_cid ON block_owners(cid);
CREATE INDEX idx_block_owners_account_rev ON block_owners(account_did, rev);
