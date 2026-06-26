-- Blob storage metadata.
-- Blobs are stored on the local filesystem; this table tracks metadata and lifecycle.
CREATE TABLE blobs (
    cid          TEXT PRIMARY KEY,       -- base32-multihash CID (bafk...)
    account_did  TEXT NOT NULL REFERENCES accounts(did),
    mime_type    TEXT NOT NULL,           -- MIME type detected via magic bytes
    size_bytes   INTEGER NOT NULL,        -- blob size in bytes
    storage_path TEXT NOT NULL,           -- relative path under data_dir/blobs/
    ref_count    INTEGER NOT NULL DEFAULT 0, -- number of repo records referencing this blob
    temp_until   TEXT,                    -- ISO-8601 expiry for unreferenced uploads; NULL = permanent
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_blobs_account_did ON blobs(account_did);
CREATE INDEX idx_blobs_temp_until ON blobs(temp_until) WHERE temp_until IS NOT NULL;
