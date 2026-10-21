-- Content-addressed block storage for ATProto repositories.
-- Each block is a single DAG-CBOR object (MST node or record), addressed by CIDv1.
CREATE TABLE blocks (
    cid         TEXT PRIMARY KEY,           -- CIDv1 (dag-cbor codec, sha2-256)
    account_did TEXT NOT NULL REFERENCES accounts(did),
    bytes       BLOB NOT NULL,             -- raw DAG-CBOR bytes
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_blocks_account_did ON blocks(account_did);
