-- The relay's whole world: who may talk to it, and which opaque handles they own.
--
-- No DIDs, no account handles, no raw device tokens beyond the APNs token Apple itself
-- requires — the relay is a blind courier, and this schema is the limit of what it knows.

-- Enrollment grants, minted by the operator (`notify-relay mint-code`). Status is derived
-- from the timestamps rather than stored (the pds crate's claim_codes doctrine): a code is
-- pending while unconsumed and unexpired, and redemption is a single guarded UPDATE.
CREATE TABLE enrollment_codes (
    code             TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT,
    consumed_by_node TEXT
) WITHOUT ROWID;

-- Instances allowed to register handles and push. `code_used` is NULL for a node enrolled
-- under open enrollment, which is exactly the audit distinction an operator wants.
CREATE TABLE enrollments (
    node_id     TEXT PRIMARY KEY,
    enrolled_at TEXT NOT NULL,
    code_used   TEXT
) WITHOUT ROWID;

-- Opaque push handles: 128 bits of randomness standing in for a device's APNs token, so
-- an instance never re-sends the token and the relay never correlates one across nodes.
CREATE TABLE handles (
    handle       TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL REFERENCES enrollments(node_id),
    apns_token   TEXT NOT NULL,
    apns_topic   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_push_at TEXT
) WITHOUT ROWID;

-- One live handle per (node, token): re-registering the same device rotates the handle
-- rather than accumulating aliases for it.
CREATE UNIQUE INDEX handles_node_token ON handles (node_id, apns_token);

-- Every lookup is scoped by the registering node id, so it leads the index.
CREATE INDEX handles_node ON handles (node_id);
