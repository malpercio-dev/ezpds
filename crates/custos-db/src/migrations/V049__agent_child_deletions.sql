-- Durable tombstone for a parent's deletion of a sovereign child agent (MM-400).
--
-- Deleting a child reuses the deactivate + delete_after + reaper pipeline: the reaper eventually
-- calls account_delete::purge_account, which drops the child's account, repo, handle, blobs, the
-- agent_identities capability row AND (via the FK chain) the child's whole agent_audit_events
-- trail. So the child's own audit history cannot anchor "the deletion is auditable after the fact".
--
-- This table is that durable anchor (V030-style doctrine: the audit row survives the purge). It is
-- keyed by child_did but carries NO foreign key to accounts(did) on that column, so purging the
-- child's account row leaves it intact. It is anchored to parent_did (which DOES reference
-- accounts) so the parent's audit view outlives the child and the row is reclaimed only when the
-- parent itself is deleted (account_delete::purge_account deletes it WHERE parent_did = ?, never
-- WHERE child_did = ?). handle and registration_id are denormalized because their source rows are
-- purged with the child.
CREATE TABLE agent_child_deletions (
    child_did        TEXT NOT NULL,
    parent_did       TEXT NOT NULL,
    handle           TEXT NOT NULL,
    registration_id  TEXT NOT NULL,
    scheduled_at     TEXT NOT NULL,
    delete_after     TEXT NOT NULL,
    PRIMARY KEY (child_did),
    FOREIGN KEY (parent_did) REFERENCES accounts (did)
);

CREATE INDEX idx_agent_child_deletions_parent ON agent_child_deletions (parent_did);
