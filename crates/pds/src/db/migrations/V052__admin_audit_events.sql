-- Server-wide append-only admin action audit log: one row per privileged admin action,
-- attributing it to the acting credential (the master token or a specific paired device).
--
-- Deliberately no foreign keys: an audit trail must outlive its subjects. A takedown row
-- survives the account's later permanent deletion, a device_revoked row survives its
-- device, and `actor` is the AdminActor log string ("master-token" / "device:<id>"), not a
-- device FK. This is the server's own history — unlike `operator_account_audit_events`
-- (V046), whose account-owned rows are purged with their account — so nothing deletes
-- from this table.
--
-- `subject` is the acted-on entity (account DID, admin-device id, transfer id, claim
-- code) when the action has one. `outcome` is a short result word ("ok", "revoked", ...).
-- `detail` is a compact JSON object of mechanical facts (counts, resulting status) —
-- never request bodies, pairing codes, or token material. Pagination cursors read the
-- implicit rowid (append-only => rowid order = event order), matching V040.
CREATE TABLE admin_audit_events (
    id         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    subject    TEXT,
    outcome    TEXT NOT NULL,
    detail     TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_admin_audit_events_action ON admin_audit_events (action);
CREATE INDEX idx_admin_audit_events_actor ON admin_audit_events (actor);
CREATE INDEX idx_admin_audit_events_subject ON admin_audit_events (subject);
