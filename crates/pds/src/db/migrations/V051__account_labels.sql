-- Account-level labels observed on hosted accounts from watched labelers
-- (`labeler_watch.rs`). One row per (account, labeler, label value) that is
-- currently in force; each poll pass reconciles the table against the labeler's
-- live label set, so a negated or expired label's row is deleted rather than
-- tombstoned. The table is an explicitly rebuildable cache of external labeler
-- state — the labeler's own log stays the source of truth.
--
-- `cts` is the labeler's label-creation timestamp (surfaced to the operator as
-- "when was this account flagged"); `first_seen_at` is when *this* server first
-- observed the (account, labeler, value) pair — the seam a future notifier uses
-- to tell a genuinely new flag from backfill.
CREATE TABLE account_labels (
    did TEXT NOT NULL REFERENCES accounts (did),
    labeler_did TEXT NOT NULL,
    val TEXT NOT NULL,
    cts TEXT NOT NULL,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (did, labeler_did, val)
) WITHOUT ROWID;

-- The per-labeler reconcile (fetch existing rows, delete a removed labeler's
-- rows) scans by labeler; per-account lookups ride the primary key's did prefix.
CREATE INDEX idx_account_labels_labeler ON account_labels (labeler_did);
