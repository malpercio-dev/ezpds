-- Per-labeler seeding marker for the labeler watcher's operator notifications.
--
-- The first successful reconcile against a newly watched labeler backfills every label
-- already in force — flags the operator has had ample time to hear about elsewhere. A row
-- here means that backfill has happened: only labels first observed on a LATER pass are
-- genuinely news, and only those may page the operator's admin devices.
--
-- One row per labeler DID rather than a global flag, because labelers are added to
-- `[labeler] watched` independently: adding a second labeler must suppress ITS backfill
-- without silencing new flags from the first. Rows are pruned with the labeler's labels
-- when it leaves the watch list, so re-adding a labeler re-suppresses its backfill.
CREATE TABLE labels_seeded (
    labeler_did TEXT PRIMARY KEY,
    seeded_at TEXT NOT NULL
) WITHOUT ROWID;
