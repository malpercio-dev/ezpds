-- The permissioned-data spec reworked who notifies whom.
--
-- A repo host no longer auto-registers with the space authority: it pushes `notifyWrite` straight
-- to the authority's `#atproto_space_host` on every write. Delete the per-repo rows that
-- registration left behind; only whole-space rows (`repo_did = ''`, written by `registerNotify`)
-- remain. The column stays, since it is part of the V065 primary key.
DELETE FROM space_notify_registrations WHERE repo_did != '';

-- The last space revision assigned in each space, so the next one is assigned after it even when
-- the writer row that carried it has since been deleted (account purge drops a writer's row).
-- Backfilled from the writer set, which until now was the only record of it.
ALTER TABLE spaces ADD COLUMN last_space_rev TEXT;
UPDATE spaces SET last_space_rev = (
    SELECT MAX(space_rev) FROM space_writers
    WHERE space_writers.space_uri = spaces.uri AND space_rev != ''
);
