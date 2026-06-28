-- V026: Moderation-lifecycle timestamps for getRepoStatus / listRepos
--
-- com.atproto.sync.getRepoStatus reports a repo's hosting status so relays/BGS know whether to
-- crawl and serve it. Until now the only lifecycle signal on `accounts` was `deactivated_at`
-- (V008) — a user-initiated state — so the endpoint could only ever report `active` or
-- `deactivated`. The lexicon's `status` knownValues also cover moderation states: `takendown`
-- (a permanent operator action) and `suspended` (temporary). A relay must see these to stop
-- serving a repo; reporting only `active`/`deactivated` would leave a suspended or taken-down
-- repo looking `active` to the network.
--
-- These two nullable timestamps record *when* each moderation state was entered, mirroring how
-- `deactivated_at` records deactivation. Status is derived, not stored (matching `deactivated_at`
-- and the `claim_codes` pattern): an account is taken down while `taken_down_at IS NOT NULL` and
-- suspended while `suspended_at IS NOT NULL`. When more than one is set the strongest wins, with
-- reporting precedence takendown > suspended > deactivated.
--
-- There is no writer for these columns yet: the admin takedown/suspend actions
-- (com.atproto.admin updateSubjectStatus parity) are separate, later work. This migration lands
-- the read-side half — the columns plus getRepoStatus/listRepos reporting — so that producer can
-- write against a schema that already models the state. The repo-write and login gates continue
-- to key on `deactivated_at` only until that producer exists.

ALTER TABLE accounts ADD COLUMN suspended_at TEXT;
ALTER TABLE accounts ADD COLUMN taken_down_at TEXT;
