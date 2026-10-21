-- The permissioned-data lexicons split a space's single `policy` into a read policy and a write
-- policy, gave each member list entry its own read/write bits, and sequenced the writer set with
-- a per-space revision.
--
-- `spaces.policy` / `managing_app` keep their columns and now mean the READ policy; the write
-- policy gets its own pair, backfilled from the read policy so an existing space behaves exactly
-- as it did. Members and writers keep their rows: both bits default on (the old list admitted a
-- member for everything), and a writer's `space_rev` starts at its repo `rev` (a TID, so it sorts
-- correctly against the revisions assigned from here on).
ALTER TABLE spaces ADD COLUMN write_policy TEXT;
ALTER TABLE spaces ADD COLUMN write_managing_app TEXT;
UPDATE spaces SET write_policy = policy, write_managing_app = managing_app WHERE policy IS NOT NULL;

ALTER TABLE space_members ADD COLUMN can_read INTEGER NOT NULL DEFAULT 1;
ALTER TABLE space_members ADD COLUMN can_write INTEGER NOT NULL DEFAULT 1;

ALTER TABLE space_writers ADD COLUMN space_rev TEXT NOT NULL DEFAULT '';
UPDATE space_writers SET space_rev = rev;
CREATE INDEX idx_space_writers_rev ON space_writers (space_uri, space_rev);
