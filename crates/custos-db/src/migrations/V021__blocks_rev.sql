-- Per-block commit revision (TID) for com.atproto.sync.getRepo?since=<rev> incremental export.
-- A block's rev is the revision of the commit that introduced it. Because revisions are TIDs
-- (lexicographically ordered by time), getRepo with `since` selects exactly the blocks whose
-- rev sorts after the requested revision, letting a consumer catch up without re-downloading
-- the whole repo. Nullable: a block is written by an in-flight commit before that commit's
-- revision is final, then tagged once the commit's root swap succeeds.
ALTER TABLE blocks ADD COLUMN rev TEXT;

-- Backfill existing blocks with their account's current repo revision. Pre-migration repos
-- carry no per-block history, so the best reconstruction is "introduced at the current rev":
-- a consumer behind the current rev then receives the full block set, which is correct if
-- coarse, and `since = current rev` correctly yields nothing new.
UPDATE blocks
SET rev = (SELECT repo_rev FROM accounts WHERE accounts.did = blocks.account_did)
WHERE rev IS NULL;

-- Supports the `WHERE account_did = ? AND rev > ?` range scan that drives incremental export.
CREATE INDEX idx_blocks_account_rev ON blocks(account_did, rev);
