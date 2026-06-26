-- Add repo_rev to accounts: the current commit revision (TID) of the repo, persisted
-- alongside repo_root_cid. This lets com.atproto.sync.listRepos report each repo's rev
-- straight from the accounts row instead of opening every repo to read its commit block.
-- NULL for accounts whose repo has not yet been created (and for pre-migration accounts,
-- which listRepos falls back to reading from the commit block).
ALTER TABLE accounts ADD COLUMN repo_rev TEXT;
