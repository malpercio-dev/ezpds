-- Add repo_root_cid to accounts table for tracking the ATProto repo root commit.
ALTER TABLE accounts ADD COLUMN repo_root_cid TEXT;
