-- The maintained per-repo record count backing the write-path MST integrity check
-- (record_write::commit_repo_write): the independent second witness the MST lacks, so a
-- commit that silently drops keys (the 2026-08-27 atrium-repo split_subtree data loss)
-- disagrees with this count and the write aborts instead of persisting the corruption.
--
-- NULL = unknown (pre-V068 account, fresh genesis, or a just-imported repo); initialized
-- from a full MST key walk on the next successful record write and maintained by the
-- commit CAS thereafter.
ALTER TABLE accounts ADD COLUMN record_count INTEGER;
