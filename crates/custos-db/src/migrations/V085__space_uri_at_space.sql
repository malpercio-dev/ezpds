-- V085: stored space URIs move from `at://{spaceDid}/space/{spaceType}/{skey}` to
-- `at:space/{spaceDid}/{spaceType}/{skey}`, the form the server accepts and emits.
--
-- Every column that keys a row on a space URI is rewritten: `spaces.uri` and the `space_uri`
-- of the nine tables below. Record values (`space_records.value`) are left alone, since
-- rewriting one would change its CID; so is the admin audit log, which records what was true
-- when it was written.
--
-- Each UPDATE matches only the old form, so a second run changes nothing. A DID holds no `/`,
-- so the first `/space/` in an old-form URI is the marker.
--
-- `spaces.uri` is a parent key with no ON UPDATE CASCADE, and `space_repos` is one in turn, so
-- the foreign-key checks are deferred to the end of the migration: every child is rewritten by
-- the same expression as its parent, which returns the deferred-violation counter to zero.
-- (Plain UPDATEs keep that counter balanced; V038's objection to it concerns a table rebuild.)
PRAGMA defer_foreign_keys = ON;

UPDATE spaces
   SET uri = 'at:space/' || substr(uri, 6, instr(uri, '/space/') - 6) || substr(uri, instr(uri, '/space/') + 6)
 WHERE uri LIKE 'at://%/space/%';

UPDATE space_repos
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_records
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_repo_ops
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_members
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_writers
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_notify_registrations
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_revoked_credentials
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_syncer_notice_retries
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

UPDATE space_repo_update_retries
   SET space_uri = 'at:space/' || substr(space_uri, 6, instr(space_uri, '/space/') - 6) || substr(space_uri, instr(space_uri, '/space/') + 6)
 WHERE space_uri LIKE 'at://%/space/%';

PRAGMA defer_foreign_keys = OFF;
