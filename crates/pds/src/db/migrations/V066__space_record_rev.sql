-- V066: per-record rev for the Atproto Spaces sync surface.
--
-- `com.atproto.space.listBlobs` takes a `since` rev and must answer "which blobs are
-- referenced by records written after that rev" — a durable fact about the record store, not
-- one the droppable/compactable oplog can carry (a compacted oplog would silently shrink the
-- answer). The reference stores the same thing as `space_record.repoRev`. Written by the write
-- choke point (`space_record_write.rs`) with the commit's rev on every create/update.
ALTER TABLE space_records ADD COLUMN rev TEXT;

-- Backfill: stamp every existing record with its repo's current head rev. Over-inclusive on
-- purpose — a `since` listing may report a blob whose record predates the rev, never miss one.
UPDATE space_records
SET rev = (
    SELECT r.rev FROM space_repos r
    WHERE r.space_uri = space_records.space_uri
      AND r.account_did = space_records.account_did
);
