Repo writes can no longer silently destroy records: a local patch to the atrium-repo
MST fixes an upstream bug (atrium-rs/atrium#343) where inserting a record whose key
hashes to a higher tree layer could discard every record sorting on one side of the
insertion point — whole collections vanished with no error and no firehose delete.
