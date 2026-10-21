-- Lifecycle status for per-account repo signing keys.
--
-- A wallet-driven key rotation needs somewhere to hold a freshly generated
-- replacement key while the DID document still points at the old one: the
-- commit-signing lookup selects the newest row per DID, so inserting the new
-- key directly would flip the signer before the DID document repoints at it,
-- leaving commits signed by a key absent from the document. 'staged' rows are
-- invisible to every 'active'-filtered reader until the rotation cutover
-- promotes them in one transaction (and deletes the retired 'active' rows).
ALTER TABLE signing_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
