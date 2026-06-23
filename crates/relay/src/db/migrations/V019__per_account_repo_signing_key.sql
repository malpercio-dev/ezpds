-- Per-account ATProto repo signing key.
--
-- Generated during the DID ceremony and published as the DID's #atproto
-- verification method (replacing the shared operator key). Stored on the
-- pending account until promotion, then copied into signing_keys (DID-keyed)
-- inside the promotion transaction. The private key is AES-256-GCM encrypted
-- with the relay's master key (same format as relay_signing_keys).
ALTER TABLE pending_accounts ADD COLUMN repo_signing_key_id TEXT;
ALTER TABLE pending_accounts ADD COLUMN repo_signing_public_key TEXT;
ALTER TABLE pending_accounts ADD COLUMN repo_signing_private_key_encrypted TEXT;
