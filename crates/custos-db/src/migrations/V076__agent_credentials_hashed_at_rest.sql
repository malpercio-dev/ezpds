-- Agent credential material no longer rests in plain text. `agent_identities.claim_token` was
-- the raw polling secret and `identity_assertion` the raw post-claim bearer credential (a 30-day,
-- self-renewing JWT the jwt-bearer grant accepts), so anyone reading the database or a
-- Litestream backup could act as every claimed agent until each assertion expired.
--
-- The claim token is now stored as its SHA-256 hex (`claim_token_hash`, the `token_hash`
-- envelope every other single-use credential table uses) and looked up by hash. The assertion
-- is not stored at all: the surfaces that handed back "the stored assertion" re-mint one under
-- the server's OAuth key (the sliding renewal already did at every exchange), and the jwt-bearer
-- grant verifies by signature plus the claimed registration, never against a stored copy.
-- `agent_child_provisionings` held the same credential (and its expiry) for a resumed child
-- mint, which now re-mints too, so both columns go.
--
-- SQLite has no SHA-256, so an in-flight raw claim token cannot be hashed in place: it is
-- dropped with the column, and a claim ceremony open across this upgrade — including one the
-- owner has confirmed but the agent has not yet collected by polling — must re-register (its
-- poll answers `invalid_grant`). Claim tokens live `[agent_auth] claim_token_ttl_secs` (default
-- ten minutes), so the window is brief. An agent that already holds its assertion keeps
-- working: that credential is what it presents, and nothing here touches it.
--
-- `DROP COLUMN` refuses an indexed column, so the raw token's unique index goes first.
DROP INDEX idx_agent_identities_claim_token;
ALTER TABLE agent_identities DROP COLUMN claim_token;
ALTER TABLE agent_identities DROP COLUMN identity_assertion;
ALTER TABLE agent_identities ADD COLUMN claim_token_hash TEXT;
CREATE UNIQUE INDEX idx_agent_identities_claim_token_hash
    ON agent_identities (claim_token_hash)
    WHERE claim_token_hash IS NOT NULL;

ALTER TABLE agent_child_provisionings DROP COLUMN identity_assertion;
ALTER TABLE agent_child_provisionings DROP COLUMN assertion_expires_at;
