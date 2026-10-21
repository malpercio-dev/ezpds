-- V011: Add pending shares to pending_accounts for idempotent share generation
-- Applied in a single transaction by the migration runner.
--
-- Stores the three base32-encoded Shamir shares alongside pending_did so that
-- retried DID ceremony requests return exactly the same shares. Without this,
-- every retry generates a fresh random secret: the first attempt's Share 2 is
-- committed to accounts.recovery_share, but Shares 1 and 3 from that attempt
-- were never delivered — orphaning the relay's share and breaking the 2-of-3
-- scheme for the user.
--
-- Flow:
--   First attempt:  pending_did IS NULL → generate shares, store all three +
--                   pending_did in a single UPDATE; proceed to plc.directory
--   Retry attempt:  pending_did IS NOT NULL → reuse stored shares; skip plc.directory
--   Promotion:      share_2 written to accounts.recovery_share inside the atomic
--                   transaction; pending_accounts row (including shares) is deleted
--
-- All three columns are NULL for pending accounts created before V011.

ALTER TABLE pending_accounts ADD COLUMN pending_share_1 TEXT;
ALTER TABLE pending_accounts ADD COLUMN pending_share_2 TEXT;
ALTER TABLE pending_accounts ADD COLUMN pending_share_3 TEXT;
