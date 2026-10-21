-- V055: Drop the legacy server-side Shamir share columns from pending_accounts.
-- Applied in a single transaction by the migration runner.
--
-- V011 added pending_share_{1,2,3} so the retired server-side DID ceremony could
-- return the same three shares across retries (idempotent generation, avoiding an
-- orphaned Share 2 in accounts.recovery_share). The ceremony inversion (MM-407)
-- moved share generation client-side: POST /v1/dids now takes the wallet's Share 2
-- envelope and stores it in recovery_escrow, and the server no longer generates or
-- splits any secret. With the legacy server-side path retired (MM-426), nothing
-- reads or writes these columns — they only ever put full reconstruction material
-- (two of three shares, on retry) into Litestream backups.
--
-- Forward-only: the columns are plain nullable TEXT with no index, FK, or default,
-- so DROP COLUMN (SQLite >= 3.35) applies cleanly on a populated pending_accounts.
-- pending_did (V008) and pending_plc_registered_at (V054) stay — they gate the DID
-- pre-store / plc.directory re-POST retry logic, which is share-independent.

ALTER TABLE pending_accounts DROP COLUMN pending_share_1;
ALTER TABLE pending_accounts DROP COLUMN pending_share_2;
ALTER TABLE pending_accounts DROP COLUMN pending_share_3;
