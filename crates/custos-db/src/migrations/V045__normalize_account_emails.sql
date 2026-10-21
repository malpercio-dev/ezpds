-- V045: Normalize existing account/pending-account emails to lowercase (trimmed), matching the
-- reference PDS's case-insensitive email storage and lookup (accounts.rs / uniqueness.rs now
-- normalize on every read and write path).
--
-- accounts.email and pending_accounts.email are both already covered by a UNIQUE index
-- (idx_accounts_email, idx_pending_accounts_email), so this normalizing UPDATE fails loudly —
-- the whole migration transaction rolls back — if two rows would collide once normalized (e.g.
-- 'Alice@Example.com' and 'alice@example.com' as distinct rows today). Such a collision needs an
-- operator to manually resolve which row is authoritative before this migration can apply.

UPDATE accounts SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
UPDATE pending_accounts SET email = LOWER(TRIM(email)) WHERE email != LOWER(TRIM(email));
