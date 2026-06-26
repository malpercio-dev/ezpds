-- V010: Add recovery_share to accounts for Shamir relay custody
-- Applied in a single transaction by the migration runner.
--
-- Stores Share 2 of the 2-of-3 Shamir split of the per-user recovery secret.
-- Share 1 goes to the user's iCloud Keychain; Share 3 goes to the user's
-- manual backup. Any two of the three shares can reconstruct the recovery
-- secret, enabling account recovery without both the relay and the user's
-- device being available simultaneously.
--
-- Encoded as base32 (RFC 4648, no padding) — 52 uppercase A-Z/2-7 characters.
-- NULL for accounts created before V010 (pre-Shamir accounts).

ALTER TABLE accounts ADD COLUMN recovery_share TEXT;
