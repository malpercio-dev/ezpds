-- V041: Operator revocation for claim codes
--
-- A minted-but-unredeemed claim code is a live signup credential; the operator needs to be
-- able to kill one (a code shared to the wrong channel, a batch minted by mistake) without
-- waiting out its expiry. Following the derived-status doctrine (V004: pending/redeemed/
-- expired from timestamps; V025: admin-device active/revoked from `revoked_at`), revocation
-- is a nullable timestamp, not a status column: NULL = never revoked. Every redemption path
-- (the atomic single-use UPDATEs and the `claim_code_valid` preflight) additionally requires
-- `revoked_at IS NULL`, so revocation closes redemption exactly like expiry does — and the
-- row survives as the audit record of the kill.
--
-- Deliberately an in-place ALTER, not a table rebuild: `pending_accounts.claim_code` (V005)
-- carries a `REFERENCES claim_codes (code)` FK, and with foreign-key enforcement always on,
-- a DROP/rename rebuild fails on any database holding outstanding pending-account rows
-- (V038 documents why neither `PRAGMA foreign_keys` nor `defer_foreign_keys` can bridge a
-- parent drop inside the migration transaction). The inventory endpoint therefore pages on
-- the immutable `(created_at, code)` keyset — NOT the implicit rowid, which VACUUM may
-- renumber under this TEXT-keyed table — served by the composite index below.

ALTER TABLE claim_codes ADD COLUMN revoked_at TEXT;

-- Serves the inventory's newest-first keyset pagination (ORDER BY created_at DESC, code DESC).
CREATE INDEX idx_claim_codes_created_at_code ON claim_codes (created_at, code);
