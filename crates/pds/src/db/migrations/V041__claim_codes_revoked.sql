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

ALTER TABLE claim_codes ADD COLUMN revoked_at TEXT;
