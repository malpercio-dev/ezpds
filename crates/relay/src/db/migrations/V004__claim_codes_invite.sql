-- V004: Redesign claim_codes for invite-code use case
--
-- The Wave 1 schema (V002) required a NOT NULL DID FK to accounts, which prevents
-- generating invite codes before an account exists. This migration recreates the
-- table for operator-generated invite codes issued prior to account creation.
--
-- Status is derived rather than stored:
--   pending  : redeemed_at IS NULL AND expires_at > datetime('now')
--   redeemed : redeemed_at IS NOT NULL
--   expired  : redeemed_at IS NULL AND expires_at <= datetime('now')
--
-- Production data loss: none (table was empty at time of migration; v0.1 pre-launch).

ALTER TABLE claim_codes RENAME TO claim_codes_v1;

CREATE TABLE claim_codes (
    code        TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    redeemed_at TEXT,
    PRIMARY KEY (code)
);

-- Supports expiry sweeps and redemption validity checks.
CREATE INDEX idx_claim_codes_expires_at ON claim_codes (expires_at);

DROP TABLE claim_codes_v1;
