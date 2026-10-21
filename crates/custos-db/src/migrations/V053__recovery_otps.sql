-- V053: Email OTP store for the escrow-assisted recovery release flow.
--
-- `recovery_otps` is the standard SHA-256-hashed, 1-hour, single-use email token
-- envelope (the same shape as `password_reset_tokens` V014 / `plc_operation_tokens`
-- V033 / `account_deletion_tokens` V034 / `email_tokens` V036), minted by
-- `POST /v1/recovery/initiate` and consumed by the opening `POST /v1/recovery/release`
-- call. Only the token's hash is ever stored; `used_at` NULL = unspent. A dedicated
-- table (rather than a new `purpose` on an existing one) keeps the recovery credential
-- from ever being redeemable in another flow.
CREATE TABLE recovery_otps (
    token_hash TEXT PRIMARY KEY,
    did        TEXT NOT NULL REFERENCES accounts (did),
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_recovery_otps_did ON recovery_otps (did);
