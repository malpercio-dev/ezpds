-- V005: Pre-provisioned (pending) accounts
-- Applied in a single transaction by the migration runner.
--
-- A pending account is an operator-created slot before the user claims it with a device.
-- It records the desired email, handle, and tier alongside the claim code that the device
-- must present to complete provisioning. The did is assigned only after device binding
-- (a future wave), at which point the row is promoted to the accounts table.
--
-- Status is implicit: every row in this table is "pending".
-- After device binding, the row is deleted and a full accounts row is created.

CREATE TABLE pending_accounts (
    id         TEXT NOT NULL,  -- UUID v4; returned as account_id
    email      TEXT NOT NULL,
    handle     TEXT NOT NULL,
    tier       TEXT NOT NULL,  -- free | pro | business
    claim_code TEXT NOT NULL REFERENCES claim_codes (code),
    created_at TEXT NOT NULL,
    PRIMARY KEY (id)
);

-- Uniqueness: an email or handle may not appear in both pending_accounts and accounts.
-- The accounts table already has idx_accounts_email; these cover the pending side.
CREATE UNIQUE INDEX idx_pending_accounts_email  ON pending_accounts (email);
CREATE UNIQUE INDEX idx_pending_accounts_handle ON pending_accounts (handle);
