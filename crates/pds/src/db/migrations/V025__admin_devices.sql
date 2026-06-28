-- V025: Admin-device data model for the operator companion app.
--
-- Backs per-device signed-request admin authentication. Three tables:
--   admin_pairing_codes — single-use, short-TTL codes that bootstrap device enrollment
--   admin_devices       — registered device public keys (did:key) the relay verifies against
--   admin_nonces        — seen request nonces, for anti-replay
--
-- Status is derived rather than stored, matching claim_codes (V004) — there is no
-- risk of a stored status diverging from the underlying timestamp columns:
--   pairing code  pending  : consumed_at IS NULL AND expires_at > datetime('now')
--                 consumed : consumed_at IS NOT NULL
--                 expired  : consumed_at IS NULL AND expires_at <= datetime('now')
--   device        active   : revoked_at IS NULL
--                 revoked  : revoked_at IS NOT NULL

CREATE TABLE admin_pairing_codes (
    code        TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    consumed_at TEXT,
    PRIMARY KEY (code)
);

-- Supports expiry sweeps and pending-validity checks.
CREATE INDEX idx_admin_pairing_codes_expires_at ON admin_pairing_codes (expires_at);

CREATE TABLE admin_devices (
    id           TEXT NOT NULL,
    label        TEXT NOT NULL,
    public_key   TEXT NOT NULL,                  -- did:key:z…
    platform     TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'full',   -- growth hook: narrow device authority later
    created_at   TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at   TEXT,
    PRIMARY KEY (id)
);

CREATE TABLE admin_nonces (
    device_id TEXT NOT NULL,
    nonce     TEXT NOT NULL,
    seen_at   TEXT NOT NULL,
    -- Scoped per device: replay detection asks "has THIS device seen this nonce?",
    -- so two devices may independently use the same nonce value without collision.
    PRIMARY KEY (device_id, nonce),
    FOREIGN KEY (device_id) REFERENCES admin_devices (id)
);

-- Supports sweeping nonces older than the timestamp window.
CREATE INDEX idx_admin_nonces_seen_at ON admin_nonces (seen_at);
