-- V058: The Custos side of the blind-courier notification relay.
--
-- Three tables: the instance's own versioned sender keys, and one registration
-- table per app surface (wallet accounts, admin-companion devices).
--
-- `notification_sender_keys` holds the P-256 secret the instance seals with in
-- HPKE mode_auth. Devices pin the *public* half, so a rotation is a two-sided
-- ceremony rather than a swap: publish the new key alongside the old, seal with
-- the newest, and only retire the old once every device has re-pinned. Status is
-- derived from timestamps (the `claim_codes` doctrine):
--
--   retired_at NULL, revoked_at NULL -- active: published and used for sealing
--   retired_at set                   -- retired: still published so payloads
--                                       sealed before the rotation still verify,
--                                       never used to seal anything new
--   revoked_at set                   -- revoked: gone from the published set
--                                       immediately (the compromise path)
--
-- The secret is AES-256-GCM-wrapped under the master KEK exactly like
-- `iroh_identity` (V022), and joins `SecretFamily::ALL` so `rewrap-master-key`
-- covers it.
CREATE TABLE notification_sender_keys (
    kid                  INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_key_encrypted TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    retired_at           TEXT,
    revoked_at           TEXT
);

-- `notification_registrations` deliberately does NOT reference `devices`.
-- `devices` is a transient pre-DID artifact: its rows are deleted inside the
-- DID-promotion transaction (`routes/create_did.rs`) and it FKs to
-- `pending_accounts`. A registration anchored there would be destroyed exactly
-- when the account starts mattering. The key is instead (did, device_uuid),
-- where `device_uuid` is an app-generated stable identifier, and registration
-- happens post-promotion over the DPoP-authenticated channel.
--
-- `push_handle` is the relay's opaque per-device handle: NULL until the relay
-- registration round trip succeeds, so a relay that is down at registration time
-- leaves a row we can re-register later rather than losing the device key.
CREATE TABLE notification_registrations (
    did                     TEXT NOT NULL REFERENCES accounts (did),
    device_uuid             TEXT NOT NULL,
    notification_public_key TEXT NOT NULL,
    apns_token              TEXT NOT NULL,
    apns_topic              TEXT NOT NULL,
    push_handle             TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (did, device_uuid)
) WITHOUT ROWID;

-- The admin-companion analog. Keyed by the admin device itself, because an
-- operator device authenticates as a device (signed envelope), not as an
-- account; the row is cleaned up alongside the revoke tombstone.
CREATE TABLE admin_notification_registrations (
    admin_device_id         TEXT PRIMARY KEY REFERENCES admin_devices (id),
    notification_public_key TEXT NOT NULL,
    apns_token              TEXT NOT NULL,
    apns_topic              TEXT NOT NULL,
    push_handle             TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL
) WITHOUT ROWID;
