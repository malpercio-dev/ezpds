-- Per-registration ping-mode preference for the notification relay: 1 = the device asked
-- for content-free `content-available` background pushes (the relay sees only "something
-- happened" — no sealed envelope at all), 0 = the default HPKE-sealed alert push.
-- A plain flag rather than a derived timestamp: this is a two-state preference the register
-- routes overwrite wholesale on every re-registration, with no lifecycle to derive.
ALTER TABLE notification_registrations ADD COLUMN ping INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_notification_registrations ADD COLUMN ping INTEGER NOT NULL DEFAULT 0;
