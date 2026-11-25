-- V081: notification registrations move into `authorizeSpaceSync`.
-- Applied in a single transaction by the migration runner.
--
-- A syncer now registers a base URL and an opaque token alongside each credential it asks for,
-- instead of a service DID through `registerNotify`. The endpoint and token together identify a
-- registration, so one syncer may hold several. A registration expires with the credential it
-- was made with (`expires_at`), and `expiry_notified` records that its lapse has been claimed
-- for the one `registrationExpired` notice it is owed.
--
-- The token is stored in plain text: the space host presents it in every notice it sends, so it
-- can't be hashed. It is never logged and never returned.
--
-- The old rows name a DID, not an endpoint and token, so nothing converts. Their syncers register
-- again on their next `authorizeSpaceSync`.
DROP TABLE space_notify_registrations;

CREATE TABLE space_notify_registrations (
    space_uri       TEXT NOT NULL REFERENCES spaces (uri),
    endpoint        TEXT NOT NULL,
    token           TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    expiry_notified INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (space_uri, endpoint, token)
) WITHOUT ROWID;
