-- V057: Public interest-signup waitlist store (the `waitlist` capability).
--
-- One row per interested person, written by the public unauthenticated
-- `POST /waitlist` endpoint and read back by `GET /v1/admin/waitlist`. `email` is
-- stored normalized (trimmed, lowercased — `uniqueness::normalize_email`) and UNIQUE,
-- so a repeat signup is an idempotent no-op rather than a duplicate row; `handle` is
-- the optional self-reported atproto handle (syntactically validated, deliberately
-- not resolved — it is interest signal, not an authenticated identity claim).
-- Deliberately no foreign keys: signups predate any account, so the table stays off
-- the account-purge path entirely.
CREATE TABLE waitlist_signups (
    email      TEXT PRIMARY KEY,
    handle     TEXT,
    created_at TEXT NOT NULL
);
