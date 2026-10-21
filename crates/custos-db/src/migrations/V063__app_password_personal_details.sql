-- The opt-in personal-details grant on an app password (ADR-0033): 1 lets sessions opened
-- with this credential read and write the full-access-only preference types (e.g.
-- personalDetailsPref's birth date). Chosen at mint time, immutable thereafter, like
-- `privileged`. Existing rows default to 0 — the reference-parity behavior.
ALTER TABLE app_passwords ADD COLUMN personal_details INTEGER NOT NULL DEFAULT 0;
