-- The permissioned-data spec dropped the repo host's auto-registration: a repo host now pushes
-- `notifyWrite` straight to the space authority's `#atproto_space_host` on every write, with no
-- subscription. Delete the per-repo rows that registration left behind; only whole-space rows
-- (`repo_did = ''`, written by `registerNotify` on a space host) remain. The column stays, since
-- it is part of the V065 primary key.
DELETE FROM space_notify_registrations WHERE repo_did != '';
