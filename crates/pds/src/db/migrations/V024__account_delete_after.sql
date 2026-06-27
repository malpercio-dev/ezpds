-- V024: Scheduled-deletion timestamp for deactivateAccount
--
-- com.atproto.server.deactivateAccount accepts an optional `deleteAfter` datetime asking that
-- the account be permanently deleted after that instant. We record the requested instant here
-- so the intent is durable across restarts. `deactivated_at` (added in V008) already records
-- *that* an account is deactivated; this column records *when it asked to be deleted*, if at
-- all. The reaper that acts on this timestamp is a separate concern and is not yet implemented;
-- storing the value is the honest minimum. Cleared whenever the account is reactivated.

ALTER TABLE accounts ADD COLUMN delete_after TEXT;
