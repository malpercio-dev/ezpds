-- V059: Carry the authorization request's response_mode through the wallet-consent flow.
--
-- The completion redirect (`POST /oauth/authorize/complete`) is rebuilt entirely from the
-- pending row, so the mode the client asked for at PAR time must ride along or the wallet
-- path always answers in the query string — invisible to a fragment-mode browser client
-- (the official @atproto/oauth-client-browser default). The default backfills every
-- pre-existing row as 'query', which is exactly how those requests were answered.
ALTER TABLE pending_oauth_authorizations
    ADD COLUMN response_mode TEXT NOT NULL DEFAULT 'query';
