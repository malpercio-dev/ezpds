-- The connector resource a refresh-token family was issued for (ADR-0042); NULL for a family
-- issued for this server. It is the access token's audience on every rotation, and it is what
-- tells a deliberately unbound connector family (NULL `jkt`, resource set) from a refresh token
-- that predates DPoP binding (NULL `jkt`, no resource), which stays refused.
ALTER TABLE oauth_tokens ADD COLUMN resource TEXT;
