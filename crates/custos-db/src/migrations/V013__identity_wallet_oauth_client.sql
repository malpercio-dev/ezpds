-- Seed the identity-wallet as a registered OAuth client.
--
-- client_metadata is a RFC 7591 JSON object. The PAR handler parses
-- metadata["redirect_uris"] to validate the redirect_uri parameter.
-- INSERT OR IGNORE makes this migration idempotent on re-run.
INSERT OR IGNORE INTO oauth_clients (client_id, client_metadata, created_at)
VALUES (
    'dev.malpercio.identitywallet',
    json('{
        "client_id": "dev.malpercio.identitywallet",
        "application_type": "native",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "redirect_uris": ["dev.malpercio.identitywallet:/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "atproto",
        "client_name": "Malpercio Identity Wallet"
    }'),
    datetime('now')
);
