-- Seed the identity wallet's canonical OAuth client.
--
-- The wallet's client_id is the canonical metadata URL on the production host:
-- the atproto OAuth spec requires a native client's private-use redirect scheme
-- to be the client_id host's FQDN in reverse order, so the
-- 'org.obsign.identitywallet:' callback scheme pins the client_id host to
-- identitywallet.obsign.org (served by the production *.obsign.org wildcard).
-- Seeding the row lets every Custos instance accept the wallet without an
-- outbound fetch of the canonical document (offline dev instances, staging).
-- The upsert also corrects any previously cached copy of this document.
--
-- The V013 row (client_id 'dev.malpercio.identitywallet', old scheme) is
-- deliberately kept: wallet builds shipped before the scheme change still
-- present it during the transition window.
INSERT INTO oauth_clients (client_id, client_metadata, created_at)
VALUES (
    'https://identitywallet.obsign.org/oauth/client-metadata.json',
    json('{
        "client_id": "https://identitywallet.obsign.org/oauth/client-metadata.json",
        "client_name": "Obsign Identity Wallet",
        "client_uri": "https://identitywallet.obsign.org",
        "application_type": "native",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "redirect_uris": ["org.obsign.identitywallet:/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "atproto transition:generic"
    }'),
    datetime('now')
)
ON CONFLICT (client_id) DO UPDATE SET client_metadata = excluded.client_metadata;
