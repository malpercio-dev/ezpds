---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-005]
---

# OAuth 2.0 + DPoP

The authentication mechanism used by the [[entities/identity-wallet|Identity Wallet]] to authenticate with the [[entities/relay|Relay Server]]. Combines OAuth 2.0 Authorization Code flow with PKCE (RFC 7636) and DPoP-bound tokens (RFC 9449).

## Flow

1. **DPoP keygen**: Generate P-256 keypair, persist in Keychain as `oauth-dpop-key-priv`
2. **PKCE verifier**: Generate random verifier + S256 challenge
3. **PAR**: Push authorization request to relay (POST /oauth/par) with PKCE challenge + DPoP proof
4. **Safari redirect**: Open browser to `/oauth/authorize` with `request_uri`
5. **Deep-link callback**: `dev.malpercio.identitywallet:/oauth/callback?code=...&state=...`
6. **Token exchange**: POST /oauth/token with PKCE verifier + DPoP proof → access + refresh tokens
7. **Subsequent requests**: `Authorization: DPoP {access_token}` + DPoP proof header

## Key Properties

- **DPoP-bound tokens**: Tokens are bound to the DPoP keypair via `jkt` thumbprint. The relay verifies the DPoP proof on each request.
- **Transparent refresh**: `OAuthClient` checks token expiry before each request and refreshes if <60s remaining.
- **Nonce retry**: Retries once on `use_dpop_nonce` 400 responses (server requires a nonce the client didn't have yet).
- **Persistent DPoP key**: Same P-256 key reused across all app sessions. Changing it invalidates all DPoP-bound tokens.

## In ezpds

**Relay endpoints**:
- `GET /.well-known/oauth-authorization-server` — Metadata
- `GET/POST /oauth/authorize` — Authorization
- `POST /oauth/par` — Pushed Authorization Request
- `POST /oauth/token` — Token exchange
- `GET /oauth/jwks` — Public keys
- `GET /oauth/client-metadata.json` — Client metadata

**Identity Wallet modules**:
- `src-tauri/src/oauth.rs` — OAuth PKCE flow, DPoP keypair, deep-link handling
- `src-tauri/src/oauth_client.rs` — `OAuthClient` with transparent refresh and nonce retry

## Related

- [[concepts/pkce|PKCE]]
- [[concepts/did-key|did:key]]
- [[entities/relay|Relay Server]]
- [[entities/identity-wallet|Identity Wallet]]
- [[sources/SRC-2026-06-22-005]] — Identity Wallet architecture
