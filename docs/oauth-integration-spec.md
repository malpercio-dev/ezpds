# ATProto OAuth Integration Spec

PDS OAuth Provider

v0.1 Draft — March 2026

Companion to: Provisioning API Spec, Mobile Architecture Spec

---

## 1. Overview

The PDS must be a compliant ATProto OAuth 2.1 authorization server so that third-party apps (Bluesky, etc.) can authenticate users and create records via XRPC. This document specifies how the PDS integrates existing Rust OAuth libraries rather than building OAuth from scratch.

### 1.1 Why OAuth Matters

Without a compliant OAuth provider, no third-party app can authenticate against the PDS. A user who creates an identity through the mobile app or desktop PDS cannot log into Bluesky — the entire product is unusable. OAuth is on the critical path for every lifecycle phase.

### 1.2 ATProto OAuth Requirements

The ATProto OAuth spec requires PDS implementations to support:

- **OAuth 2.1** authorization code flow with PKCE (S256 only)
- **DPoP** (Demonstrating Proof-of-Possession) using ES256, with unique JTI per request and nonce support
- **PAR** (Pushed Authorization Requests) — mandatory for all client types
- **Dynamic Client Registration** (RFC 7591) — clients provide metadata URLs, not pre-registered credentials
- **Server metadata** at `/.well-known/oauth-authorization-server`
- **JWKS endpoint** for public key discovery
- Grant types: `authorization_code` and `refresh_token`
- Token endpoint auth: `none` and `private_key_jwt`
- Scopes: `atproto` and `transition:generic`
- CORS support for browser-based apps
- Refresh tokens are single-use (rotation on each use)
- Tokens bound to DPoP key and client_id

---

## 2. Existing Rust Ecosystem

### 2.1 Recommended: `atproto-oauth-axum`

**Crate:** [atproto-oauth-axum](https://crates.io/crates/atproto-oauth-axum) (v0.14.0, Feb 2026)
**Author:** Nick Gerakines
**Status:** Actively maintained, 22 releases since June 2025, ~440 downloads/month

Provides pre-built Axum handlers for:
- Authorization endpoint
- Token endpoint
- PAR endpoint
- JWKS endpoint
- Server metadata endpoint
- Client metadata resolution
- Authorization callback handling

This is the most direct integration path if the PDS uses Axum (which aligns with the Rust web server ecosystem).

### 2.2 Alternative: `atproto-oauth-aip`

**Crate:** [atproto-oauth-aip](https://crates.io/crates/atproto-oauth-aip)
**Status:** Same author, lower-level workflow library

Use this if the PDS uses a different HTTP framework (e.g., actix-web) or needs more control over the OAuth flow. Provides the OAuth logic without Axum-specific bindings.

### 2.3 Reference Implementation: graze-social/aip

**Repo:** [graze-social/aip](https://github.com/graze-social/aip) (105 stars, v2.2.3, Jan 2026)
**Status:** Production-ready, Docker support, multiple storage backends

A complete standalone OAuth 2.1 authorization server with native ATProto integration. Useful as:
- Reference for how a production ATProto OAuth server works
- Potential deployment as a separate sidecar service (vs. embedding in the PDS)
- Storage backend patterns (SQLite, PostgreSQL)

---

## 3. Integration Architecture

### 3.1 Deployment Model

Two viable approaches:

**Option A: Embedded (recommended for v1.0)**

The PDS process embeds `atproto-oauth-axum` handlers directly into its Axum router. OAuth state lives in the same database as PDS state. Simplest deployment — one process, one database.

```
[Third-party app] → HTTPS → [PDS: Axum router]
                                ├── /oauth/* → atproto-oauth-axum handlers
                                ├── /xrpc/*  → XRPC proxy/handler
                                └── /v1/*    → Provisioning API
```

**Option B: Sidecar**

Deploy graze-social/aip as a separate service. The PDS delegates OAuth to the sidecar and validates tokens on XRPC requests. More complex but isolates OAuth concerns.

Not recommended for v1.0 — adds operational complexity for a solo developer.

### 3.2 Storage

OAuth state (authorization codes, tokens, sessions, client metadata cache) stored in the PDS's SQLite database. Both `atproto-oauth-axum` and graze-social/aip support SQLite backends.

Tables needed:
- `oauth_authorization_codes` — short-lived, per-authorization-flow
- `oauth_access_tokens` — bound to DPoP key, client_id, account
- `oauth_refresh_tokens` — single-use, rotated on each use
- `oauth_client_metadata_cache` — cached client metadata from discovery URLs
- `oauth_dpop_nonces` — replay prevention

### 3.3 Account Binding

The OAuth provider needs to map ATProto DIDs to PDS accounts. During authorization:

1. User is redirected to PDS's authorization endpoint
2. PDS resolves the user's DID → account_id
3. User authenticates (password, or session token if already logged in)
4. PDS issues tokens bound to the account

The PDS's existing session/authentication system (provisioning API §2) handles step 3. The OAuth library handles everything else.

---

## 4. Lifecycle Phase Behavior

### 4.1 Mobile-Only Phase

The PDS is a full PDS. OAuth works identically to any hosted PDS:
- Authorization, token, and XRPC endpoints all on the PDS
- PDS stores repo, signs commits, serves reads
- Third-party apps see a normal PDS

No special behavior needed. This is the standard ATProto OAuth flow.

### 4.2 Desktop-Enrolled Phase

The PDS is still the OAuth provider and XRPC endpoint. The difference is internal:
- Write XRPC calls (createRecord, etc.) are proxied to the desktop for repo construction before the PDS signs them
- Read XRPC calls can be served from PDS cache
- OAuth tokens and sessions are managed entirely at the PDS — the desktop is invisible to third-party apps

No OAuth changes needed for desktop enrollment. This is the key advantage of the PDS-as-permanent-endpoint architecture.

### 4.3 Desktop Offline (During Desktop-Enrolled Phase)

- Read XRPC calls: served from PDS cache (no change to OAuth)
- Write XRPC calls: PDS returns 503 to the XRPC caller
- OAuth tokens remain valid — the 503 is at the XRPC layer, not the auth layer

Third-party apps see a PDS that accepts reads but rejects writes. This is a known ATProto pattern (PDS maintenance mode).

---

## 5. Endpoints

The PDS must serve these endpoints at its base URL (the DID document's service endpoint):

| Endpoint | Source | Purpose |
|----------|--------|---------|
| `/.well-known/oauth-authorization-server` | atproto-oauth-axum | Server metadata (issuer, endpoints, supported flows) |
| `/oauth/authorize` | atproto-oauth-axum | Authorization endpoint (user-facing) |
| `/oauth/token` | atproto-oauth-axum | Token endpoint (app-facing) |
| `/oauth/par` | atproto-oauth-axum | Pushed Authorization Request endpoint |
| `/oauth/jwks` | atproto-oauth-axum | Public keys for token verification |
| `/oauth/callback` | atproto-oauth-axum | Authorization callback |

These are in addition to the PDS's existing endpoints:
- `/v1/*` — provisioning API
- `/xrpc/*` — ATProto XRPC

### 5.1 Server Metadata

The `/.well-known/oauth-authorization-server` response must include:

```json
{
  "issuer": "https://PDS.example.com",
  "authorization_endpoint": "https://PDS.example.com/oauth/authorize",
  "token_endpoint": "https://PDS.example.com/oauth/token",
  "pushed_authorization_request_endpoint": "https://PDS.example.com/oauth/par",
  "jwks_uri": "https://PDS.example.com/oauth/jwks",
  "scopes_supported": ["atproto", "transition:generic"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["ES256"]
}
```

---

## 6. Authorization UI

The PDS needs a minimal web UI for the OAuth authorization screen. When a third-party app redirects a user to `/oauth/authorize`, the PDS must:

1. Show the app's name and permissions requested
2. Allow the user to approve or deny
3. Redirect back to the app with an authorization code

For v1.0, this can be a minimal server-rendered page. No SPA needed. The provisioning API's session system handles user authentication.

For BYO PDS operators, the authorization UI should be customizable (branding, colors) via PDS config.

---

## 7. Security Considerations

### 7.1 Token Storage

Access tokens and refresh tokens are stored server-side. The PDS validates DPoP proofs on every request, preventing token theft from being useful without the DPoP private key.

### 7.2 Client Metadata Caching

ATProto uses dynamic client registration — clients provide a metadata URL, not pre-registered credentials. The PDS must:
- Fetch and cache client metadata on first authorization
- Re-validate periodically (TTL: 24 hours recommended)
- Reject clients with unreachable or invalid metadata

### 7.3 Rate Limiting

OAuth endpoints should be rate-limited separately from XRPC and provisioning API endpoints. Recommended limits:
- Authorization: 10/min per IP
- Token: 30/min per client_id
- PAR: 30/min per client_id

### 7.4 BYO PDS Implications

Self-hosted PDS operators run their own OAuth provider. The BYO PDS binary (Nix/Docker) must include the OAuth endpoints. The authorization UI defaults should be sensible without configuration.

---

## 8. Implementation Milestones

### v0.1 — Basic OAuth (blocks mobile-only phase)

- Integrate `atproto-oauth-axum` into PDS's Axum router
- SQLite-backed token storage
- Minimal authorization UI (server-rendered)
- Server metadata endpoint
- Test with Bluesky app as client

### v1.0 — Production OAuth

- PostgreSQL storage backend option
- Client metadata caching with TTL
- Rate limiting on OAuth endpoints
- Customizable authorization UI for BYO PDS operators
- Token revocation endpoint
- Audit logging of authorization grants

### Later

- Scoped tokens (read-only grants for specific collections)
- Token introspection endpoint
- Admin dashboard for managing active OAuth sessions

---

## 9. Integration Checklist

Before the PDS can accept third-party app logins:

- [ ] `/.well-known/oauth-authorization-server` returns valid metadata
- [ ] `/oauth/authorize` renders authorization UI and handles consent
- [ ] `/oauth/token` issues DPoP-bound access + refresh tokens
- [ ] `/oauth/par` accepts pushed authorization requests
- [ ] `/oauth/jwks` returns current signing keys
- [ ] PKCE (S256) enforced on all flows
- [ ] DPoP proof validated on every token request
- [ ] Refresh token rotation (single-use) working
- [ ] Bluesky app can complete full OAuth flow
- [ ] Bluesky app can create a post via XRPC after OAuth
- [ ] Token bound to correct account/DID

---

## 10. Design Decisions

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| Embed `atproto-oauth-axum` in PDS process | Simplest deployment for solo dev. One process, one DB. | Sidecar (graze-social/aip) — more complex ops. |
| SQLite for OAuth storage in v1.0 | Matches PDS's existing storage. No additional infra. | PostgreSQL from day one — overkill for early users. |
| Minimal server-rendered auth UI | OAuth authorization screen is visited rarely. No SPA needed. | Full React SPA — unnecessary complexity. |
| Use existing crates, don't build OAuth | ATProto OAuth is complex (DPoP, PAR, PKCE, dynamic registration). Building from scratch is months of work. | Build custom — slower, more bugs, no community fixes. |
