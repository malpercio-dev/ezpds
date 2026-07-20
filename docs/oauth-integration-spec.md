# ATProto OAuth Integration Spec

PDS OAuth Provider

v0.1 Draft — March 2026

Companion to: Provisioning API Spec, Mobile Architecture Spec

---

> **Status (verified 2026-07-20): superseded pre-build planning draft — read §§5–5.1 as trued-up, treat the crate-integration plan as the road not taken.**
>
> This document was written before the OAuth server was built, and its central
> thesis — that the PDS would *integrate an existing Rust OAuth crate rather than
> build OAuth from scratch* (§1.1, §2, §3.1, §8, §10) — describes a path that was
> **not** taken. The shipped PDS implements the ATProto OAuth authorization server
> **entirely by hand** in `crates/pds/src/routes/oauth_*` (authorize/PAR/token/
> revoke/jwks/metadata/client-metadata) and `crates/pds/src/auth/` (DPoP, client
> resolution, scopes, JWT). `atproto-oauth-axum`, `atproto-oauth-aip`, and
> graze-social/aip are **not** dependencies (check `Cargo.toml`); §§2–3, 8, and 10
> are retained only as provenance for that early evaluation.
>
> The living, endpoint-by-endpoint source of truth is the `routes/` table in
> [`crates/pds/AGENTS.md`](../crates/pds/AGENTS.md) (the `oauth_*` rows) and the
> code itself. §5 (endpoints) and §5.1 (server metadata) below have been trued-up
> to the shipped server; the rest of this doc is un-updated planning-era text.

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

The PDS serves these endpoints at its base URL (the DID document's service
endpoint). Every one is a hand-written handler (see the source column, all under
`crates/pds/src/routes/`), registered in `crates/pds/src/app.rs`:

| Endpoint | Handler | Purpose |
|----------|---------|---------|
| `GET /.well-known/oauth-authorization-server` | `oauth_server_metadata.rs` | AS metadata (RFC 8414 + ATProto extensions) |
| `GET /.well-known/oauth-protected-resource` | `oauth_protected_resource.rs` | Protected-resource metadata (RFC 9728); ezpds is both AS and resource server |
| `GET/POST /oauth/authorize` | `oauth_authorize.rs` | Authorization endpoint (user-facing consent) |
| `GET /oauth/authorize/consent-request`, `GET /oauth/authorize/status`, `POST /oauth/authorize/approve`, `POST /oauth/authorize/complete` | `oauth_authorize.rs` + wallet-confirmed-consent handlers | Consent-page data + the wallet-confirmed (passwordless) approval sub-flow |
| `POST /oauth/par` | `oauth_par.rs` | Pushed Authorization Request endpoint (mandatory) |
| `POST /oauth/token` | `oauth_token/` (per-grant submodules) | Token endpoint (authorization_code, refresh_token, jwt-bearer, claim) |
| `POST /oauth/revoke` | `oauth_revoke.rs` | Token revocation (RFC 7009) |
| `GET /oauth/jwks` | `oauth_jwks.rs` | Public keys for token verification |
| `GET /oauth/client-metadata.json` | `oauth_client_metadata.rs` | The identity wallet's own client-metadata document |

There is **no** PDS-served `/oauth/callback` — the `…/oauth/callback` string in
the seeded client rows is the *native app's* private-use redirect URI (e.g.
`org.obsign.identitywallet:/oauth/callback`), which the OS routes back to the
wallet, not an endpoint on the PDS.

These are in addition to the PDS's existing endpoints:
- `/v1/*` — provisioning API
- `/xrpc/*` — ATProto XRPC (access tokens minted here are validated per-request against DPoP)

### 5.1 Server Metadata

The `/.well-known/oauth-authorization-server` response (built by
`oauth_server_metadata.rs`) is shaped to pass the ATProto OAuth metadata
validator, which is stricter than plain RFC 8414. Several fields are **required
by that validator**, not optional — omitting them breaks client discovery:

```json
{
  "issuer": "https://PDS.example.com",
  "authorization_endpoint": "https://PDS.example.com/oauth/authorize",
  "token_endpoint": "https://PDS.example.com/oauth/token",
  "revocation_endpoint": "https://PDS.example.com/oauth/revoke",
  "pushed_authorization_request_endpoint": "https://PDS.example.com/oauth/par",
  "jwks_uri": "https://PDS.example.com/oauth/jwks",
  "scopes_supported": [
    "atproto",
    "transition:email",
    "transition:generic",
    "transition:chat.bsky",
    "repo:*",
    "rpc:*",
    "blob:*/*",
    "account:*",
    "identity:*",
    "include:*"
  ],
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:workos:agent-auth:grant-type:claim"
  ],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
  "revocation_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["ES256"],
  "require_pushed_authorization_requests": true,
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "agent_auth": {
    "skill": "https://PDS.example.com/auth.md",
    "identity_endpoint": "https://PDS.example.com/agent/identity",
    "claim_endpoint": "https://PDS.example.com/agent/identity/claim",
    "events_endpoint": "https://PDS.example.com/agent/event/notify",
    "identity_types_supported": ["anonymous", "identity_assertion", "service_auth"],
    "identity_assertion": {
      "assertion_types_supported": ["urn:ietf:params:oauth:token-type:id-jag"]
    },
    "events_supported": [
      "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
    ]
  }
}
```

This is the complete top-level response shape `oauth_server_metadata.rs` emits
(field for field); the only per-instance variation is the base URL substituted
into the endpoint/`agent_auth` URLs. Notes on the fields the March draft omitted:
- `token_endpoint_auth_signing_alg_values_supported: ["ES256"]` — required whenever
  `private_key_jwt` is advertised; the validator rejects a server that advertises
  `private_key_jwt` without an alg list including `ES256`.
- `require_pushed_authorization_requests`, `authorization_response_iss_parameter_supported`
  (the RFC 9207 `iss` the authorize endpoint returns), and
  `client_id_metadata_document_supported` (clients are identified by a
  metadata-document URL, not pre-registration) must all be `true`.
- The two extra `grant_types_supported` entries are the auth.md agent grants
  (`jwt-bearer` service-assertion exchange and the machine-pollable `claim`
  grant); see the `oauth_token/` and `agent_*` route docs.
- `scopes_supported` is `auth/oauth_scopes::supported_scopes()`: the four
  fixed/transition scopes **plus** a six-entry resource-prefix *summary*
  (`repo:*`, `rpc:*`, `blob:*/*`, `account:*`, `identity:*`, `include:*`).
  Each prefix accepts further positional/query parameters per the granular
  atproto scope grammar, so the grantable space is unbounded — the metadata
  summarizes it by prefix rather than enumerating every concrete value.
- `agent_auth` is an ATProto/auth.md discovery extension (not RFC 8414); its
  endpoints back the agent-registration flow documented in the `agent_identity.rs`
  / `agent_claim.rs` / `agent_event.rs` route entries in `crates/pds/AGENTS.md`.

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

> **Historical.** These milestones are the original plan; they still name the
> `atproto-oauth-axum` integration that was never adopted. What actually shipped
> diverges: v0.1 delivered a hand-rolled server (validated live against the
> official Bluesky app), and several items filed here as "v1.0" or "Later" have
> already landed — token **revocation** (`/oauth/revoke`, RFC 7009), rate limiting
> on the OAuth endpoints (`rate_limit.rs`), and granular **scoped tokens**
> (`auth/oauth_scopes.rs`). Storage stays SQLite by design (PostgreSQL was
> dropped, not deferred). Treat the list below as provenance, not a roadmap.

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
