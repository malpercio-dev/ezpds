# MM-649: How do target connectors register as OAuth clients?

Researched 2026-11-08 for the MM-647 wayfinder map. Research only; no product code changed.

## Verdict

Every target connector can identify itself to Custos with a Client ID Metadata Document (CIMD). Custos already advertises CIMD support and already resolves URL `client_id`s, so **no DCR (`registration_endpoint`) is needed**. Claude's published metadata documents pass Custos's client-resolution rules as written.

CIMD solves only identification. A connector then fails against Custos's authorization server on three other rules, none of which is about registration:

1. **PAR is mandatory at Custos; connectors do not use PAR.** `/oauth/authorize` refuses any request without a PAR `request_uri`.
2. **DPoP is mandatory at the token endpoint**; Claude's documented token handling is plain bearer, and the MCP spec requires `Authorization: Bearer`.
3. **Loopback redirect URIs are matched exactly**, so Claude Code (ephemeral port) fails the redirect check.

So the registration question resolves cleanly, but a connector cannot talk to Custos's authorization server directly. The handshake has to terminate at something that is not PAR/DPoP-only (the sidecar acting as the connector-facing authorization server is the obvious candidate). That is a map-level decision, not mine to make here.

## Verified facts

### MCP spec (draft revision, the one the docs site serves as current)

Sources: https://modelcontextprotocol.io/specification/draft/basic/authorization and https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration

- Clients must obtain a client ID through one of: CIMD, pre-registration, or DCR.
- Preferred order for clients supporting all: (1) pre-registered info, (2) CIMD if the AS advertises `client_id_metadata_document_supported`, (3) DCR if the AS has a `registration_endpoint`, (4) prompt the user.
- "Authorization servers and MCP clients SHOULD support OAuth Client ID Metadata Documents." DCR is "MAY" and is marked **deprecated**, retained for backwards compatibility.
- CIMD client rules: `client_id` is an https URL with a path; the document must include `client_id`, `client_name`, `redirect_uris`; `client_id` must match the document URL exactly.
- AS rules: must validate the document's `client_id` equals the URL, and validate the presented `redirect_uri` against `redirect_uris`.
- The spec's example document: `grant_types: ["authorization_code"]`, `response_types: ["code"]`, `token_endpoint_auth_method: "none"`, loopback `redirect_uris`. No `scope`, no `dpop_bound_access_tokens`, no `application_type`.
- The spec's flow has no PAR and no DPoP. Token usage is `Authorization: Bearer <token>`. It also requires the RFC 8707 `resource` parameter in authorization and token requests, and PKCE.
- CIMD arrived in the 2025-11-25 revision (Anthropic links that revision for CIMD: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-id-metadata-documents).

### TypeScript SDK client

Source: https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/main/packages/client/src/client/auth.ts (`authInternal`, `registerClient`). Line numbers not recorded; functions named instead. The source is `.ts`, not `client/auth.js`.

- `authInternal` tries CIMD before DCR, but only when there is no stored client info and both hold: the AS metadata sets `client_id_metadata_document_supported === true` and `provider.clientMetadataUrl` is configured. The URL must be https with a non-root path or it throws `InvalidClientMetadata`.
- Otherwise it falls through to `registerClient` (DCR). It throws if the provider cannot save client info. There is no fallback from a failed CIMD path to DCR.
- The DCR body is the provider's `clientMetadata` plus `scope`; `resolveClientMetadata` adds `grant_types` (default `authorization_code`, `refresh_token`) and `application_type` (`native` for loopback/custom-scheme redirects, else `web`). `registerClient` does not add `token_endpoint_auth_method` itself.
- No PAR: `startAuthorization` builds the authorization URL directly from query parameters; `pushed_authorization_request_endpoint` does not appear.
- DPoP: the SDK has provider-supplied DPoP plumbing (`OAuthClientProvider.dpop?()`, `executeTokenRequest` signs a proof and retries on `use_dpop_nonce`). It is opt-in per provider; the stock flow does not do it. From the excerpt I could not confirm whether the authorization-code exchange passes `dpop` (the visible `fetchToken` call does not). **Unverified**; treat the SDK as bearer-by-default.

### Claude.ai, Claude Desktop, Claude mobile, Cowork, Claude Code

Sources: https://claude.com/docs/connectors/building/authentication.md, https://claude.com/docs/connectors/building/lazy-authentication.md, https://claude.com/docs/connectors/custom/add-unlisted.md (custom connector dialog).

- Anthropic: "The same authentication infrastructure backs claude.ai, Claude Desktop, Claude mobile, Claude Code, and Cowork." Supported types include `oauth_dcr` and `oauth_cimd`, both "supported by default".
- Custom connector dialog, "OAuth client": "Use Claude's published identity" (recommended; a CIMD Anthropic hosts), "Register automatically" (DCR), or "Use your own OAuth client" (client ID, optional secret).
- Claude uses CIMD "normally" only when AS metadata advertises both `client_id_metadata_document_supported: true` and `"none"` in `token_endpoint_auth_methods_supported`; otherwise it falls back to DCR. Claude's CIMD client is a public client.
- If the AS lists `private_key_jwt`, Claude can instead present a second document whose URL ends in `/confidential_client` and sign a client assertion (always on Enterprise Managed Auth exchanges; "only for some servers" otherwise).
- Hosted apps (web, Desktop, mobile, Cowork) redirect to exactly `https://claude.ai/api/mcp/auth_callback`. Claude Code uses an RFC 8252 loopback redirect on an ephemeral port and declares `http://localhost/callback` and `http://127.0.0.1/callback` in its CIMD; Anthropic asks servers to match them with the port ignored.
- Claude always sends PKCE S256. Claude appends `offline_access` only if AS `scopes_supported` lists it. Scope comes from the `WWW-Authenticate` `scope`, else the protected resource metadata `scopes_supported`.
- Claude uses only the first `authorization_servers` entry, requires a 401 (not a 200) to start sign-in, and gives discovery/registration/token endpoints 10 s (30 s for refresh).
- The token endpoint must accept `application/x-www-form-urlencoded`; refresh tokens for public clients should rotate and return `invalid_grant` when dead. Nothing on these pages mentions PAR or DPoP.

The two documents Claude actually serves, fetched live with curl on 2026-11-08:

`https://claude.ai/oauth/mcp-oauth-client-metadata` (hosted apps):

```json
{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

`https://claude.ai/oauth/claude-code-client-metadata` (Claude Code; this URL is linked from Anthropic's docs):

```json
{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

Caveat: I did not find the hosted-apps document URL in Anthropic's docs. I found it by fetching a guessed path next to the documented Claude Code one. It returned a well-formed document that names itself, but Anthropic does not document it as the stable `client_id`, so confirm it (for example by watching a real connector's PAR or authorize request) before pinning it.

Neither document carries `scope`, `dpop_bound_access_tokens`, or `application_type`.

### Custos

Custos already advertises CIMD and public-client auth: `crates/custos-oauth/src/routes/oauth_server_metadata.rs:136` (`client_id_metadata_document_supported: true`), `:121` (`"none"` in `token_endpoint_auth_methods_supported`), `:131` (`require_pushed_authorization_requests: true`). There is no `registration_endpoint` anywhere in `crates/`. `offline_access` is not a Custos scope, so Claude will not append it.

Rule-by-rule against the two Claude documents (`crates/custos-core/src/auth/oauth_client_resolution.rs` unless noted):

| Rule | Where | Hosted-apps doc | Claude Code doc |
| --- | --- | --- | --- |
| https URL, no userinfo/fragment, public host | `validate_client_id_url` :141-167 | pass | pass |
| fetched doc's `client_id` equals the URL | `validate_metadata_document` :192-200, called :424 | pass | pass |
| `atproto` scope required in the document | not checked for fetched docs; only the synthesized loopback client enforces it (:335-338) | no rule | no rule |
| `dpop_bound_access_tokens` in the document | never read; the stored `ClientMetadata` has only `redirect_uris`, `client_name`, `token_endpoint_auth_method`, `jwks`, `jwks_uri` (`crates/custos-db/src/oauth.rs:31-43`) | no rule | no rule |
| `token_endpoint_auth_method: none` | supported (`oauth_server_metadata.rs:121`) | pass | pass |
| private-use redirect must be reverse FQDN | `validate_private_use_redirect` :217-244; http(s) redirects return early | pass (https) | pass (http) |
| `redirect_uri` must be listed | `oauth_par.rs:241`, `oauth_authorize.rs:375`: exact `Vec::contains` | pass | **fail** (see item 4 below) |

The ticket's premise needs a correction: the required-`atproto`-scope and DPoP-assumption rules in `oauth_client_resolution.rs` apply to the synthesized loopback client only. A fetched CIMD is accepted on `client_id` match alone.

## What a connector trips (rules that are not about registration)

1. **Required `atproto` scope on the PAR request.** `normalize_scope_request` (`crates/custos-core/src/auth/oauth_scopes.rs:108-129`) returns `invalid_scope` unless the requested scope includes `atproto`; `oauth_par.rs:182-189` calls it, defaulting an absent scope to `atproto`. A connector's scope comes from the resource server's `WWW-Authenticate scope` or `scopes_supported`, so the sidecar can make this pass by advertising `atproto`. Inference: if the sidecar advertises no scope at all, Claude omits `scope` and the PAR default of `atproto` applies. That path needs a live test.
2. **PAR is mandatory.** `crates/custos-oauth/src/routes/oauth_authorize.rs:203-209` rejects any authorize request without a PAR `request_uri` ("this server is PAR-only"). The MCP spec flow, the TS SDK's `startAuthorization`, and Anthropic's docs all send a plain authorization request. Hard blocker for a direct connector-to-Custos handshake. It is not a registration issue: CIMD resolves fine, and the failure only appears at `/oauth/authorize`.
3. **DPoP is mandatory at the token endpoint.** `crates/custos-oauth/src/routes/oauth_token/authorization_code.rs:92` calls `token_endpoint_dpop`, and the response `token_type` is `"DPoP"` (:224). The MCP spec requires `Authorization: Bearer`, and Anthropic documents ordinary bearer and refresh behaviour. This is the subject of the map (MM-647), not a registration matter.
4. **Exact-match redirect URIs break Claude Code.** Claude Code sends `http://localhost:<port>/callback`; its document lists `http://localhost/callback`. `oauth_par.rs:241` and `oauth_authorize.rs:375` compare exactly, so the request fails with a redirect_uri mismatch. Anthropic asks for port-agnostic loopback matching (lazy-authentication page, "Match loopback redirect URIs without the port"). The hosted apps (fixed https callback) are unaffected.
5. **`resource` parameter.** Connectors always send RFC 8707 `resource`. `oauth_par.rs` has no field for it; whether serde drops it silently (likely) or something rejects it was not tested. **Unverified.**

DCR-only connectors: none of the targets are DCR-only. Claude supports CIMD by default, and the TS SDK supports CIMD when the integrator sets `clientMetadataUrl`. A third-party SDK client that does not set `clientMetadataUrl` would fall to DCR and fail at Custos (no `registration_endpoint`). The spec marks DCR deprecated, so this is a shrinking case.

## Inference and open items

- Inference: if the sidecar is the connector-facing authorization server, Custos never sees a connector `client_id` at all, and items 2-4 move to the sidecar. In that design the sidecar needs `client_id_metadata_document_supported: true`, `"none"` in `token_endpoint_auth_methods_supported`, and its own CIMD fetch with the same SSRF hardening Custos uses. Not evaluated here.
- Unverified: whether Claude actually selects CIMD against Custos today. Both gating values are advertised, so per Anthropic's description it should; a live custom-connector test would confirm.
- Unverified: whether the TS SDK signs DPoP on the authorization-code exchange.
- Unverified: the stability of `https://claude.ai/oauth/mcp-oauth-client-metadata` as a documented `client_id`.
