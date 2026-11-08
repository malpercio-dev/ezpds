# MM-651: what `resource` do MCP connectors send, and where must protected-resource metadata live?

Researched 2026-11-08 for the MM-647 map. Research only; no product code changed.

## Answer

- **The string Custos must accept is the canonical URL of the MCP endpoint**, `https://mcp.obsign.org/mcp` (the sidecar origin plus `config.mcpPath`), compared after normalisation.
- **Normalisation rule:** parse as a URL; lowercase scheme and host; drop the default port, the fragment, and a trailing slash (a bare-origin path `/` becomes empty); keep the path and query otherwise; compare the result exactly against an allowlist.
- **Today's sidecar metadata does not produce that string.** It advertises the bare origin, so the official SDK sends `resource=https%3A%2F%2Fmcp.obsign.org%2F` (trailing slash added by `new URL(...).href`), while Claude's documented behaviour is to send the MCP URL including its path. Custos would see two different strings depending on the client.
- **The sidecar metadata should change:** `resource` should be `<origin><mcpPath>`, served at the path-suffixed well-known `/.well-known/oauth-protected-resource/mcp` (keep the root path as an alias returning the same document), and an unauthenticated MCP request should get a `401` with `WWW-Authenticate: Bearer resource_metadata="..."`.

## Verified facts

### MCP SDK 1.29.0 (installed in `tools/mcp-sidecar/node_modules/@modelcontextprotocol/sdk`)

Paths below are relative to `dist/esm/`.

1. `selectResourceURL` (`client/auth.js:328-343`) starts from the server URL the user configured, strips the fragment (`resourceUrlFromServerUrl`, `shared/auth-utils.js:8-12`), and, when protected-resource metadata is present, validates it with `checkResourceAllowed`, then returns **`new URL(resourceMetadata.resource)`**, the metadata value, not the server URL. With no metadata it returns `undefined` and sends no `resource` at all (`client/auth.js:335-337`).
2. `checkResourceAllowed` (`shared/auth-utils.js:24-46`) requires the same origin and that the *requested* (server) path starts with the *configured* (metadata) path, compared on segment boundaries. So metadata `https://mcp.obsign.org` is accepted for a server URL `https://mcp.obsign.org/mcp`, and metadata `https://mcp.obsign.org/mcp` is accepted too. It does not require equality, and RFC 9728 section 3.3's "identical" check is not implemented in this version.
3. The `resource` is serialised with `resource.href` on all three requests: authorization (`startAuthorization`, `client/auth.js:725-726`), token exchange (`executeTokenRequest`, `client/auth.js:759-761`), and refresh. Refresh goes through the same `authInternal` and passes the same `resource` into `refreshAuthorization` (`client/auth.js:815-826`, called at `client/auth.js:~281`).
4. **Trailing slash.** `URL.href` of a bare origin always ends in `/`. Run against the installed SDK:

   | server URL | metadata `resource` | sent `resource` |
   |---|---|---|
   | `https://mcp.obsign.org/mcp` | `https://mcp.obsign.org` | `https://mcp.obsign.org/` |
   | `https://mcp.obsign.org/mcp` | `https://mcp.obsign.org/mcp` | `https://mcp.obsign.org/mcp` |
   | `https://mcp.obsign.org/mcp/` | `https://mcp.obsign.org/mcp` | `https://mcp.obsign.org/mcp` |
   | `https://mcp.obsign.org/mcp` | `https://mcp.obsign.org/` | `https://mcp.obsign.org/` |

   A path-bearing metadata value is sent verbatim; only a bare origin gains a slash. The metadata value is always what is sent, so the sidecar controls the string for SDK clients.
5. **Discovery** (`discoverMetadataWithFallback`, `client/auth.js:~490-512`; `buildWellKnownPath`, `client/auth.js:~463-470`): unless a `resource_metadata` URL came from `WWW-Authenticate`, the SDK requests `/.well-known/oauth-protected-resource<pathname>` first (for `/mcp`: `/.well-known/oauth-protected-resource/mcp`), and on a 4xx or network failure falls back to the root `/.well-known/oauth-protected-resource` (`shouldAttemptFallback`). The `resource_metadata` hint is read from the `WWW-Authenticate` header (`extractWWWAuthenticateParams`, `client/auth.js:~346-370`).
6. The metadata schema only requires `resource` to be a URL string (`shared/auth.js:25`).

### MCP specification, revision 2025-11-25 (https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

- Servers must support one of: the `resource_metadata` parameter on a `401` `WWW-Authenticate`, or a well-known URI either path-suffixed (`https://example.com/.well-known/oauth-protected-resource/public/mcp` for `https://example.com/public/mcp`) or at the root. Clients must support both and "fall back to constructing and requesting the well-known URIs in the order listed above" (path-suffixed first, then root) when no header hint exists. See "Protected Resource Metadata Discovery Requirements".
- "Resource Parameter Implementation": the `resource` parameter must be on both authorization and token requests, must identify the MCP server, and must be the canonical URI per RFC 8707. Clients should send "the most specific URI that they can". Valid examples include `https://mcp.example.com/mcp` and `https://mcp.example.com`; the note says implementations should consistently use the form **without** a trailing slash.
- Servers must validate that tokens were issued for them as audience (RFC 8707 section 2) and reject others.

### RFC 9728 (https://www.rfc-editor.org/rfc/rfc9728.html)

- Section 3.1: the well-known string is inserted between host and path; for `https://resource.example.com/resource1` the request is `GET /.well-known/oauth-protected-resource/resource1`.
- Section 3.3: the returned `resource` "MUST be identical to the protected resource's resource identifier value" (the one used to build the well-known URL); a client that finds a mismatch must not use the response. Stricter clients than SDK 1.29.0 may enforce this, and a bare-origin `resource` served for an MCP URL with a path is the mismatch case.

### Claude connectors (Anthropic documentation)

- https://claude.com/docs/connectors/building/authentication.md, "Serve discovery metadata": "the document's `resource` field must equal the URL as the user enters it in Claude, including any path component"; a `401` with a `WWW-Authenticate` `resource_metadata` pointer is required to start sign-in, and Claude ignores `WWW-Authenticate` on a `200`; without the pointer Claude probes `/.well-known/oauth-protected-resource/<mcp-path>` then `/.well-known/oauth-protected-resource`; only the first `authorization_servers` entry is used. Hosted Claude apps (claude.ai, Desktop, mobile, Cowork) share one callback, `https://claude.ai/api/mcp/auth_callback`, and the same auth infrastructure; Claude Code is a separate client with its own loopback redirect.
- https://claude.com/docs/connectors/building/troubleshooting.md, "Audience mismatch": Claude sends `resource` "set to the canonical form of your MCP server URL, including any path component. The canonical form has a lowercase scheme and host, no trailing slash, no fragment, and no default port", and tells servers to "accept the canonical value when checking `aud` rather than doing a strict byte-for-byte comparison against what the user typed". The Entra section confirms Claude "sets `resource` to your MCP server URL, including the path".
- Claude refreshes reactively on `401` and up to five minutes before expiry; the form-encoded token endpoint and `invalid_grant` requirements are in "Token refresh" on the authentication page.

### The sidecar today (`tools/mcp-sidecar/src/server.ts`)

- `GET /.well-known/oauth-protected-resource` (root only, exact match, line ~216) returns `resource: config.publicOrigin` (line ~229). The path-suffixed URL falls through to the `404` at line ~240.
- A grep for `401` and `WWW-Authenticate` in `tools/mcp-sidecar/src` finds nothing: an unauthenticated request to the MCP path is not answered with a `401` challenge by the sidecar.

## Inference (not directly verified)

- I did not run Claude.ai or Claude Desktop against a server. Anthropic's pages say they send the canonical MCP URL with its path, and that statement is the only evidence; the SDK behaviour above is code I executed. If the sidecar keeps advertising a bare origin, Claude's doc says the metadata `resource` must equal the entered URL, so the connector would likely fail or send a value Custos does not expect. This is the reading of the docs, not an observed failure.
- Claude likely uses its own OAuth implementation rather than this SDK, so the SDK trailing-slash result applies to SDK-based clients (Claude Code is documented as a separate client; other third-party MCP clients typically embed the SDK). Treat both forms as possible inputs.
- A 401 that lacks `resource_metadata` still works for clients that probe, but Claude's docs call the probe a fallback that works only when the platform serves `/.well-known/*`. Railway does route it, so this is a hardening item, not a blocker; however the missing `401` challenge entirely is a probable blocker for Claude, since sign-in starts from a `401`.

## Recommendations

1. **Custos token/authorize endpoints:** accept `resource` values whose normalisation (rule above) equals `https://mcp.obsign.org/mcp` (derive it from configuration, not a literal). Reject any other `resource`. During any transition where the sidecar still advertises the bare origin, also accept the normalised origin form, which covers both `https://mcp.obsign.org` and the SDK's `https://mcp.obsign.org/`; drop it once the sidecar change ships. Echo the normalised value as the token's audience.
2. **Sidecar metadata:** set `resource` to `${publicOrigin}${mcpPath}`; serve it at `/.well-known/oauth-protected-resource${mcpPath}`, and keep the root path returning the identical document (so the SDK fallback and root-only probers still work). RFC 9728 section 3.3 then holds for the path-suffixed URL.
3. **Sidecar 401:** answer a missing or unusable bearer with `401` and `WWW-Authenticate: Bearer resource_metadata="https://mcp.obsign.org/.well-known/oauth-protected-resource/mcp"` (consider adding `scope`). That is a separate piece of work from the metadata change and should be a ticket on the map.
4. **Do not rely on exact string equality of what the user typed.** Both Anthropic and the spec point to normalised comparison.
