# Do target MCP connectors support DPoP, or plan to? (MM-648)

Researched 2026-11-08. Part of the MM-647 map (MCP connector tokens without DPoP). Facts are marked **Verified** (read from the cited primary source) or **Inference** (my reading).

## Verdict

No connector we target sends DPoP today, and none has a published plan to. Anthropic's connector docs describe a plain Bearer-style OAuth client, and Claude Code has an open bug that it sends no DPoP proof. The only live DPoP support is the opt-in TypeScript SDK 2.x client API, which a host application has to turn on. The spec itself does not mention DPoP, and the DPoP proposal (SEP-1932) is an unmerged draft. For the sidecar design, assume connectors present `Authorization: Bearer`.

## MCP specification

- **Verified.** The draft authorization spec requires `Authorization: Bearer <access-token>` on every request (Token Requirements), lists its standards basis (OAuth 2.1, RFC 6750, 8414, 7591, 8707, 9728, 9207, CIMD, OIDC Discovery), and contains no mention of DPoP, sender-constrained tokens, or token binding. <https://modelcontextprotocol.io/specification/draft/basic/authorization>
- **Verified.** The 2026-07-28 revision's changelog has authorization changes (RFC 9207 `iss` validation, `application_type` on DCR, credentials keyed by issuer, DCR deprecated in favour of CIMD) and nothing on DPoP. <https://modelcontextprotocol.io/specification/2026-07-28/changelog>
- **Verified.** The draft changelog currently holds one unrelated schema change. <https://modelcontextprotocol.io/specification/draft/changelog>
- **Verified.** The ext-auth repo lists two stable extensions, Enterprise-Managed Authorization and OAuth Client Credentials. It lists no DPoP extension in any stage. <https://github.com/modelcontextprotocol/ext-auth>
- **Verified.** SEP-1932 "DPoP Profile for MCP" is PR #1932 on modelcontextprotocol/modelcontextprotocol: open, unmerged, labelled `draft` and `extension`, opened 2025-12-05 by PieterKas, sponsor D-McAdams. The lifecycle bot flagged the sponsor for inactivity four times between 2026-09-07 and 2026-11-02. Design: client sends a proof on token and resource requests; Protected Resource Metadata advertises `dpop_signing_alg_values_supported` and `dpop_bound_access_tokens_required`; mixed Bearer/DPoP servers send dual `WWW-Authenticate` challenges; `dpop_jkt` on the authorization code is SHOULD. <https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1932>
- **Verified.** Related open proposals that are not DPoP: SEP-2752 HTTP Message Signing for client authentication (PR #2752) and SEP-1933 Workload Identity Federation (PR #1933).
- **Inference.** Because DPoP is only a draft extension, even a client that implements it will use it only where Protected Resource Metadata advertises it. A server cannot force it on a generic connector.

## Target clients

| Client | DPoP today | Evidence |
|---|---|---|
| Claude.ai custom connectors, Desktop, mobile, Cowork | No indication; docs describe none | Below |
| Claude Code | No (open bug) | Below |
| `@modelcontextprotocol/sdk` 1.x (what `tools/mcp-sidecar` pins, `^1.29.0`) | No | MM-648 body; 1.x not described as having it |
| TypeScript SDK 2.x (`@modelcontextprotocol/client`) | Yes, opt-in | Below |
| Python SDK | No | Below |
| Others (ChatGPT, Cursor, VS Code) | Not determined | No source found |

### Claude connectors (claude.ai, Desktop, mobile, Cowork)

- **Verified.** Anthropic's connector docs say Claude follows the 2025-03-26, 2025-06-18 and 2025-11-25 authorization specs, and none of those mention DPoP. The authentication page lists `oauth_dcr`, `oauth_cimd`, `oauth_anthropic_creds`, `custom_connection`, `static_headers` and `none`, and contains no DPoP, sender-constrained token or mTLS statement. It says the token endpoint receives `application/x-www-form-urlencoded`, Claude refreshes on 401 and five minutes before expiry, and public-client refresh tokens should be rotated (the spec's rotate-or-sender-constrain rule). <https://claude.com/docs/connectors/building.md> and <https://claude.com/docs/connectors/building/authentication.md>
- **Verified.** The building page says Claude implements "a subset of the MCP specification" and does not support "advanced or draft capabilities". A draft SEP falls in that bucket.
- **Verified (third party, weak).** Tailor's integration guide states Claude's and Claude Code's MCP clients do not support DPoP. <https://docs.tailor.tech/guides/integration/claude>
- **Not verified.** No Anthropic roadmap, issue or post commits to DPoP. Absence from the docs is not a promise either way.

### Claude Code

- **Verified.** anthropics/claude-code#96290 (open, filed 2026-09-23): with a pre-registered client against an authorization server that requires DPoP, the `/token` request carries no `DPoP` header, and the reporter finds no setting to enable it. <https://github.com/anthropics/claude-code/issues/96290>

### TypeScript SDK

- **Verified.** PR #2629 "feat(client): add DPoP (RFC 9449) sender-constrained token support" merged 2026-08-31. It is opt-in: DPoP activates only when the host implements `OAuthClientProvider.dpop()` and returns a `DpopSession`. Proofs are added at the fetch layer for the Streamable HTTP, SSE and `withOAuth` transports and at the token endpoint. `Authorization: DPoP <token>` is sent only when the token response says `token_type: DPoP`; otherwise Bearer is kept. `use_dpop_nonce` retry is handled for both AS and RS. <https://github.com/modelcontextprotocol/typescript-sdk/pull/2629>
- **Verified (secondary).** WorkOS (2026-09-29) says it shipped in 2.1.0 of `@modelcontextprotocol/client`, `core`, `server` and `node`, and that the spec does not mandate it. <https://workos.com/blog/mcp-sdk-dpop-and-scope-challenges>. The npm registry was blocked in this sandbox, so the 2.1.0 source was not read directly; PR #2629's description and issue #3026 (which describes 2.3.1 behaviour) are the primary evidence.
- **Verified.** Server-side proof validation is a separate, still-open PR #2630.
- **Verified.** Issue #3026 (open): `DpopSession` requires a WebCrypto `CryptoKey`. An external signer (KMS, HSM, secure enclave, remote service) is unsupported without casting through `unknown`. <https://github.com/modelcontextprotocol/typescript-sdk/issues/3026>

### Python SDK

- **Verified.** No DPoP in the client. Issue #3671 "DPoP sender-constrained tokens not implemented in OAuth client" is open; PR #3672 adding it was closed unmerged by a bot (missing issue link). The SDK only parses the `dpop_*` metadata fields. <https://github.com/modelcontextprotocol/python-sdk/issues/3671>
- **Verified.** That issue claims the spec requires DPoP; a commenter corrected it. The 2025-11-25 spec has no DPoP and SEP-1932 is a draft. Do not cite the issue title as evidence of a mandate.
- **Verified.** Issue #3728 (open): the Python resource server cannot accept DPoP-bound tokens.

## What this means for the sidecar

All of this section is **Inference**.

- A DPoP-bound token is useless behind a forwarding sidecar. The proof's `htu` is the URL the client called (the sidecar), its `ath` and signature come from a key only the client holds, and each proof is per request. The sidecar cannot replay it to the PDS or mint a new one. Forwarding `Authorization: DPoP` and the `DPoP` header unchanged would fail at the PDS on the `htu` mismatch.
- If a TS-SDK-2.x client ever did DPoP against the sidecar, the sidecar would have to be the DPoP resource server itself (validate the proof for its own URL) and then call the PDS with a credential of its own. That makes the sidecar hold a key and an auth decision, which cuts against the "forwards the caller's credential, caches nothing durable" design in ADR-0023/0024.
- Since no target connector presents DPoP, the realistic options are to issue Bearer tokens to connector clients, or to have the sidecar terminate the connector OAuth and hold the DPoP-bound PDS credential itself. Choosing between them belongs to the map, not this ticket.

## Open items

- Other widely used clients (ChatGPT connectors, Cursor, VS Code, MCP Inspector) were not determined; no primary source on their DPoP behaviour turned up.
- Anthropic's connector roadmap is unpublished; recheck the authentication page when SEP-1932 moves.
- Watch: SEP-1932 (PR #1932), TS SDK #3026 and #2630, Python SDK #3671, Claude Code #96290.
