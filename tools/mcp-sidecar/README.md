# Custos MCP sidecar

A **credential-forwarding, Streamable-HTTP** MCP server for the *hosted* Custos tier
(`mcp.obsign.org`). It reuses the [`tools/mcp`](../mcp) tool surface unchanged but serves it
over HTTP to many callers at once, authenticates each caller via OAuth against Custos, and
**forwards** the caller's token on every request — holding nothing durable.

This is the sibling of the stdio server, not a replacement. The two attribution × hosting
models are both first-class (design plan §1 matrix):

- **Self-hosted, acts-as-you** → the stdio server (`tools/mcp`). You hold your own credential.
- **Hosted, sovereign child** → this sidecar. The agent is its own identity; the sidecar never
  holds a durable credential that could act as anyone.

Design: [`docs/design-plans/2026-07-14-hosted-custos-mcp.md`](../../docs/design-plans/2026-07-14-hosted-custos-mcp.md)
§3–§5. Posture fixed by [ADR-0024](../../docs/architecture/decisions/0024-hosted-agent-credential-forwarding.md)
(credential forwarding) and [ADR-0023](../../docs/architecture/decisions/0023-sovereign-child-agent-identities.md)
(sovereign child identities).

## What it does — and deliberately does not

- **Transport:** MCP **Streamable HTTP** (`StreamableHTTPServerTransport`), not stdio. One
  long-running service, many callers.
- **Sessions:** a **per-caller in-memory map** (`SessionRegistry`), keyed by the forwarded
  token's subject, replacing the stdio server's singleton `AgentSession`. Idle-evicted and
  capped so a long-running process can't accumulate sessions.
- **Credentials:** the caller's OAuth bearer is **bound for one request and released the moment
  it resolves**. No assertion, no access token, no refresh, **no `0600` cache** — nothing on
  disk, nothing in a DB, nothing that survives a restart (ADR-0024). The `0600` state-file path
  of the stdio server is never touched here.
- **Redaction:** every log line and every client-facing error is routed through one scrubber
  (`src/log.ts`) that strips `Authorization` values, bearer tokens, and identity assertions.
- **Auth decisions stay in the PDS.** The sidecar does not verify tokens or enforce scopes; it
  terminates only the MCP transport and the OAuth *resource* metadata. The PDS is the resource
  server and rejects an invalid/out-of-scope token on the forwarded call.

The tool implementations are **single-sourced** from `tools/mcp/src/tools.ts` (imported by
relative path — Node will not type-strip a `.ts` resolved under `node_modules`, and neither
package has a build step), so a tool bugfix lands once.

## Run it

Requires Node ≥ 22.21 (runs TypeScript natively — no build step), same as `tools/mcp`.

```sh
just mcp-sidecar-setup          # cd tools/mcp-sidecar && pnpm install
just mcp-setup                  # the sidecar reuses tools/mcp's runtime deps
MCP_SIDECAR_PDS_ORIGIN=http://127.0.0.1:8080 just mcp-sidecar
```

Configuration is environment variables only:

| Variable | Required | Meaning |
|---|---|---|
| `MCP_SIDECAR_PDS_ORIGIN` | yes | Where the sidecar forwards XRPC calls. In the co-located tier this is the PDS's **private** Railway address (`http://pds.railway.internal:PORT`), never the public domain. Parse **fails loudly** if unset. |
| `MCP_SIDECAR_PUBLIC_ORIGIN` | prod | The sidecar's own public origin (`https://mcp.obsign.org`), advertised as the OAuth resource identifier. Defaults to the PDS origin for local single-host runs. |
| `PORT` | no | Listen port (Railway injects it; default 8080). |
| `MCP_SIDECAR_PATH` | no | MCP endpoint path (default `/mcp`). |
| `CUSTOS_MCP_ALLOW_DESTRUCTIVE` | no | Same gate as the stdio server: `1` lists `put_record`/`delete_record`. |
| `CUSTOS_MCP_IMAGE_DIR` | no | Same gate as the stdio server: the one directory `create_post` may read image attachments from. |

Endpoints:

- `POST /mcp` — the MCP Streamable-HTTP transport (an MCP client connects here).
- `GET /.well-known/oauth-protected-resource` — MCP-spec protected-resource metadata pointing
  a caller at Custos as the authorization server (ADR-0019).
- `GET /` — liveness (200, touches no credential).

## Connecting an MCP client

The caller completes the OAuth authorization against Custos and presents the resulting bearer;
it rides each tool call. With an MCP SDK client:

```ts
new StreamableHTTPClientTransport(new URL('https://mcp.obsign.org/mcp'), {
  requestInit: { headers: { Authorization: `Bearer ${callerToken}` } },
});
```

The sovereign-child agent is minted separately (Phase 1, [MM-368](https://linear.app/malpercio/issue/MM-368));
the sidecar's job is forwarding, not onboarding.

## Test suite

`pnpm test` (or `just mcp-sidecar-test`) is **hermetic and self-contained** — unlike the stdio
conformance suite it needs no `cargo build` and no TLS proxy. It drives the sidecar over its
real HTTP transport with an MCP `StreamableHTTPClientTransport` client and a lightweight **stub
PDS** on loopback that records inbound requests (headers included), covering:

- **registry** — same caller → same session; distinct callers → distinct; unauthenticated →
  none; idle eviction + cap.
- **forwarding** — the caller token rides each XRPC call; no credential file is written; no
  token lingers after the request resolves.
- **sessions** — two callers are isolated; an unauthenticated call is refused; restart leaves no
  recoverable state.
- **redaction** — no bearer/assertion substring reaches a log line or a client error.
- **transport** — a real MCP client lists the same tool names the stdio server exposes.
- **config** — an unset PDS origin is rejected; a private+public origin pair parses.

The `create_post` end-to-end against real staging (attributed to the child agent) and the live
OAuth-handshake / no-durable-secret checks are the next slice ([MM-370](https://linear.app/malpercio/issue/MM-370),
HV-2/HV-3/HV-4).

## Deploy

A **third Railway service** in the PDS's project, reaching the PDS over private networking —
the full runbook (including the repo-root build-context nuance, since the sidecar single-sources
`tools/mcp`) is in [`docs/deploy.md`](../../docs/deploy.md) → "MCP sidecar".
