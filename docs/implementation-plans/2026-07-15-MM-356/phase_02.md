# Hosted Custos MCP — Phase 2: Credential-forwarding Streamable-HTTP sidecar scaffold

**Child issue:** [MM-369](https://linear.app/malpercio/issue/MM-369) — Credential-forwarding Streamable-HTTP MCP sidecar scaffold (`mcp.obsign.org`).

**Goal:** Stand up a **new Node package** (`tools/mcp-sidecar/`) that reuses the
`tools/mcp/` tool surface but serves it over **Streamable HTTP**, authenticates
each caller via OAuth against Custos, keys sessions **per caller** instead of a
singleton, and **forwards** the caller's token on every request while caching
nothing durable. This is the scaffold; the acceptance-defining `create_post` E2E
is Phase 3.

**Architecture:** The `AgentSession` class is already a clean per-PDS unit; the
refactor turns the singleton into a **per-caller map** and replaces the on-disk
`0600` cache with **in-memory, session-scoped** state (design plan §4). The tool
implementations (`create_post`, `get_record`, …) are thin XRPC wrappers and are
**shared, not forked** — the sidecar imports/factors the tool registration so a
tool bugfix lands once. The sidecar terminates only the MCP transport + the
MCP-spec OAuth handshake (Custos is the authorization/resource server, ADR-0019);
all auth decisions stay in the PDS. Nothing durable is written: no state file, no
token cache, no DB (ADR-0024).

**Tech Stack:** Node 22 / TypeScript, `@modelcontextprotocol/sdk ^1.29.0`
(`StreamableHTTPServerTransport`), `zod`. Test harness reuses
`tools/mcp/test/harness.ts` (`spawnPds`, `startMockPlc`, `provisionAccount`,
`confirmClaim`) via a `file:` dev-dependency, same as `tools/mcp` depends on
`ezpds-interop`.

**Scope:** Phase 2 of 4; verifies **AC2** in
[`docs/test-plans/2026-07-15-MM-356.md`](../../test-plans/2026-07-15-MM-356.md).
Design: [`docs/design-plans/2026-07-14-hosted-custos-mcp.md`](../../design-plans/2026-07-14-hosted-custos-mcp.md)
§3, §4, §5. Decision fixed by
[ADR-0024](../../architecture/decisions/0024-hosted-agent-credential-forwarding.md).

**Codebase verified:** 2026-07-15.

---

## Acceptance Criteria Coverage

**Verifies:** `MM-356.AC2.1` … `AC2.7` (Streamable-HTTP transport, OAuth-per-caller
with no durable credential, in-memory session-scoped state, per-caller session
registry, token forwarding, log redaction, Railway third-service deploy surface).
Live confirmation of AC2.1/AC2.2 is HV-3/HV-4 in the test-requirements.

---

<!-- START_TASK_1 -->
### Task 1: Scaffold `tools/mcp-sidecar/` + per-caller session registry

**Files:**
- Create: `tools/mcp-sidecar/package.json` (`name: ezpds-mcp-sidecar`, private, ESM, node ≥ 22)
- Create: `tools/mcp-sidecar/src/registry.ts` — the per-caller session map
- Create: `tools/mcp-sidecar/tsconfig.json`, `bin/`, `README.md`

**Implementation:**

A `SessionRegistry` keyed by **authenticated caller identity** returns the same
`AgentSession`-shaped object within a caller's session and distinct objects across
callers; an unauthenticated request resolves to none. Unlike the stdio server, the
registry holds sessions only in memory, scoped to the live MCP session, and never
touches `state.ts`'s `0600` file path. Bound the map (idle eviction) so a
long-running process can't accumulate sessions.

**Verification:**
Run: `cd tools/mcp-sidecar && pnpm check`
Expected: type-clean.
Run: `node test/run.ts` (registry test)
Expected: same caller → same session; distinct callers → distinct sessions;
unauthenticated → none. (AC2.4)

**Commit:** `feat(mcp-sidecar): scaffold package + per-caller session registry`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Credential forwarding — session-scoped, in-memory, nothing durable

**Files:**
- Create: `tools/mcp-sidecar/src/session.ts` — a forwarding session (holds the caller token in memory only, for the life of the request/session)
- Create: `tools/mcp-sidecar/test/{forwarding,sessions}.test.ts`

**Implementation:**

Adapt `AgentSession` into a **forwarding** session: instead of loading/saving a
`0600` cache and re-exchanging a durable assertion, it takes the caller's
OAuth-obtained bearer (from the transport's auth context) and attaches it to each
forwarded XRPC call. It persists **nothing** — no assertion, no access token, no
refresh — beyond the in-memory, session-scoped value. On session teardown the token
is dropped; on process restart nothing is recoverable (ADR-0024).

The tool code paths that today call `session.accessToken()` get the forwarded token
transparently, so the shared tool surface (Task 3) needs no per-tool change.

**Verification:**
Run: `node test/run.ts` (forwarding + sessions tests)
Expected: (a) every forwarded XRPC call carries the caller's `Authorization: Bearer`
(stub PDS captures inbound headers); (b) **no** credential file exists under any
state dir after a call; (c) two callers' tokens are isolated; (d) restart leaves no
recoverable session. (AC2.2, AC2.3, AC2.5)

**Commit:** `feat(mcp-sidecar): forward caller token per request, cache nothing durable`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Share the tool surface; serve it over Streamable HTTP

**Files:**
- Modify: `tools/mcp/src/tools.ts` — factor `registerTools` so it is importable by the sidecar without behavior change (or export a shared factory both entry points call)
- Create: `tools/mcp-sidecar/src/server.ts` — the HTTP entry point (`StreamableHTTPServerTransport` + listener + MCP-spec OAuth handshake)
- Create: `tools/mcp-sidecar/test/transport.test.ts`

**Implementation:**

Keep the tool implementations single-sourced. The stdio `server.ts` keeps its
`StdioServerTransport`; the sidecar `server.ts` binds a
`StreamableHTTPServerTransport` (and the MCP OAuth handshake pointing at Custos's
`oauth-protected-resource` → `oauth-authorization-server` metadata, ADR-0019),
resolves the caller via the registry (Task 1), and registers the **same** tools
against a per-caller session (Task 2). The out-of-band claim UX changes: the
`user_code` is surfaced through the MCP auth flow / wallet, not stderr (design plan
§4) — but for the sovereign-child hosted path the child is already minted (Phase 1),
so the sidecar's job is forwarding, not onboarding.

**Verification:**
Run: `node test/run.ts` (transport test, against the hermetic `spawnPds`)
Expected: an MCP `StreamableHTTPClientTransport` client connects, lists tools, and
sees the same tool names the stdio server exposes. (AC2.1)
Run: `cd tools/mcp && pnpm check && node test/run.ts`
Expected: the stdio server's own suite is unaffected by the `tools.ts` refactor
(guards AC4.3 early).

**Commit:** `feat(mcp-sidecar): serve the shared tool surface over Streamable HTTP`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Redact authorization material everywhere

**Files:**
- Create: `tools/mcp-sidecar/src/log.ts` — a formatter that scrubs bearer/assertion material
- Create: `tools/mcp-sidecar/test/redaction.test.ts`

**Implementation:**

ADR-0024: avoiding DB storage is not sufficient — logs, traces, errors, and metrics
must redact authorization material. Route all sidecar logging and client-facing
error formatting through one scrubber that strips `Authorization` values, bearer
tokens, and identity assertions. Mirror the stdio server's discipline (tokens never
go to logs or MCP responses, per `state.ts` header) but enforce it centrally since
the sidecar handles many callers' tokens.

**Verification:**
Run: `node test/run.ts` (redaction test)
Expected: a token-bearing request and a token-bearing failure produce no
bearer/assertion substring in any emitted log line or client-surfaced error. (AC2.6)

**Commit:** `feat(mcp-sidecar): centralize authorization-material redaction`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Deploy surface — third Railway service over private networking

**Files:**
- Create: `tools/mcp-sidecar/src/config.ts` — required PDS origin (private `*.railway.internal` in the co-located tier) + public origin
- Modify: `docs/deploy.md` — document the third service (mirrors the `sites/marketing/` pattern)

**Implementation:**

Config reads the PDS origin and the sidecar's own public origin from the
environment; parse **fails loudly** when the PDS origin is unset (no silent default
to a public URL). Document deploying `mcp.obsign.org` as a third Railway service in
the same project, reaching the PDS over private networking (`*.railway.internal`),
with "Wait for CI" as its deploy gate — the same shape as staging/production
(design plan §5). Do not wire Railway tokens into CI (deploys are Railway-native,
per AGENTS.md).

**Verification:**
Run: `node test/run.ts` (config test)
Expected: config-parse rejects an unset PDS origin; a valid private + public origin
pair parses. (AC2.7)
Inspection: `docs/deploy.md` describes the third-service deploy.

**Commit:** `docs(deploy): document the mcp-sidecar as a third Railway service`
<!-- END_TASK_5 -->

---

## Live verification (HV-3, HV-4)

After this phase, run HV-3 (real MCP-spec OAuth handshake against staging's AS
metadata; restart forces re-authorization; no credential in logs) and HV-4
(inspect a deployed staging sidecar's filesystem/volume/logs for any durable
secret — there must be none). These prove the forwarding posture holds under a real
deployment, not just under the hermetic harness.
