# Custos MCP

A first-party [MCP](https://modelcontextprotocol.io) stdio server that lets an AI agent use a
Custos PDS — and, unlike the API-key-in-config norm, it gets its credentials by onboarding
itself through the PDS's own [auth.md](https://github.com/workos/auth.md) agent flow:

1. **Discover** — `/.well-known/oauth-protected-resource` → authorization-server metadata →
   the `auth.md` skill document.
2. **Register** — `POST /agent/identity` (`service_auth`, your account email as `login_hint`).
3. **Claim ceremony** — the server prints a short `user_code`; *you* (the account owner)
   confirm it, proving a human authorized this agent. The server polls until you do.
4. **Exchange** — the resulting service-signed identity assertion is exchanged for short-lived,
   scope-limited access tokens (RFC 7523 JWT-bearer grant) for the actual tool calls.

Every action the agent takes is attributed to its registration and visible to the account
owner — that is the point.

## Two supported modes — and which one this is

Custos supports **two attribution models**, chosen **independently** of who hosts the process.
This stdio server is one of them; the credential-forwarding [`tools/mcp-sidecar/`](../mcp-sidecar)
is the other. Neither is a fallback for the other — they answer two different questions:

- **Attribution** — does the agent act **as you** (writes into *your* repo; its actions carry
  *your* identity) or **as itself** (its own DID, repo, and handle — a named bot you own)?
- **Hosting** — who runs the process: **you** (self-host) or the **operator** (hosted)?

|                        | **Acts as you** (delegate)                                                                 | **Acts as itself** (sovereign child)                          |
|------------------------|--------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| **Self-hosted**        | ✅ **this stdio server** — you hold your own credential on your own machine, so acting *as you* is exactly right | ✅ fine — you just prefer a separate named identity            |
| **Hosted** (operator)  | ⚠️ only safe with strict credential-**forwarding** (operator holds nothing durable); never with server-side custody | ✅ **the hosted default** — even a durable bot credential can't act as you |

**This server sits in the top-left cell, and that cell is first-class, not a power-user
afterthought.** Self-hosting so the agent acts *directly on your behalf* is a supported,
encouraged mode. The only **forbidden** combination is *hosted + acts-as-you + durable custody*
(an operator holding a credential that can act as you) — everything else is a legitimate choice.

**The honest tradeoff** (yours to make, not ours to make for you): an agent that acts *as you*
posts under *your* attribution — the audit trail reads "you did this" — which is what you want
when the agent should *be* you (draft your real posts, manage your actual presence). A
[sovereign child identity](../mcp-sidecar) is preferable when you'd rather the agent's actions
stay **distinguishable** from your own. Same rigor either way; different attribution.

Decisions recorded in
[ADR-0023](../../docs/architecture/decisions/0023-sovereign-child-agent-identities.md)
(sovereign child identities — keeps acts-as-you first-class and the self-host default) and
[ADR-0024](../../docs/architecture/decisions/0024-hosted-agent-credential-forwarding.md)
(the hosted tier forwards credentials, holds nothing durable). Full reasoning:
[design plan §1](../../docs/design-plans/2026-07-14-hosted-custos-mcp.md) (the attribution ×
hosting matrix). For the hosted, sovereign-child sibling, see
[`tools/mcp-sidecar/README.md`](../mcp-sidecar/README.md).

## Ground rules (read first)

- **The agent acts as you.** Tools write to your real repository on whatever PDS you point
  this at. Point it at staging (or a local PDS) unless you mean it.
- **Scopes are enforced server-side.** The default agent profile is
  `atproto repo:*?action=create&action=update blob:*/*` — create/update posts and records,
  upload blobs, read. No deletes, no account or identity operations. The PDS operator controls
  this via `[agent_auth] granted_scopes`.
- **Destructive tools are off by default.** `put_record`/`delete_record` are not even listed
  unless you set `CUSTOS_MCP_ALLOW_DESTRUCTIVE=1` (and delete still needs a server-side grant).
- **Revocation wins.** If the registration is revoked on the server, the next exchange fails
  and the MCP server stays down until a human explicitly re-onboards it (`custos-mcp reset`).

## Setup

Requires Node ≥ 22.21 (matches `tools/interop`; the runtime runs TypeScript natively — there
is no build step).

```sh
cd tools/mcp && pnpm install    # or: just mcp-setup
```

The PDS must have the agent flow enabled: `[agent_auth] service_auth_enabled = true`
(or `EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED=true`). Against a PDS without it, the server
exits nonzero with the server's `service_auth_not_enabled` error — it will not retry.

## MCP client configuration

The launcher is `tools/mcp/bin/custos-mcp` (a wrapper that wires Node's fetch to any
configured egress proxy, then execs the stdio server). Configuration is environment
variables only:

| Variable | Required | Meaning |
|---|---|---|
| `CUSTOS_PDS_URL` | yes | Base URL of the PDS to onboard to |
| `CUSTOS_MCP_EMAIL` | first run | Your account email on that PDS (`login_hint` for registration) |
| `CUSTOS_MCP_AGENT_NAME` | no | Display name for the registration (default "Custos MCP") |
| `CUSTOS_MCP_ALLOW_DESTRUCTIVE` | no | `1` lists `put_record`/`delete_record` |
| `CUSTOS_MCP_IMAGE_DIR` | no | The one directory `create_post` may read image attachments from; unset = attachments disabled |
| `CUSTOS_MCP_STATE_DIR` | no | Credential-cache dir (default: OS state dir, e.g. `~/.local/state/custos-mcp`) |
| `CUSTOS_MCP_PACE_MS` | no | Min gap between HTTP requests (default 150) |

**Claude Code:**

```sh
claude mcp add custos --env CUSTOS_PDS_URL=https://your-pds.example.com \
  --env CUSTOS_MCP_EMAIL=you@example.com -- /path/to/ezpds/tools/mcp/bin/custos-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "custos": {
      "command": "/path/to/ezpds/tools/mcp/bin/custos-mcp",
      "env": {
        "CUSTOS_PDS_URL": "https://your-pds.example.com",
        "CUSTOS_MCP_EMAIL": "you@example.com"
      }
    }
  }
}
```

## The claim ceremony (first launch)

On first launch the server registers and then blocks on you:

```
[custos-mcp] onboarding to https://your-pds.example.com as "Custos MCP"
[custos-mcp] ACTION NEEDED — confirm this agent as the account owner:
[custos-mcp]   claim code:  AB3D9F
[custos-mcp]   confirm at:  https://your-pds.example.com/agent/claim (or in the Obsign wallet)
[custos-mcp]   expires:     …
```

Confirm the code in Obsign (or via `POST /agent/identity/claim/confirm` with your session
token). The MCP session is already live while it waits — the `whoami` tool reports the same
code and live status — and it transitions to ready the moment you confirm, no restart needed.
If the code expires unconfirmed, restart the server for a fresh one.

Credentials are cached per-PDS-host under the state dir, `0600`, and never appear in logs or
tool responses. Access tokens are short-lived and re-minted from the identity assertion
transparently; when the assertion itself expires (server default: 1 hour), a new claim
ceremony is required.

## Tools

| Tool | What it does |
|---|---|
| `whoami` | Onboarding status, DID/handle, granted scopes; pending claim code if any |
| `create_post` | `app.bsky.feed.post` via `createRecord` — text, reply refs, optional image via `uploadBlob` (only from `CUSTOS_MCP_IMAGE_DIR`) |
| `get_record` / `list_records` | Read a repo by collection (defaults to the onboarded account) |
| `search_timeline` | Timeline, or post search with `query` — proxied through the PDS to its AppView |
| `account_status` | `checkAccountStatus`: activation, repo head, record/blob counts |
| `put_record` / `delete_record` | Gated behind `CUSTOS_MCP_ALLOW_DESTRUCTIVE=1`; hidden otherwise |

Calls outside the granted scopes fail with the server's 403 relayed as a plain-language
error naming the missing permission and the scopes the agent actually holds.

## Revocation

Revoking the agent in the wallet makes the next token exchange fail with `access_denied`.
The server then reports "revoked in Obsign" on every tool call, remembers the revocation
across restarts, and **never re-registers on its own**. To onboard again after a deliberate
revocation:

```sh
CUSTOS_PDS_URL=https://your-pds.example.com tools/mcp/bin/custos-mcp reset
```

then restart the MCP server and confirm the new claim code.

## Conformance suite

`pnpm test` (or `just mcp-test`) is the client half of the Wave 8 agent-auth conformance
story: it spawns a hermetic local PDS (`cargo build -p pds` first; plc.directory is mocked,
nothing touches the live network), provisions a real account by reusing the
`tools/interop` ceremony, then drives discovery → register → claim → confirm → exchange →
tool calls through the real MCP server, plus the scope-refusal, revocation, and
agent-auth-disabled failure paths. The server half lives in
`crates/pds/src/routes/agent_auth_test.rs`.

It runs in CI as part of `.github/workflows/ci.yml`'s PDS gate, which points
`CUSTOS_MCP_TEST_PDS_BIN` at the `pds` binary that gate already built via `cargo test`
rather than building a second one. The path-filtered `.github/workflows/mcp-check.yml`
lane is a separate, faster, secret-free check (type-checking plus the MCP sidecar's
hermetic suite) that runs only on `tools/mcp/**`/`tools/mcp-sidecar/**` changes.
