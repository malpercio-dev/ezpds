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
[design plan §1](../../docs/archive/design-plans/2026-07-14-hosted-custos-mcp.md) (the attribution ×
hosting matrix). For the hosted, sovereign-child sibling, see
[`tools/mcp-sidecar/README.md`](../mcp-sidecar/README.md).

## Ground rules (read first)

- **The agent acts as you.** Tools write to your real repository on whatever PDS you point
  this at. Point it at staging (or a local PDS) unless you mean it.
- **Scopes are enforced server-side.** The default agent profile is
  `atproto repo:*?action=create&action=update repo:*?action=delete blob:*/*` — create, edit,
  and delete records in your repo, upload blobs, read. No account or identity operations. The
  PDS operator controls this via `[agent_auth] granted_scopes`. Delete is granted so an agent
  can retract its own mistaken write; it does not widen the blast radius, since `action=update`
  already lets it overwrite a record irreversibly.
- **Destructive tools are off by default.** `put_record`/`delete_record` (and their space
  siblings `space_put_record`/`space_delete_record`) are not even listed unless you set
  `CUSTOS_MCP_ALLOW_DESTRUCTIVE=1`. The client-side gate and the server-side grant are
  independent: a registration minted before delete joined the default profile still refuses
  with 403 until it re-registers.
- **Atproto Spaces tools need a `space:` grant.** `list_spaces`, `space_get_record`,
  `space_list_records`, and `space_create_record` drive the user's permissioned space repos;
  the default profile grants no `space:` scope, so each reports a clean refusal naming what
  the operator must add to `[agent_auth] granted_scopes` (for example
  `space:*?authority=*&collection=*` — a bare `space:*` confers reads but no write target).
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
| `CUSTOS_MCP_IMAGE_DIR` | no | The one directory `create_post`, `upload_blob`, and `update_bluesky_profile` may read files from; unset = uploads disabled |
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
transparently, and every exchange also returns a renewed assertion the client persists (a
sliding window — server default: 30 days for a claimed binding). A new claim ceremony is only
needed after the agent has been completely inactive for a full assertion lifetime.

## Tools

| Tool | What it does |
|---|---|
| `whoami` | Onboarding status, DID/handle, granted scopes; pending claim code if any |
| `create_post` | `app.bsky.feed.post` via `createRecord` — text, reply refs, optional image via `uploadBlob` (only from `CUSTOS_MCP_IMAGE_DIR`). URLs, `#hashtags`, and `@mentions` in the text become rich-text facets automatically; pass `facets` to override |
| `upload_blob` | Upload a file from `CUSTOS_MCP_IMAGE_DIR` as a blob and return its ref, for avatars, banners, or any other record field that takes a blob. MIME inferred from the extension for png/jpg/gif/webp; pass `mime_type` for anything else. A blob no record references is eventually garbage-collected |
| `update_bluesky_profile` | Update the Bluesky profile record `app.bsky.actor.profile` — display name, description, avatar, banner. Read-modify-write, so omitted fields keep their value and an empty string clears one; guarded with `swapRecord` against the CID just read, so a concurrent edit fails with `InvalidSwap` rather than overwriting. Set an image either by path (uploaded for you, from `CUSTOS_MCP_IMAGE_DIR`) or by a blob ref from `upload_blob` |
| `get_record` / `list_records` | Read a repo by collection (defaults to the onboarded account) |
| `search_timeline` | Timeline, or post search with `query` — proxied through the PDS to its AppView |
| `account_status` | `checkAccountStatus`: activation, repo head, record/blob counts |
| `list_spaces` | Atproto Spaces: list the permissioned spaces the account's repo has written to, filterable by space type or authority DID (needs a `space:` grant) |
| `space_get_record` / `space_list_records` | Read the account's records inside a permissioned space, addressed by a canonical space ref (needs a `space:` grant) |
| `space_create_record` | Create a record in the account's repo inside a permissioned space (needs a `space:` grant covering create) |
| `put_record` / `delete_record` | Gated behind `CUSTOS_MCP_ALLOW_DESTRUCTIVE=1`; hidden otherwise. `delete_record` is how an agent retracts its own mistaken write |
| `space_put_record` / `space_delete_record` | Space siblings of `put_record`/`delete_record`, gated behind the same `CUSTOS_MCP_ALLOW_DESTRUCTIVE=1` (each also needs a `space:` grant covering the write) |

Calls outside the granted scopes fail with the server's 403 relayed as a plain-language
error naming the missing permission and the scopes the agent actually holds. The `space:`
grant the Spaces tools need is not in the default profile — see the Spaces ground rule above.

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
