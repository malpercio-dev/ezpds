# Design plan: a first-party *hosted* Custos MCP

**Status: design / exploration — captures a design session, not yet committed to a wave slot.**
Written to durably record where a "hosted MCP alongside obsign.org" conversation landed. Verdict
up front: the interesting product is **not** "the same stdio server, but we run it" — it's a
reframing where the agent becomes its **own sovereign identity** (own handle, recovery key in the
user's Obsign wallet), and the hosted MCP tier **forwards** the caller's credential rather than
holding it. That combination dissolves the custody objection that otherwise makes hosting
contradict the product thesis.

Two decisions in here are ADR-worthy and are flagged inline (see **§7 ADRs to write**).

## What already exists (this is not greenfield)

- **Custos *is* the PDS** (`crates/pds/`, axum + single-writer SQLite), deployed at **obsign.org**
  (production) and `ezpds-staging.up.railway.app` (staging). Deploy model: OCI image, Railway
  native GitHub integration (ADR-0008, ADR-0009, `docs/deploy.md`).
- **The agent-auth surface is first-party** (ADR-0019, `crates/pds/assets/auth.md`): discover →
  `POST /agent/identity` → human claim ceremony (`user_code` confirmed in Obsign) → RFC 7523
  jwt-bearer exchange for a **5-minute, scope-clamped, per-agent-revocable** Bearer token. No
  static API keys. Enabled on production (`EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED=true`, 2026-07-13).
- **The MCP exists** (`tools/mcp/`, `ezpds-mcp`): a Node/TS **stdio, single-user** client of that
  surface. `@modelcontextprotocol/sdk ^1.29.0`. One process = one account = one `AgentSession`
  keyed by PDS host = credentials cached `0600` on the user's own machine. HTTP/SSE transport and
  multi-user hosting are **explicitly out of scope for v1** (`docs/archive/design-plans/2026-07-07-custos-mcp-server.md`).
- **The `anonymous` registration type** already models an "ownerless pre-claim identity bound to an
  account on claim" — ~80% of the scaffolding for a child identity, today bound as *acts-as-user*.
- **The wallet already does `did:plc` genesis + rotation** for the user's own identity (ADR-0001,
  ADR-0004; `crates/crypto/`). The same machinery can mint and hold recovery for an *agent's* DID.
- **Sovereign sessions** (`routes/sovereign_session.rs`, `POST /v1/sessions/sovereign`):
  passwordless session issuance from a rotation-key-signed proof — the delegation primitive an
  agent-native credential path can mirror.
- **Iroh** is bound opt-in for device→PDS NAT traversal (`EZPDS_IROH_ENABLED`, dial by stable node
  id; `crates/pds/src/iroh_tunnel.rs`, ADR context in `docs/design-plans/2026-07-11-iroh-http-tunnel-exploration.md`).
- **Litestream** backs up the production DB; as of 2026 it also supports live read replicas
  (object-store lease, no Consul). LiteFS is the FUSE-based HA alternative.

## 1. The core reframing — agent as a sovereign *child* identity

Today the MCP onboards an agent to **act as you** — write into *your* repo — so the durable
credential a hosted service would hold maps to *your* identity. That is the entire source of the
custody problem. Flip it: make the agent **its own ATProto principal** — own DID, own repo, own
handle — created and owned by a parent account.

The key-custody ladder then reads:

| Key | Where it lives | In scope for the hosted tier? |
|---|---|---|
| User's rotation/recovery key | Obsign Secure Enclave | **Never** — never touches any server, in any option |
| **Agent's** rotation/recovery key | **Obsign wallet** (same genesis/rotation machinery) | No — held by the user, not the operator |
| Agent's day-to-day signing capability | Delegated, short-lived, scope-clamped, revocable | Yes — but disposable and one-tap killable |
| Agent's access token | 5-minute Bearer (existing) | Ephemeral by design |

So "custodian of keys" collapses to "holder of a **revocable delegated signing capability** for a
bot whose master key is in the user's wallet." That is arguably a *stronger* posture than the local
stdio server, where the assertion sits `0600` on a laptop with no enclave. The agent's actions are
attributable to a real, separate, named identity — more honest in a feed and in the wallet's audit
list than an opaque "acting as you" token.

**This is ADR-worthy** (§7, ADR-A): it changes the agent model from *acts-as-user delegate* to
*sovereign child principal*, and defines who holds the agent's recovery key.

## 2. Handles — subdomain now, custom domain later (both native to ATProto)

- **Subdomain now.** obsign.org already serves `*.obsign.org` for user handles
  (`EZPDS_AVAILABLE_USER_DOMAINS`). A **flat** agent handle (`alice-writer.obsign.org`) costs
  nothing new. Caveat: a single-label wildcard cert covers `alice-writer.obsign.org` but **not** a
  nested `writer.alice.obsign.org` (that needs `*.alice.obsign.org` or on-demand TLS issuance —
  Caddy supports it, but it's real infra). **Flat naming first; nested "agent under your handle" is
  a phase-two** gated on on-demand certs.
- **Custom domain later.** Native — ATProto handle verification is DNS-TXT or
  `/.well-known/atproto-did`, the same path users already have for their own handles. "Bring
  `bot.mycompany.com`" is not new protocol, just letting an agent identity traverse the existing
  handle-verification path.
- **Reserved handles** (`EZPDS_RESERVED_HANDLES`) already exist to keep infra names out of the
  user-handle wildcard space; agent handles share that namespace and must respect it.

## 3. Custody and codebase are independent axes

The earlier "Option A (in the PDS) vs Option B (separate service)" framing conflated two
orthogonal decisions. Separate them:

|  | **Hold credentials** (durable, server-side) | **Forward credentials** (per-request, hold nothing durable) |
|---|---|---|
| **In the PDS (Rust)** | — | **"A": MCP endpoint on axum**; agent Bearer *is* the MCP session token |
| **Separate process (Node)** | the naive multi-tenant service (custody trap) | **"sidecar": reuse `tools/mcp/` tool code, forward caller auth** |

- **Custody axis — always forward.** MCP's remote-auth model *is* OAuth, and Custos already *is*
  the OAuth AS. So the MCP client authenticates against obsign.org, the token rides each tool call,
  and the tier caches nothing durable (in-memory per session at most). The naive multi-tenant
  service only "needed" custody because it assumed long-lived server-side sessions; forwarding
  removes that assumption. **Commit to forwarding regardless of process choice.** *(ADR-worthy — §7,
  ADR-B.)*
- **Codebase/process axis — sidecar first.** A **credential-forwarding Node sidecar** keeps the
  mature `tools/mcp/` tool surface (`create_post`, `get_record`, …, which are thin XRPC wrappers)
  and terminates only the MCP transport + streaming, delegating all auth to the PDS. Folding the
  endpoint into axum (option "A") is the tighter long-term shape (one process, one language, tools
  reimplemented in Rust) but is a larger lift; treat it as a possible later consolidation, not the
  first step.

Net of §1–§3: **agent = sovereign child identity; hosted tier = credential-forwarding sidecar.**

## 4. Transport and the multi-tenancy refactor

- **Transport: stdio → Streamable HTTP.** `server.ts` hard-codes `StdioServerTransport`; the SDK
  supports HTTP transports, so this is a swap plus a listener and the MCP-spec OAuth handshake
  (Custos as the authorization server / resource server).
- **Sessions: singleton → keyed by authenticated caller.** Today `config.ts` reads one
  `CUSTOS_PDS_URL`/`CUSTOS_MCP_EMAIL` and `state.ts` keys one cache file per PDS host. The `AgentSession`
  class is already a clean per-PDS unit; the refactor turns the singleton into a per-caller map and
  replaces the on-disk `0600` cache with **in-memory, session-scoped** state (nothing durable, per
  §3). The out-of-band claim UX changes too: surface the `user_code` to the right human via the MCP
  auth flow / wallet, not stderr.
- **Single-process boundary is real (inherited).** ADR-0019 notes agent claim-polling state is an
  *in-memory tracker* tied to the single-process SQLite PDS. A horizontally-scaled MCP tier fronting
  a single-writer PDS is fine, but any "hosted → therefore scale" ambition eventually collides with
  the *PDS* deployment model, not the MCP tier. Name it; don't solve it here.

## 5. Deployment tiers (and where Iroh earns its keep)

1. **Fully hosted, co-located** (default). The sidecar is a **third Railway service in the same
   project** (mirroring how `sites/marketing/` is deployed), e.g. `mcp.obsign.org`, reaching the PDS
   over Railway **private networking** (`*.railway.internal`). Iroh is unnecessary here.
2. **Host-your-own sidecar, still first-party-connected** (later tier). A user runs the sidecar
   themselves but wants a direct, authenticated, NAT-punching channel to the PDS **without exposing
   a new public endpoint** — exactly what **Iroh** provides (dial the PDS as a known node id, TLS
   1.3 raw-public-key auth, independent of WebPKI/DNS). Iroh is a **connectivity/topology**
   primitive here, **neutral on custody**. This reuses the existing endpoint; it does not require
   HTTP-over-iroh (see the iroh-tunnel exploration doc for that separate question).
3. **Local stdio** (today) stays as-is for power users.

## 6. Explicitly deferred levers (recorded so they aren't re-litigated)

- **honker.dev** — a SQLite extension giving Postgres-style NOTIFY/LISTEN, durable queues, streams,
  pub/sub, and a scheduler (transactional-outbox on one SQLite file, zero servers). **Orthogonal to
  the hosting/transport/custody question.** Genuinely useful *later* as agent-runtime plumbing:
  durable **agent job queues** (survive a restart), **scheduled agent tasks** ("post the digest each
  morning"), and an **audit-event outbox** reliably fanning "agent did X" into the wallet's audit
  stream + firehose. On-ethos (SQLite-native, single-file), slots beside the PDS's existing
  background sweeps. **Reach for it when agents get async/scheduled behavior, not before.**
- **Litestream / DB replication** — as of 2026 Litestream does live read replicas (not just DR).
  But agents are **write-then-immediately-read**, so an async replica breaks read-after-write (agent
  posts, then lists, and doesn't see its own write). Reads that tolerate staleness (public timeline,
  search) *could* use a replica; own-repo reads must hit the primary. **This is a whole-PDS
  geo-scaling decision, not an MCP-hosting one — do not couple them.** The MCP talks to the
  single-writer primary; SQLite stays the source of truth.

## 7. ADRs to write

Two decisions here are architecturally load-bearing and should be recorded as ADRs (next free
number is 0022; assign in order when written):

- **ADR-A — Agents are sovereign child identities.** The agent has its own DID/repo/handle; its
  recovery key is held in the user's Obsign wallet (same genesis/rotation machinery as the user's
  own identity); day-to-day signing is a delegated, revocable capability. Supersedes the
  *acts-as-user* assumption baked into the current auth.md service_auth flow for the hosted path.
  Relates to ADR-0019, ADR-0001, ADR-0004.
- **ADR-B — The hosted agent tier forwards credentials; it never holds durable user/agent
  secrets.** MCP remote auth = OAuth against Custos (the existing AS); the caller's token rides each
  request; the tier caches nothing durable. This is the security-posture commitment that keeps a
  hosted offering consistent with the product thesis. Relates to ADR-0019.

Whether ADR-A and ADR-B are two documents or one is an author's call at writing time; they are
separable claims (identity model vs custody posture) and default to two.

## 8. Gating

Both the in-PDS and sidecar paths gate naturally: **an agent identity can only be minted as a child
of an account that exists on this PDS.** The agent inherits the parent's entitlement, the parent
holder provisions and revokes it, and a non-obsign.org user has no parent account to hang an agent
off. The gate falls out of the ownership graph rather than being a bolted-on check.

## 9. One-sentence compression

Make the agent a **sovereign child identity** (own handle, recovery key in the wallet), run the MCP
as a **credential-forwarding sidecar** (Node now over Railway private networking; Iroh for a
self-host tier later), and keep **honker/Litestream** as separate "when we need async jobs / geo
reads" levers — not part of the hosting decision.

## Sequencing / next step

This plan is the input to **implementation plans** (design → test-requirements → phases triad, per
`docs/archive/README.md`). Tracking issue:
[MM-356](https://linear.app/malpercio/issue/MM-356/hosted-custos-mcp-agent-as-child-identity-credential-forwarding)
(project `ezpds`, Wave 8: auth.md — Linear is the source of truth for its status). The first
implementation plan should cover the smallest end-to-end slice:
agent-as-child-identity minting + a credential-forwarding Streamable-HTTP sidecar for one tool
(`create_post`) against staging, with the two ADRs written alongside.
