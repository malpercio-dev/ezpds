# Hosted Custos MCP — Phase 3: `create_post` end to end over the sidecar on staging

**Child issue:** [MM-370](https://linear.app/malpercio/issue/MM-370) — `create_post` end to end over the hosted sidecar on staging (acceptance-defining).

**Goal:** A `create_post` tool call, made over the sidecar's **Streamable HTTP**
transport by a client bearing a **forwarded** OAuth token, publishes an
`app.bsky.feed.post` to the **child agent's** repo — attributed to the child, not
the parent — first against the hermetic PDS, then live against **staging**. This is
the acceptance-defining slice: it composes Phase 1 (minting) and Phase 2
(forwarding sidecar) into one working path.

**Architecture:** No new production surface beyond wiring — Phase 1 minted the
child and its scope-clamped credential; Phase 2 stood up the forwarding transport
and shared tool surface. This phase proves the composition and hardens the two
failure edges that matter to a caller: **scope refusal** (403 InsufficientScope
relayed legibly) and **revocation mid-session** (legible revoked/expired error, no
partial write). The e2e tests drive the sidecar exactly as a real MCP client would.

**Tech Stack:** Node 22 / TypeScript, `@modelcontextprotocol/sdk` HTTP client
transport, the `tools/mcp/test/harness.ts` hermetic PDS. Live pass runs against
`ezpds-staging.up.railway.app`.

**Scope:** Phase 3 of 4; verifies **AC3** in
[`docs/test-plans/2026-07-15-MM-356.md`](../../test-plans/2026-07-15-MM-356.md).
Design: [`docs/design-plans/2026-07-14-hosted-custos-mcp.md`](../../design-plans/2026-07-14-hosted-custos-mcp.md)
§1 (attribution), §3 (forwarding). Attribution fixed by
[ADR-0023](../../architecture/decisions/0023-sovereign-child-agent-identities.md).

**Codebase verified:** 2026-07-15.

---

## Acceptance Criteria Coverage

**Verifies:** `MM-356.AC3.1` … `AC3.4` (create_post publishes to the child repo;
attribution to the child DID; scope-refusal relayed legibly; revocation
mid-session relayed legibly). AC3.1/AC3.2 are the Definition of Done and are
confirmed live as HV-2.

---

<!-- START_TASK_1 -->
### Task 1: End-to-end fixture — mint a child, then drive the sidecar as a client

**Files:**
- Create: `tools/mcp-sidecar/test/e2e-fixture.ts` — spins the hermetic PDS (`spawnPds`), provisions a parent account, mints a child via the Phase-1 `/agent/child` route, starts the sidecar against that PDS, and returns an MCP HTTP client bound to a forwarded token for the child

**Implementation:**

Compose the existing harness pieces: `spawnPds` + `startMockPlc` +
`provisionAccount` (parent) from `tools/mcp/test/harness.ts`, then call the new
`POST /agent/child` mint (Phase 1) to create the sovereign child and obtain its
scope-clamped credential. Start the sidecar (Phase 2) pointed at the hermetic PDS,
obtain a caller token for the child, and hand back a connected
`StreamableHTTPClientTransport` MCP client. This fixture is the spine of every AC3
test — write it once.

**Verification:**
Run: `node test/run.ts` (fixture smoke)
Expected: fixture stands up PDS + child + sidecar + client without error and tears
them all down cleanly.

**Commit:** `test(mcp-sidecar): e2e fixture — hermetic PDS + minted child + sidecar client`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `create_post` publishes to the child repo, attributed to the child

**Files:**
- Create: `tools/mcp-sidecar/test/create_post.test.ts`

**Implementation:**

Using the Task-1 fixture, call `create_post` over the HTTP transport, then read the
record back (`get_record` / `com.atproto.repo.getRecord`). Assert:

- a record is created and readable (AC3.1);
- the record's repo/author DID is the **child's**, and the **parent's** repo is
  unchanged (AC3.2) — the sovereign-child attribution guarantee.

Confirm the forwarded token — not any sidecar-held credential — is what authorized
the write (ties back to AC2.5).

**Verification:**
Run: `node test/run.ts` (create_post test)
Expected: post created, readable, attributed to the child DID; parent repo
untouched. (AC3.1, AC3.2)

**Commit:** `test(mcp-sidecar): create_post publishes to the child repo (attributed)`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Failure edges — scope refusal and mid-session revocation

**Files:**
- Create: `tools/mcp-sidecar/test/scope.test.ts`
- Create: `tools/mcp-sidecar/test/revocation.test.ts`

**Implementation:**

- **Scope (AC3.3):** forward a token whose scopes exclude the write; assert the PDS
  returns `403 InsufficientScope` and the sidecar relays a legible, scope-naming
  error (parity with the stdio `relayError` in `tools/mcp/src/tools.ts`, which names
  the missing permission and the granted scopes), never a stack trace.
- **Revocation (AC3.4):** with the fixture, do one successful `create_post`, then
  revoke the child (Phase 1 `revoke` route) and attempt a second `create_post`;
  assert it fails with a legible revoked/expired message and **no partial write**
  lands. This ties AC1.7 (server-side revoke kills the delegated capability) to the
  caller-facing surface.

**Verification:**
Run: `node test/run.ts` (scope + revocation tests)
Expected: scope-refused call yields a legible scope-naming error; post-revocation
call yields a legible revoked/expired error with no write. (AC3.3, AC3.4)

**Commit:** `test(mcp-sidecar): relay scope-refusal + mid-session revocation legibly`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Wire the e2e suite into the runner and CI documentation

**Files:**
- Modify: `tools/mcp-sidecar/test/run.ts` (register the new suites)
- Modify: `justfile` — add `mcp-sidecar-setup` / `mcp-sidecar-test` recipes mirroring `mcp-setup` / `mcp-test`
- Modify: `AGENTS.md` (Commands) — document the new recipes (like `just mcp-test`; not part of `just ci`, needs node/pnpm)

**Implementation:**

Mirror the `tools/mcp` recipe pattern (`mcp-setup`, `mcp`, `mcp-test`). The sidecar
e2e suite is **not** part of `just ci-pds` (it needs node/pnpm + a built `pds`
binary, exactly like the existing conformance suite). Document how to run it and
what it needs (a debug/release `pds` build; `CUSTOS_MCP_TEST_PDS_BIN` override).

**Verification:**
Run: `just mcp-sidecar-test`
Expected: the full hermetic AC3 suite passes end to end.

**Commit:** `chore(mcp-sidecar): add just recipes + document the e2e suite`
<!-- END_TASK_4 -->

---

## Live verification (HV-2 — Definition of Done)

This is the headline acceptance. With the sidecar deployed as the third **staging**
Railway service reaching the PDS over private networking, connect a real MCP client,
complete the real OAuth handshake, and call `create_post`. Confirm the post appears
in the **child agent's** repo/feed (not the parent's) in a real Bluesky client and
that the audit log attributes it to the agent registration. Passing HV-2 closes the
first slice's acceptance ("implementation-plan phases map cleanly onto the Phase-1
children; `create_post` works end to end over the hosted sidecar on staging").
