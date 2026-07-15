# Hosted Custos MCP — Phase 4: Preserve + document the self-hosted acts-as-you stdio path

**Child issue:** [MM-367](https://linear.app/malpercio/issue/MM-367) — Preserve + document the self-hosted acts-as-you stdio path (non-regression).

**Goal:** The shipped stdio MCP (`tools/mcp/`) keeps working **unchanged**, and the
**acts-as-you** attribution model is documented as **first-class and the self-host
default** — not a fallback the hosted tier deprecates. This phase is the regression
gate for the self-hosted path and the prose that records where each attribution
model applies.

**Architecture:** The sidecar (Phases 2–3) is a **sibling package**, not a rewrite
of the stdio server. The only shared code is the tool surface (`tools/mcp/src/tools.ts`,
factored in Phase 2 Task 3); that refactor must be behavior-preserving for the stdio
server. This phase runs the existing hermetic conformance suite as the non-regression
gate, asserts the stdio transport / `0600` cache / singleton session are untouched,
and writes the attribution × hosting matrix into the docs so the two models stay
visible (design plan §1, ADR-0023 consequences).

**Tech Stack:** Node 22 / TypeScript (existing `tools/mcp/`), the existing
`just mcp-test` conformance harness. Docs in `tools/mcp/README.md` and the design
corpus.

**Scope:** Phase 4 of 4; verifies **AC4** in
[`docs/test-plans/2026-07-15-MM-356.md`](../../test-plans/2026-07-15-MM-356.md).
Design: [`docs/design-plans/2026-07-14-hosted-custos-mcp.md`](../../design-plans/2026-07-14-hosted-custos-mcp.md)
§1 (attribution × hosting matrix), §5 (tier 3: self-hosted).
[ADR-0023](../../architecture/decisions/0023-sovereign-child-agent-identities.md)
keeps acts-as-you first-class.

**Codebase verified:** 2026-07-15.

---

## Acceptance Criteria Coverage

**Verifies:** `MM-356.AC4.1` … `AC4.3` (stdio conformance suite stays green;
acts-as-you documented first-class / self-host default; stdio transport + `0600`
cache + singleton session untouched by this slice). AC4 needs no live check — the
hermetic conformance suite is the gate.

---

<!-- START_TASK_1 -->
### Task 1: Document the attribution × hosting matrix (acts-as-you first-class)

**Files:**
- Modify: `tools/mcp/README.md` — state that this stdio server is the self-hosted **acts-as-you** path and that it is a supported, encouraged mode
- Modify: the design corpus cross-links (ensure the README points at
  [ADR-0023](../../architecture/decisions/0023-sovereign-child-agent-identities.md) /
  [ADR-0024](../../architecture/decisions/0024-hosted-agent-credential-forwarding.md)
  and the design plan)

**Implementation:**

Write the matrix explicitly (design plan §1): attribution (acts-as-you vs sovereign
child) and hosting (self vs operator) are **independent** choices; self-hosted
acts-as-you (top-left) is where the shipped stdio server sits and is a first-class
mode, **not** a power-user afterthought; the operator-hosted default is the
sovereign child (Phases 1–3). Name the one forbidden cell (hosted + acts-as-you +
durable custody). Keep it honest about the tradeoff the design plan surfaces (your
own attribution vs a distinguishable bot identity). No ticket references in the
prose beyond the ADR/plan links (project convention allows doc-level traceability,
not source comments).

**Verification:**
Inspection: `tools/mcp/README.md` states the matrix, marks acts-as-you first-class,
cross-links ADR-0023/0024 and the design plan. (AC4.2)

**Commit:** `docs(mcp): document acts-as-you as the first-class self-host default`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Assert the self-hosted path's surface is untouched

**Files:**
- Inspect (no change expected): `tools/mcp/src/server.ts` (`StdioServerTransport`),
  `tools/mcp/src/state.ts` (`0600` on-disk cache), `tools/mcp/src/auth.ts`
  (singleton `AgentSession` lifecycle)

**Implementation:**

Confirm — via git diff over the whole slice — that the Phase-2 `tools.ts` refactor
did **not** change the stdio server's transport, its on-disk `0600` credential
cache, or its singleton-per-PDS `AgentSession`. The sidecar's per-caller /
in-memory / forwarding behavior lives entirely in `tools/mcp-sidecar/`; the stdio
server retains its cache-and-reuse model (correct for self-hosting, where the user
holds their own credential on their own machine). If the shared-tool factoring
required touching stdio wiring, keep it to the seam only and prove behavior parity
via Task 3.

**Verification:**
Run: `git diff origin/main -- tools/mcp/src/server.ts tools/mcp/src/state.ts tools/mcp/src/auth.ts`
Expected: empty (or, at most, a behavior-preserving import change from the Task-3
seam of Phase 2, justified in the diff). (AC4.3)

**Commit:** _(no code change; verification recorded in the phase / PR description)_
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Run the stdio conformance suite as the non-regression gate

**Files:**
- Modify (only if a shared-tool import needs it): `tools/mcp/src/tools.ts`
- Exercise: `tools/mcp/test/conformance.test.ts` via `just mcp-test`

**Implementation:**

The existing hermetic conformance suite (`spawnPds` → provision account → onboard
via `service_auth` → confirm claim → `create_post` → whoami/reads) is the
regression gate. It must pass **unchanged** after the whole slice lands. If the
Phase-2 shared-tool factoring introduced any seam in `tools.ts`, this is where its
behavior parity is proven for the stdio server.

**Verification:**
Run: `just mcp-test`
Expected: the conformance suite passes green, identical to pre-slice behavior. (AC4.1)
Run: `cd tools/mcp && pnpm check`
Expected: type-clean.

**Commit:** _(no code change unless the seam requires it; the green suite is the deliverable)_
<!-- END_TASK_3 -->

---

## No live verification required

AC4 is fully covered by the existing hermetic conformance suite plus documentation
inspection — it asserts *this* codebase's non-regression, which the harness drives
deterministically. This phase can run in parallel with Phases 1–3 for the docs half
(Task 1) but its gate (Tasks 2–3) must run **after** the Phase-2 `tools.ts` refactor
lands, since that is the only change that could regress the stdio server.
