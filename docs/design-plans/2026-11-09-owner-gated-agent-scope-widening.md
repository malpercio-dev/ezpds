# Owner-gated agent scope widening

**Date:** 2026-11-09 · **Status:** Ready for implementation · **Linear:** MM-550 (Wave 8: auth.md)
**Decision record:** [ADR-0041](../architecture/decisions/0041-owner-gated-agent-scope-widening.md)
**Sources:**
- Wayfinder map MM-642 ("Owner-gated agent scope widening") and the resolution comments on MM-643, MM-644, MM-645 and MM-646
- Research note [2026-11-08-atproto-oauth-scope-widening](https://github.com/malpercio-dev/ezpds/blob/research/atproto-oauth-scope-widening/docs/research/2026-11-08-atproto-oauth-scope-widening.md) (branch `research/atproto-oauth-scope-widening`)
- Throwaway prototype on branch `prototype/agent-permissions-affordance` (never merge): `PROTOTYPE_ScopeWidening.svelte`, variant C, with the `agent-children` or `agent-connected` harness scenario and `?variant=C`
- Code as of `origin/main` 3be68448: `crates/custos-agents/src/routes/agents.rs`, `crates/custos-db/src/agent_audit.rs`, `crates/custos-db/src/agent_auth.rs`, `crates/custos-core/src/auth/oauth_scopes.rs`, `crates/obsign-core/src/agents.rs`

Terms follow `GLOSSARY.md` → Agents: **agent claim**, **agent scope grant** (here
"the grant"), **scope profile** (here "the profile"), **sovereign child**
(here "child").

## 1. The problem

An agent's grant is written once, at the agent claim (or child conversion), and
never again. Renewal clamps the stored grant to the current profile, so it can
only narrow. When the operator raises the profile, every live agent stays where it
was. The only way up is revoke and re-claim, which for a child means a new DID, a
possible handle loss and a trip through the deletion pipeline.

ADR-0041 records the rules that fix this. This plan specifies the work.

## 2. Rules (from ADR-0041)

- Every widening needs a fresh owner act. Raising the profile never widens a live
  agent. Narrowing stays automatic.
- The profile is a hard ceiling.
- The owner approves the whole current profile, all-or-nothing, with one biometric
  tap. No step-up for elevated scopes, no subset picker.
- The grant only grows: a widening stores `grant ∪ (shown ∩ current profile)`. The
  profile suspends a scope without revoking it; restoring a suspended scope needs
  no tap.
- Claimed agents and children widen under one consent rule and one route.

Two facts the design rests on (re-checked against 3be68448):

- For auth.md agents and children, nothing writes `scopes` after the claim except
  the one-time claim and child-conversion UPDATEs. `connector` / `oauth_app` grant
  records rewrite `scopes` on every OAuth re-consent upsert (`agent_auth.rs`).
- Re-mint stores only `assertion_expires_at` and returns the JWT in its response.
  Every jwt-bearer exchange returns a renewed assertion built from the stored grant
  clamped to the profile. A widened grant reaches an active agent within about one
  access-token lifetime with no new delivery path; a dormant child still needs the
  wallet's re-mint hand-over.

## 3. Design: the endpoint

**Route.** `POST /v1/agents/{registration_id}/scopes`, on `custos-agents`'
`internal_router` beside `/revoke` and `/audit`.

**Auth.** `authenticate_owner` (the owner guard, `authenticate_account_owner`,
which refuses agent-derived and app-password credentials), then `owned_identity`:
the caller is the account the agent acts as, or a child's parent. Unknown and
foreign ids are the same uniform 404. The wallet's biometric gate is the fresh
owner act; no server-side proof is bound to the tap, the same as claim confirm.

**Accepted registrations.** Status `claimed`, type `identity_assertion`,
`service_auth`, `anonymous` or `child`. Refusals:

| Case | Answer |
|---|---|
| `connector` / `oauth_app` | 400 with a message pointing at OAuth re-consent (that path rewrites the grant itself) |
| any status other than `claimed` | 403 `Forbidden`, as the child re-mint route refuses a child that isn't `claimed` |
| unknown / foreign id | 404 `unknown agent registration` |

**Request.** `{ "scopes": [...] }`: the exact set the consent screen showed.

**Write.** In one transaction:

1. Read the stored grant (`before`).
2. `after = before ∪ (shown ∩ current profile)`, using the existing
   `intersect_scope_tokens` for the clamp and canonical token order for the union.
3. If `after == before`, commit nothing and return 200 with the current values.
4. Otherwise UPDATE `scopes` and insert the audit row, then commit.

A profile change that races the screen is handled by the arithmetic: scopes added
to the profile after the screen rendered aren't in `shown`; scopes removed from it
fall out of the clamp.

**Audit row.** New `AgentAuditEventType::ScopesWidened` → `"scopes_widened"`.
`did` is the acting owner (the parent, for a child). `detail` is
`{"before": [...], "shown": [...], "after": [...]}`. "Added" isn't stored; it's
`after − before`.

**Response.** `{ "scopes": [...], "effectiveScopes": [...] }`: the stored grant
and `grant ∩ current profile`. No assertion. Detail screens use `effectiveScopes`
to tell held from suspended without a second fetch.

**The child re-mint route** (`POST /agent/child/assertion`) is unchanged and stays
renewal-only.

## 4. Design: the wallet

Both `AgentDetailScreen` and `ChildAgentDetailScreen` get the same three pieces,
the shape chosen in the prototype (variant C).

**Banner.** "More permissions available" ("Your server allows N more. Tap to
review."), where N is `|profile − grant|`. It shows only for a live agent whose
profile holds scopes the grant lacks; never for a revoked, deleting or
provisioning agent, and never for `connector` / `oauth_app` records. Tapping it
opens the Permissions section.

**Permissions list.** Held scopes only: the grant clamped to the profile. Elevated
scopes (`transition:*`, `account:*`, `identity:*`, `com.atproto.access`) keep
their existing warning. Scopes in the grant but outside the profile fold behind
an "N suspended" disclosure. Opened, each shows a pause icon, a "Suspended" tag and
struck-through text, under a note that the server no longer allows it and that it
returns without asking if the server allows it again. Status is never carried by
colour alone.

**Consent screen.** Its own "More permissions" screen with a back arrow, not an
inline expansion. It lists the full current profile with a "New" tag on each scope
the grant lacks. A new elevated scope carries both the tag and the elevated
warning. It says the set is all-or-nothing and that suspended scopes stay
suspended. One "Approve with biometrics" button; "Not now" goes back.

**After approval.** The wallet calls the endpoint with the shown set. For a child,
under the same tap, it then calls the existing `remint_child_assertion` and hands
the assertion over as it does today, so a dormant child picks up the wider grant.
The banner goes away; suspended scopes stay suspended.

**Layers.** `custos-client::agents` gets the HTTP call; `obsign-core::agents`
gets `widen_agent_scopes` (and the child chaining); `src-tauri/src/commands.rs`
exposes a `widen_agent_scopes` IPC command; `src/lib/ipc/agents.ts` wraps it. The
browser harness fake implements the same arithmetic so the screens are drivable
with no PDS.

## 5. Corrections the change forces

These were the map's open "Not yet specified" item. Each is named work in the
phase that causes it.

- **MCP `InsufficientScope` text** (`tools/mcp/src/tools.ts`). Today it tells the
  user widening needs the operator to change `granted_scopes` *and the owner to
  re-confirm a claim ceremony*. It should say the operator raises the profile and
  the owner approves the new scopes from the agent's page in the wallet, with no
  re-claim. The sidecar single-sources this surface, so one edit covers both.
- **auth.md** (`crates/custos-agents/assets/auth.md`, the scope section near "Operators
  can widen or narrow"): state that raising the profile doesn't widen claimed
  agents, that the owner widens per agent from the wallet, and that narrowing
  applies to every renewal.
- **Operator capability docs** (`sites/docs/src/content/docs/operator/capabilities.md`
  → `agents`): the paragraph on `agent_auth.granted_scopes` currently describes
  narrowing only. Add that raising it takes effect for each agent once its owner
  approves. Also update the `summary` in `crates/custos-agents/src/capability.rs` if
  the wording changes; `just capability-docs-check` and `just docs-check` gate the
  pair.
- **Bruno**: new `bruno/agents_widen_scopes.bru` (next `seq`), `POST
  {{baseUrl}}/v1/agents/{{registrationId}}/scopes`, owner Bearer, body
  `{"scopes": [...]}`. `just bruno-check` gates the path.
- **ADR-0036 wording.** Its Decision §2 says the renewal is minted and "persists
  it". Since PR #748 only the expiry is stored. Correct that one line.

## 6. Phases

1. **Server** (one PR: `crates/custos-agents`, `crates/custos-db`, docs). The
   endpoint, the `scopes_widened` event type, the union-and-clamp write, the
   Bruno file, auth.md, the capability docs, the ADR-0036 line, the `agents.rs`
   row in `crates/custos-agents/AGENTS.md`, a changelog fragment. Deploys to
   staging on merge.
2. **Wallet** (one PR: `crates/custos-client`, `crates/obsign-core`,
   `apps/identity-wallet`). Client method, core function, IPC command, harness
   fake, banner, Permissions list with suspended scopes, consent screen, child
   re-mint chaining. Regenerate the IPC reference (`just docs-generate`), add a
   changelog fragment, and add harness scenarios for "more available" and
   "suspended" so `just docs-screenshots` can capture them. Lands after phase 1
   is on staging.
3. **MCP text** (one small PR: `tools/mcp`). The `InsufficientScope` message.
   Independent of phase 2; can land with or after phase 1.

## 7. Acceptance criteria

### Phase 1: server

- **AC1.1** An owner `POST`s a shown set to a claimed `identity_assertion`,
  `service_auth`, `anonymous` or `child` agent: the stored grant becomes
  `before ∪ (shown ∩ profile)` and the response returns that as `scopes` and its
  clamp to the profile as `effectiveScopes`.
- **AC1.2** A shown scope outside the current profile is never stored.
- **AC1.3** A grant scope outside the current profile (suspended) is kept after a
  widening, and appears in `scopes` but not `effectiveScopes`.
- **AC1.4** A widening writes exactly one `scopes_widened` row whose `did` is the
  acting owner (the parent, for a child) and whose `detail` holds `before`,
  `shown` and `after`. The row and the UPDATE commit together; a forced failure of
  either leaves neither.
- **AC1.5** A request that adds nothing returns 200 with the current values and
  writes no UPDATE and no audit row.
- **AC1.6** A `connector` or `oauth_app` registration is refused with an error
  naming OAuth re-consent, and its grant is unchanged.
- **AC1.7** A registration in any status other than `claimed` is refused with
  403, unchanged.
- **AC1.8** An unknown id and another owner's id both return the same 404.
- **AC1.9** An agent-derived token and an app-password session are both refused
  by the owner guard.
- **AC1.10** After a widening, the next jwt-bearer exchange for that agent returns
  an access token and renewed assertion carrying the widened `effectiveScopes`.
- **AC1.11** After a widening, `POST /agent/child/assertion` for that child mints
  an assertion carrying the widened `effectiveScopes`.
- **AC1.12** Lowering the profile below a widened grant narrows the next renewal
  with no write to the grant; restoring the profile restores the scope at the
  next renewal with no owner request.
- **AC1.13** `just bruno-check`, `just capability-docs-check`, `just docs-check`
  and `just ci-pds` pass.

### Phase 2: wallet

- **AC2.1** The banner shows with the right N on both detail screens for a live
  agent whose profile holds scopes the grant lacks, and doesn't show for a
  revoked, deleting or provisioning agent or a `connector` / `oauth_app` record.
- **AC2.2** The Permissions list shows held scopes only; suspended scopes sit
  behind an "N suspended" disclosure with icon, tag and strike-through.
- **AC2.3** The consent screen lists the full profile, tags each new scope "New",
  shows the elevated warning on new elevated scopes, and has one biometric
  approve button and a "Not now" back.
- **AC2.4** Approving sends exactly the shown set; a failed biometric sends
  nothing.
- **AC2.5** For a child, approving calls the widening endpoint and then
  `remint_child_assertion` under the same tap; a re-mint failure leaves the
  widened grant in place and reports the hand-over failure.
- **AC2.6** After approval the banner is gone and suspended scopes are still
  suspended.
- **AC2.7** The harness fake reproduces AC2.1–AC2.6 with no PDS, and the IPC
  reference is regenerated.
- **AC2.8** Wallet host tests pass (`cargo test -p identity-wallet` with the iOS
  env), and `pnpm check` and the frontend unit tests pass.

### Phase 3: MCP

- **AC3.1** The MCP `InsufficientScope` message lists the agent's granted scopes
  and says the owner can approve more from the agent's page in the wallet once the
  operator allows them, without mentioning a re-claim.
- **AC3.2** `pnpm check` and `pnpm test` pass in `tools/mcp`, and the sidecar
  type-checks.

## 8. Open points

- **How the wallet learns the profile for a live agent.** The banner and the "New"
  tags need the current profile, but today it's only exposed by
  `POST /v1/agents/claim-preview`, which needs a `user_code`. The map didn't
  decide this. The smallest option is for `GET /v1/agents` to return
  `effectiveScopes` per agent plus the current profile once at the top level.
  Settle it in phase 1 before the wallet work starts.
- **`describeScopes` copy for a child's `account:` scope.** It says "your
  account", which overstates what a child's scope reaches. Noted in the
  prototype review, not decided; fix it in phase 2 if the copy is touched anyway.

## 9. Out of scope

- Agent-initiated requests for wider permissions (the owner-initiated path is the
  minimum; agent requests can layer on top later).
- Releasing a child's handle as soon as it's queued for deletion.
- Consolidating the child and claimed-agent owner endpoints into one style.
- Per-agent owner narrowing.
