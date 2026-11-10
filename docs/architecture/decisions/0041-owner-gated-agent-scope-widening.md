# ADR-0041: Owner-gated agent scope widening

- **Status:** Accepted
- **Date:** 2026-11-09
- **Deciders:** malpercio
- **Related:** MM-550 (spike), MM-642 (wayfinder map) and its resolutions MM-643–MM-646; ADR-0019 (auth.md agent authentication); ADR-0023 (sovereign child agents); ADR-0036 (sliding assertion renewal); design plan [2026-11-09-owner-gated-agent-scope-widening](../../design-plans/2026-11-09-owner-gated-agent-scope-widening.md); research note [2026-11-08-atproto-oauth-scope-widening](https://github.com/malpercio-dev/ezpds/blob/research/atproto-oauth-scope-widening/docs/research/2026-11-08-atproto-oauth-scope-widening.md) (branch `research/atproto-oauth-scope-widening`); `crates/custos-agents/src/routes/agents.rs`, `crates/custos-core/src/auth/oauth_scopes.rs`, `crates/custos-oauth/src/routes/oauth_token/jwt_bearer.rs`

## Context

An auth.md agent's **agent scope grant** is written once, at the **agent claim**
(for a **sovereign child**, at child conversion), from the operator's **scope
profile** (`[agent_auth] granted_scopes`) at that moment. Nothing writes it
afterwards. Every jwt-bearer exchange renews the assertion from the stored grant
clamped to the current profile (ADR-0036), and the child re-mint route
(`POST /agent/child/assertion`) applies the same clamp. Both are narrow-only: a
renewal can never climb above what was claimed.

That is the right rule for a renewal, but it leaves no deliberate way up. When an
operator raises the profile, every live agent stays at its claim-time grant. The
only route to the new scopes is revoke and re-claim. For a child that mints a new
DID, may cost its handle, and sends the old account through the deletion pipeline.
This happened in practice: an operator granted `transition:chat.bsky` for a DM
gateway, and a freshly minted child couldn't pick it up by any owner action short of
deletion.

OAuth grant records (`connector`, `oauth_app`) don't have this gap. Their grant is
rewritten on every OAuth re-consent.

atproto itself has no in-place widening (the research note above). A client that
wants more scope re-runs PAR and gets a new token family; a refresh can't change
scope. The reference PDS keeps a grow-only union of approved scopes per (account,
client), used only to decide whether consent can be skipped, and its consent screen
always shows the full requested set.

The tension: give owners a way to widen a live agent without identity churn, while
keeping the custody property that no agent ever holds a scope its owner didn't
approve.

## Decision

We will let an owner widen a live agent's grant in place, keeping its DID, under
these rules.

1. **Every widening needs a fresh owner act.** Raising the scope profile never
   widens a live agent by itself. The owner widens through the new owner endpoint
   `POST /v1/agents/{registration_id}/scopes`, behind the same gates as claim
   confirm: the owner guard (`authenticate_account_owner`, which refuses
   agent-derived and app-password credentials) plus the wallet's biometric tap. No
   server-side proof is bound to the tap. Narrowing stays automatic.

2. **The scope profile is a hard ceiling.** An owner never grants above it. The
   server clamps whatever the request carries to the current profile.

3. **Consent covers the whole profile, all-or-nothing, with one biometric tap.**
   The owner approves the full current profile, the same as at claim. There is no
   subset picker and no step-up for elevated scopes (`transition:*`, `account:*`,
   `identity:*`, `com.atproto.access`); they carry the same warning they carry at
   claim. The consent screen shows the full set with the scopes the agent doesn't
   hold marked as new. Marking is display only and has no protocol effect.

4. **The grant only grows; the profile suspends.** A widening stores
   `grant ∪ (shown ∩ current profile)`, where `shown` is the exact set the consent
   screen displayed. It never replaces the grant. The grant is the record of what
   the owner has approved; the profile decides which of those approvals are usable
   now. A scope the operator removes from the profile is *suspended*, not revoked,
   and comes back with no new tap if the operator restores it, because the owner
   approved it once. Restoring a suspended scope is not a widening.

5. **One consent rule for claimed agents and children.** The endpoint serves
   claimed registrations of type `identity_assertion`, `service_auth`, `anonymous`
   and `child`, found through the existing `owned_identity` check (the account the
   agent acts as, or a child's parent). `connector` and `oauth_app` grant records
   are refused with an error that points at OAuth re-consent, their own path.

6. **Every widening is audited.** A `scopes_widened` audit row, with the owner as
   actor and `{before, shown, after}` as detail, commits in the same transaction as
   the grant write. A request that adds nothing writes neither.

7. **The endpoint returns no assertion.** It returns `scopes` (the stored grant)
   and `effectiveScopes` (grant ∩ current profile). An active agent picks up the
   wider grant at its next jwt-bearer exchange, within about one access-token
   lifetime, through the renewal ADR-0036 already returns. For a dormant child, the
   wallet calls the existing re-mint route right after, under the same tap, and
   hands the assertion over as it does today.

This ADR sits beside ADR-0019 and ADR-0036 and amends neither. ADR-0036 is about
sliding renewal and never took a narrow-only stance.

## Consequences

- Raising the profile no longer strands live agents. An owner reaches the new
  scopes with one tap, and a child keeps its DID, handle and repo.
- Custody is unchanged: every scope an agent holds traces to an owner tap and an
  audit row. An operator can still narrow every agent at once by lowering the
  profile.
- The stored grant can now hold scopes the agent can't currently use. Anything
  that reads the grant must clamp it to the profile before calling a scope held.
  The wallet's detail screens show the raw grant today; they must show
  `effectiveScopes` as held and the rest as suspended.
- A suspended scope reappears without a tap if the operator restores it. An owner
  who wants a scope gone for good revokes the agent. Per-agent owner narrowing is
  not provided, because the grow-only grant doesn't give it for free.
- The new route sits under `/v1/agents/*` with the other claimed-agent owner
  routes. Child management still has its own owner routes under `/agent/child/*`;
  converging the two styles is separate work.
- This goes past atproto in one respect: atproto never widens a live grant in
  place. Custos can, because the grant bounds a renewable assertion rather than a
  fixed token family, and the renewal path already exists.

## Alternatives considered

- **A refresh flag on the child re-mint route** (`POST /agent/child/assertion`
  with `refresh_scopes: true`, re-clamping from the profile). Covers children only,
  and puts an owner consent write on the agent-facing surface. Rejected for the
  single owner endpoint.
- **Widen automatically when the profile rises.** Removes the stranding with no
  UI, but grants scopes no owner approved, which breaks the custody property the
  claim ceremony exists for.
- **Replace the grant with the shown set.** Simpler arithmetic, but a widening
  during a profile dip would silently drop a suspended scope the owner approved
  earlier, and narrowing would need its own write path. The union keeps the grant
  monotonic.
- **Delta-only consent** (show only the new scopes). The reference PDS always
  shows the full set, and an owner deciding whether to grant more should see what
  the agent will hold in total. New scopes are marked instead.
- **A subset picker** (in the spirit of the reference PDS's
  `narrowAuthorizedScope`). Adds per-agent narrowing state the grow-only grant
  can't represent, and a claim is already all-or-nothing.
- **Step-up for elevated scopes.** The claim ceremony grants the same elevated
  scopes behind one tap with a warning. A widening follows the claim's rule rather
  than setting a stricter one for the same scopes.
- **Revoke and re-claim** (status quo). Mints a new DID for a child, can lose the
  handle, and runs the deletion pipeline for what is a permission change.
