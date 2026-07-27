# Wallet Information Architecture — The Instrument Panel

**Status: phases 1–3 shipped; 4 open.** Deliverable of a structured IA brainstorm
(2026-07-24), tracked as MM-465–MM-470 (§9). The identity instrument panel (§2.1–§2.4,
MM-465), the Protection surface + home strip (§2.5, MM-466), and the alarm takeover
landing (§3, MM-467) are built; the Add-identity situation question (§4, MM-468) is not.
§7's mapping table describes the target, which phases 1–3 have now reached for every
row except `mode_select`.

Phase 3 added one rule §3 did not state. "Always dismissible" is not enough on its own:
an alarm dismissed on launch would re-take the app on the very next foreground, which is
the lock-in §3 forbids arriving by a different door. So the takeover records which alarms
it has already presented — keyed by the affected DID *and* its set of change CIDs — and
does not interrupt for those again in the same app session. Keying on content rather than
on the DID is what keeps that from suppressing news: a second unauthorized operation
against an already-dismissed identity is a new alarm and interrupts again. The record is
in-memory by design; a relaunch is a fresh chance to be told, because an attack must not
be dismissible once, forever.

One decision was made during phase 2 that this document left open. §2.5 asks the
Protection list to reorder "by urgency" without saying which of the wallet's two existing
orderings that means. It follows the **identity panel's** rule — rank by what is *true*,
so an active unauthorized change leads — rather than the home card strips' rule, which
ranks by what to do *next* and puts a dead device key first (the recovery override an
alarm leads to is signed with the very key that is missing). The sequencing that rule
protects is not lost: it moves into the summary copy, which says to recover first when an
alarmed wallet also holds an unusable key. Ordering states severity; the sentence states
the order of operations.

The identity wallet grew feature-by-feature, so its structure mirrors the Rust IPC
modules, not user intent: each backend module got a screen, and each screen got a button
on `DIDDocumentScreen`. That produced the two pains this plan fixes — a **detail-screen
hub with ~10 verbs of wildly different frequency and stakes**, and **no spatial model**
(every screen is "a state you got sent to" inside one ~50-step flat state machine).

The chosen cure is a **mode-based IA**: structure by the user's tempo, not by feature.
The wallet has exactly three tempos — *use* (frequent, calm), *maintain* (rare, careful),
*defend* (emergency) — and the IA now encodes them structurally.

## Decisions record

Every structural call below was made deliberately in the brainstorm session:

| Question | Decision |
|---|---|
| Primary pains | Detail-screen overload; no spatial model |
| Organizing lens | Mode-based split (Use / Maintain / Defend) |
| Shape | **B+ hybrid**: instrument-panel identity screens + a home protection strip that opens a full app-level Protection surface. No persistent tab bar (shape C rejected: near-empty tabs at the realistic 1–2 identity count, tab chrome suppressed during the app's most important ceremonies anyway, stock-iOS register risk) |
| Defend placement | Both levels: app-level Protection surface + per-identity status panel |
| Alarm entry | **Full takeover** on open — the app lands on the alarm surface, no navigation required |
| Maintain depth | Two tiers behind one "Manage identity" door; the advanced tier opens with a **vestibule** (plain-language framing screen) |
| App passwords | Use zone — the job is "use my identity in apps", even though it's credential minting |
| Migration | **Own door** on the identity screen ("Move or rebuild") — credible exit is the product's core promise, not a repair to bury |
| Naming | "Protection" (app-level Defend), "Manage identity" (Maintain door) — plain Proton/1Password register, not seal-metaphor theater |
| Entry flows | One situational "Add identity" question replacing the create/import/recover door taxonomy |
| Scope | Design doc only; the `+page.svelte` state machine is untouched by this plan. Admin-companion gets shared principles (§8), not a redesign |

## 1. Sibling IA principles (both apps)

These bind both Obsign and the Brass Console — the IA-level extension of the shared
"practice what you preach" rigor:

1. **Structure by tempo, not by module.** A screen earns its position by how often and
   in what emotional state a person reaches for it — never by which backend module
   implements it. Frequent+calm sits one tap deep; rare+careful sits behind one
   deliberate door; emergency is not navigated to at all (see 4).
2. **State leads, actions follow.** The first thing any object screen shows is the
   object's live status (the seal panel; relay health), not a menu. Actions hang off
   state, so the screen answers "am I okay?" before "what can I do?".
3. **Surgery gets a vestibule.** Protocol-level, irreversible, or identity-threatening
   operations live behind a framing screen that states plainly what this tier of tools
   does, before showing the tools. Depth is the warning; the vestibule is the consent.
4. **Emergencies interrupt; they are never destinations.** An active alarm restructures
   the surface (takeover, transformed home) rather than waiting behind navigation.
   Nothing time-critical may live only behind a badge.
5. **One door per depth tier.** A surface may present at most one "go deeper" affordance
   per tier (Use → Manage → Advanced). Two sibling doors at the same depth is the start
   of the next verb wall.

## 2. Wallet: target structure

```
Home ("Identities")
├── Protection strip  ──────────────▶ Protection (app-level)
│     "All identities secure ·           ├── per-identity status list
│      checked 2 min ago"                ├── monitor history (sweep log)
│                                        └── [alarm mode: sorted by urgency]
├── Identity card(s) ───────────────▶ Identity (instrument panel)
│                                        ├── STATUS PANEL (the Defend surface)
│                                        │     Secure / Action needed / Under attack
│                                        │     └── Security checkup · alarm path
│                                        ├── USE
│                                        │     ├── Sign in to an app (consent/QR)
│                                        │     ├── Sign in to Bluesky (app passwords)
│                                        │     └── My agents (+ approvals)
│                                        ├── MOVE OR REBUILD (own door)
│                                        │     ├── Move to another server (migration)
│                                        │     └── Rebuild from backup (disaster rec.)
│                                        └── MANAGE IDENTITY (one door)
│                                              ├── everyday tier
│                                              │     ├── Change handle
│                                              │     ├── Backups (media + posts)
│                                              │     └── DID document (view/verify)
│                                              └── Advanced ▸ VESTIBULE
│                                                    ├── Rotate repo signing key
│                                                    ├── Re-key (old-model upgrade)
│                                                    ├── Repair hosting endpoint
│                                                    └── Remove identity
├── Add identity ───────────────────▶ situational wizard (§4)
└── Settings (global: appearance, background backup, diagnostics, PDS config)
```

### 2.1 The status panel (per-identity Defend)

The top of every identity screen is a large-format sibling of `UrgencyBadge` — same
four-state vocabulary (safe / warning / critical / expired), same color+icon+label+
position rule, rendered as a panel, not a badge:

- **Secure**: verified-green tonal panel; "Secure — directory checked N min ago";
  a quiet "Security checkup" disclosure (key custody summary, Share 3 confirmation
  status, backup freshness — the Watchtower pattern).
- **Action needed** (warning): amber panel naming the action (e.g. backup stale,
  session needs unlock), one primary affordance.
- **Under attack** (critical): the panel *is* the alarm entry — countdown, "Review &
  override" primary. The existing `alert_detail` → `recovery_override` path hangs off
  it unchanged.
- **Expired**: ashen/closed, per the existing Critical-vs-Expired distinction.

### 2.2 Use zone

Directly below the panel, ungrouped-feeling, one tap each: OAuth consent approval
(typed code / QR), app passwords, agents. These are the only identity actions a normal
week touches. App passwords sit here deliberately — the user's job is "use my identity
in Bluesky", and the credential mechanics are the machinery, not the task.

### 2.3 Move or rebuild (the exit door)

Migration and disaster recovery share one visible door between Use and Manage. Rationale:
credible exit is the sovereignty story made structural — an owned identity's "leave"
affordance must be findable without spelunking, but it is not an everyday verb, so it
gets a door, not top-level buttons. Inside: "Move to another server" (the outbound
migration journey) and "Rebuild from backup" (disaster recovery when the current host is
gone). Both remain the ceremony flows they are today.

### 2.4 Manage identity (Maintain)

One door. Everyday tier visible on entry: change handle, backups (the media + posts
surface, presented as one "Backups" item), DID document (moves here from being the hub
itself — it becomes the inspection/verification surface it was named for). Below the
everyday tier, a single "Advanced" affordance opens the **vestibule**: a plain-language
screen — *"These tools change how your identity works at the protocol level. You rarely
need them, and each one explains itself before anything is signed."* — then the surgery
list (rotate repo key, re-key, repair endpoint, remove identity). Remove keeps its
existing warn → verify → hold-to-confirm ceremony; the vestibule is additive framing,
not a replacement for per-operation gates.

### 2.5 Protection (app-level Defend)

Opened from the home strip (the strip is a door, not just a status readout). Contents:
every identity's status row (tap-through to that identity's panel/alarm), and the
monitor history — when the sweep last ran, what it checked, per-identity last-verified
times. This gives the PLC monitor a visible face: today it works invisibly and the user
has no way to see that protection is *happening*, which wastes the product's central
trust-building opportunity. In alarm state the surface reorders by urgency.

## 3. Alarm behavior: full takeover

When an unauthorized change is active and the app is opened or foregrounded, the app
**lands directly on the alarm surface** for the affected identity — zero navigation
between "phone unlocked" and "the one clear action". Rules:

- One identity in alarm → its alarm surface (the critical status panel expanded, i.e.
  today's `alert_detail` content).
- Multiple identities in alarm → Protection in alarm mode, most urgent first.
- Always dismissible ("Not now") to a home rendered in alarm state — protection strip
  as a pinned critical banner, affected cards elevated. Calm under alarm means one
  clear action *offered*, never a lock-in.
- An in-progress ceremony (recovery epilogue resume, mid-migration) still wins the
  landing decision — resuming interrupted key material handling outranks re-showing an
  alarm the user has already seen. The alarm banner still renders inside those flows'
  chrome where safe.

## 4. Add identity: the situational wizard

`mode_select`'s door taxonomy (create / import / recover / rebuild / migrate — five
sibling journeys with near-synonymous names) is replaced by **one situation question**:

> **Add an identity** — what's your situation?
> 1. **Starting fresh** — make a brand-new identity → create flow (did:plc/did:web
>    method choice and `pds_config` capability gate unchanged, one level in).
> 2. **I have an account somewhere** — hold the keys to an existing Bluesky/ATProto
>    account → import/claim flow.
> 3. **I lost access to my wallet** — rebuild wallet custody from recovery shares →
>    share-recovery flow.
> 4. **My server is gone** — informational route, not a flow of its own: if the
>    identity is already in this wallet, it points to that identity's "Move or
>    rebuild" door; if the wallet itself was also lost, it chains share recovery
>    (option 3) first, then rebuild. Disaster recovery structurally requires wallet
>    custody, so this option is honest routing, never a dead end.

First launch lands on this question directly (there is no home yet); with existing
identities it is reached from home's "Add identity".

## 5. Copy and naming

- **Protection** — the app-level Defend surface. Not "Security" (zero voice), not
  seal-metaphor names (theater risk).
- **Manage identity** — the Maintain door. Its everyday tier needs no group label.
- **Advanced** — the vestibule door label; the vestibule body carries the plain-language
  framing (§2.4).
- **Move or rebuild** — the exit door. Inside: "Move to another server", "Rebuild from
  backup".
- The status panel states reuse the `UrgencyBadge` label vocabulary ("Secure", "Action
  needed", countdown, "Recovery window closed") verbatim — one vocabulary, two sizes.

## 6. DESIGN.md amendment required

§5 "Navigation" currently reads "a calm state-machine flow, not a chrome-heavy shell…
no tab bars". That stays true (shape C was rejected), but the section must be extended
to name the new structural vocabulary: the instrument-panel identity screen (state
leads, actions follow), the zone order (status → use → exit → manage), the vestibule
pattern, the Protection surface, and the alarm-takeover landing rule. The Status/Urgency
Badge section gains the panel-format sibling. This doc is the source for that edit.

## 7. Screen inventory mapping (current → target)

No screen is deleted; this is a re-homing. `+page.svelte` step names are today's IDs.

| Current step(s) | Target location |
|---|---|
| `mode_select` | replaced by the Add-identity situation question (§4) |
| `identity_method`, `did_web_*`, `pds_config`, `create_unavailable`, `claim_code`, `email`, `handle`, `password`, `loading`, `did_ceremony`, `did_success`, `shamir_backup`, `handle_registration`, `authenticating` | unchanged ceremony flow under "Starting fresh" |
| `identity_input`, `pds_auth`, `email_verification`, `review_operation`, `claim_success` | unchanged under "I have an account somewhere" |
| `recover_*` | unchanged under "I lost access to my wallet" |
| `home` | Home: protection strip + identity cards + Add identity + Settings |
| *new* | Protection surface (strip tap-through; alarm mode) |
| `identity_detail` (DIDDocumentScreen as hub) | replaced by the instrument-panel identity screen; the DID *document* view moves into Manage identity as an inspection surface |
| `oauth_consent_approval`, `app_passwords`, `my_agents`, `agent_approval` | Use zone |
| `migration_*` | behind "Move or rebuild" |
| `recovery_rebuild_start/progress` | behind "Move or rebuild" |
| `change_handle`, `media_backup` | Manage identity, everyday tier |
| `rotate_repo_key`, `rekey_*`, `endpoint_repair`, `remove_identity` | Manage identity → Advanced (behind the vestibule) |
| `alert_detail`, `recovery_override` | the critical status panel's expansion (content unchanged) |
| `settings` | unchanged (global) |

## 8. Admin-companion: applying the principles

Light pass only (per scope decision); the Brass Console is already closer to the target
because it was built later. Observations against §1:

- **Principle 2 (state leads)**: per-relay screens should open with relay health/
  reachability before operator verbs, if they don't already.
- **Principle 1 (tempo)**: claim-code generation (frequent) vs device revocation and
  moderation (rare/surgical) deserve the same tier separation as Use vs Advanced.
- **Principle 3 (vestibule)**: per-relay revocation and destructive moderation actions
  are the console's surgery tier.
- **Principle 4 (interrupt)**: a relay in a failing state should restructure the relay
  list the way an identity alarm restructures Home.

A dedicated Brass Console IA review applying these is follow-up work (§9).

## 9. Follow-up issues (Linear, project ezpds — filed 2026-07-24)

1. **MM-465 — Wallet IA phase 1 — identity instrument panel**: status panel + Use zone +
   "Manage identity" door + vestibule; DIDDocumentScreen becomes the document view.
2. **MM-466 — Wallet IA phase 2 — Protection surface + home strip** (incl. monitor
   history, which needs a small IPC addition to expose sweep timestamps).
3. **MM-467 — Wallet IA phase 3 — alarm takeover landing** (launch-decision ordering vs
   ceremony resume, §3).
4. **MM-468 — Wallet IA phase 4 — Add-identity situation question** replacing
   `mode_select`.
5. **MM-469 — DESIGN.md §5 amendment** (§6) — can ride with phase 1.
6. **MM-470 — Brass Console IA review** applying §1 (separate, later).

Phases 1–2 carry most of the value and are independent of 3–4. None of this changes
IPC contracts except the monitor-history read in phase 2.
