# Admin Multi-Server Support — Phase 4: ADR and Documentation

**Goal:** Record the two ADR-worthy decisions (one global device key across N relays; single-document keychain storage with a Rust-owned active pointer) and bring the contract docs in line with the shipped behavior.

**Architecture:** One new ADR (`0017`, the next number in `docs/architecture/decisions/`) covering both decisions, added to the decisions README log per the documented procedure. `apps/admin-companion/AGENTS.md` gets its keychain-accounts, IPC-command, and pairing-contract sections rewritten to match the implemented surface, and one stale `pairing_state` example in `docs/security/tauri-ipc-boundary.md` is corrected.

**Tech Stack:** Markdown only. No code changes.

**Scope:** Phase 4 of 4 from `docs/design-plans/2026-07-06-admin-multi-server.md`. Depends on Phases 1–3 (documents shipped behavior).

**Codebase verified:** 2026-07-06

---

## Acceptance Criteria Coverage

This phase implements and verifies:

### admin-multi-server.AC5: ADR recorded
- **admin-multi-server.AC5.1 Success:** An ADR in `docs/architecture/decisions/` documents the one-global-device-key-across-N-relays trust model and the single-document keychain storage with Rust-owned active pointer

(admin-multi-server.AC4.1 — the XRPC survey appendix — is already satisfied by the design document itself: `docs/design-plans/2026-07-06-admin-multi-server.md` § "Appendix: XRPC follow-up recommendations". No task here; test-requirements records it as verified-by-inspection.)

**Out of scope for this phase:** moving the design/implementation/test plan triad to `docs/archive/` — per `docs/archive/README.md`, that happens after the work fully ships and stops being referenced, i.e. post-merge, not in this branch.

---

<!-- START_TASK_1 -->
### Task 1: ADR-0017 + decisions log entry

**Verifies:** admin-multi-server.AC5.1.

**Files:**
- Create: `docs/architecture/decisions/0017-multi-relay-admin-pairings.md`
- Modify: `docs/architecture/decisions/README.md` (the log table, lines 35–54)

**Implementation:**

Follow the repo's ADR conventions exactly (verified against ADR-0016 and `adr-template.md`): `# ADR-NNNN: Title` heading, then Status/Date/Deciders/Related bullets, then Context / Decision / Consequences / Alternatives considered. Keep it a page — link to the design plan for detail. Content to write (adjust prose freely; keep every decision point):

```markdown
# ADR-0017: One global admin device key across N relays, in a single pairing document

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** ezpds maintainers
- **Related:** [design plan](../../design-plans/2026-07-06-admin-multi-server.md) ·
  [ADR-0005](0005-functional-core-imperative-shell.md)

## Context

The Brass Console (admin-companion) originally bound the device to exactly one relay:
a fixed keychain triple (`admin-device-id`, `admin-relay-url`, `admin-device-label`)
overwritten on every pair. One operator running staging and production needs pairings
to several relays at once, which forces two decisions: how many device keys exist, and
how multi-pairing state is stored and selected.

## Decision

**One global Secure-Enclave device key, registered independently with each relay.**
The P-256 admin key is generated once per install and never leaves the Enclave. Pairing
with a relay registers the same public key with that relay; each relay only ever knows
"this public key is registered with me". Relays never learn about each other, and
revocation is per-relay by design: revoking the credential on staging leaves production
intact, and killing a lost device everywhere means revoking on each relay it was paired
with.

**All pairings in one versioned JSON keychain item with a Rust-owned active pointer.**
A single `kSecClassGenericPassword` item (account `admin-pairings`, service
`ezpds-admin-companion`) holds `{ version, active, pairings[] }`. Entries are keyed by a
locally generated UUID (relay-assigned device ids change on re-pair; URLs can repeat).
Every mutation is read-modify-write of the whole document ending in one atomic keychain
write, with the invariants (active always references an existing entry; auto-promote on
removal only when unambiguous) enforced by a pure Rust module. Zero-argument commands
like `generate_claim_code` resolve the active pairing on the Rust side, so the server
identity the UI shows and the server actually acted on cannot diverge. A document that
fails to parse or validate is a hard, loud error — never a silent reset, which would be
indistinguishable from a successful unpair. A future format change bumps `version` and
ships a deliberate migration.

## Consequences

- Pairing to N relays requires zero server-side changes: every route the app calls
  already accepts the device signature, and each relay independently registers the key.
- A compromise of the one device key is a compromise on every paired relay. Accepted:
  the key is hardware-held and non-exportable, and the response (per-relay revoke) is
  the same operation the app already ships.
- Whole-document rewrite per mutation is trivially cheap at the intended scale (2–5
  pairings) and avoids the orphan/partial-write risk of dynamic per-pairing keychain
  items, which would also need raw `security_framework_sys` enumeration.
- The legacy triple is deleted on first load with no migration: existing installs
  re-pair, and the stale relay-side device entry can be revoked from that relay's
  device list.

## Alternatives considered

- **Per-relay device keys.** Stronger isolation, but adds Enclave key management and a
  key-to-relay mapping for no operator-visible gain in a personal tool; the relay's
  registration model doesn't require it.
- **One keychain item per pairing.** The established `security_framework::passwords`
  surface has no enumeration; dynamic accounts would need `security_framework_sys` and
  invite orphaned items on partial writes.
- **Active pointer in UserDefaults.** Splits pairing state across two stores and breaks
  single-write atomicity; the app deliberately has no UserDefaults plumbing (the
  biometric preference already lives in the keychain).
- **Frontend-owned active selection.** Passing the target server from the UI into each
  command makes shown-vs-acted-on divergence possible; resolving in Rust makes it
  structurally impossible.
```

Then add the row to the log table in `docs/architecture/decisions/README.md` (same format as the 0016 row — number linked to the file, status, one-line decision), e.g.:

`| [0017](0017-multi-relay-admin-pairings.md) | Accepted | One global admin device key across N relays; pairings in a single versioned keychain document with a Rust-owned active pointer |`

(Match the table's actual column layout when editing — verify against the existing rows.)

**Verification:**

- `ls docs/architecture/decisions/0017-multi-relay-admin-pairings.md` succeeds.
- The README log table renders with the new row (inspect the markdown).
- Relative links resolve: `../../design-plans/2026-07-06-admin-multi-server.md` and `0005-functional-core-imperative-shell.md` exist from the ADR's directory.

**Commit:** `docs: ADR-0017 — multi-relay admin pairings trust and storage model`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Contract docs match the shipped surface

**Verifies:** Phase exit criterion "AGENTS.md contracts match the implemented command surface".

**Files:**
- Modify: `apps/admin-companion/AGENTS.md`
- Modify: `docs/security/tauri-ipc-boundary.md` (one stale example, line 105)

**Implementation:**

**A. `apps/admin-companion/AGENTS.md`** — update these regions (line numbers per 2026-07-06 verification; re-locate by content if drifted):

1. **Dates (lines 3–4):** `Last verified: 2026-07-06` / `Last updated: 2026-07-06`.
2. **"Current status" pairing/persistence bullet (lines 39–42)** — replace the `store_pairing`/`get_pairing`/`clear_pairing` triple description with the document model. New text (adjust to the file's voice):

   > - **Pairing + preference persistence** — `pairings.rs` (Functional Core: the versioned `PairingDoc` — `{ version, active, pairings[] }` with UUID-keyed entries and invariant-preserving append/rename/remove/set-active operations) persisted by `keychain.rs` `load_pairings`/`save_pairings` as ONE JSON item (account `admin-pairings`). Multiple relays pair simultaneously; one is *active* and all unqualified actions resolve it Rust-side. The legacy triple accounts (`admin-device-id`, `admin-relay-url`, `admin-device-label`) are deleted on first load (no migration — re-pair). `get/set_biometric_enabled` (`admin-biometric-enabled`, default on, survives unpair — a device setting) is unchanged.

3. **IPC command list (lines 43–45)** — replace with the shipped surface:

   > - IPC commands: `pair_device` (relay URL, pairing code, label, **nickname** — appends and becomes active), `list_pairings` (`{ active, pairings[] }`), `set_active_pairing(id)`, `rename_pairing(id, nickname)` (local-only), `generate_claim_code` (acts on the active pairing; `NOT_PAIRED` when none), `revoke_self(id)` (signed revoke on that pairing's relay, then local removal), `unpair(id)` (local-only forget), `biometric_enabled`, `set_biometric_enabled` (plus Phase 6's `get_or_create_device_key`, `sign_with_device_key`). `pairing_state` is gone — superseded by `list_pairings`.

4. **Contracts → keychain accounts (lines 68–73)** — rewrite to: device-key accounts unchanged; `admin-pairings` (the pairing document, replaces the triple); `admin-biometric-enabled` unchanged. State the removal semantics (removing the active entry auto-promotes only when exactly one remains, otherwise the selection clears and the UI requires an explicit pick), the fail-loud rule (a corrupt document errors through `RelayClientError::Keychain`, never a silent reset), the new `NO_SUCH_PAIRING` error code, and that "unpair" keeps the device key AND the biometric pref, both per-device state.

5. **Screens bullet (in "Current status")** — update the Home/Settings/Pair line: Home = biometric-gated claim code for the *active* server, tappable identity block → inline switcher (+ "Pair another server…"), explicit-pick state; Pair = QR/manual + required nickname, reachable while paired; Settings = per-server list (rename / revoke-on-server / forget-locally, biometric gate on revoke), global admin key + biometric toggle. Mention `src/lib/server-identity.ts` and the `ScreenShell` server slot in whichever bullet covers UI primitives.

Keep edits scoped to what changed — this file is a contract document, not a changelog. Do not add ticket references.

**B. `docs/security/tauri-ipc-boundary.md` line 105:** the parenthetical example of app-defined commands names `pairing_state`, which no longer exists — replace with `list_pairings` only (leave the surrounding sentence intact — `list_identities` in the same parenthetical is a legitimate identity-wallet example).

**Verification:**

Cross-check the documented command list against the code — from the worktree root:

```bash
grep -A 13 'generate_handler!' apps/admin-companion/src-tauri/src/lib.rs
grep -c 'pairing_state' apps/admin-companion/AGENTS.md docs/security/tauri-ipc-boundary.md
```

Expected: every command in `generate_handler!` appears in the AGENTS.md list and vice versa; the `pairing_state` grep only matches (if at all) in the "is gone — superseded" sentence, and matches nothing in `tauri-ipc-boundary.md`.

**Commit:** `docs(admin-companion): contracts for the multi-server pairing document and command surface`
<!-- END_TASK_2 -->
