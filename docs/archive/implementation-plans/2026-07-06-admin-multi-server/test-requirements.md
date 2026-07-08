# Admin Multi-Server Support — Test Requirements

**Scope:** `docs/design-plans/2026-07-06-admin-multi-server.md` and its four implementation phases (`phase_01.md`–`phase_04.md`).

**Purpose:** Map every acceptance criterion (admin-multi-server.AC1.1 through admin-multi-server.AC6.2) to its verification: a fully-automated test, a split (backend automated + UI/live human), a human/simulator walkthrough, or verification-by-inspection. Each criterion below quotes the design plan's text literally. Every criterion appears exactly once.

## How each lane runs

**Rust lane** (`pairings.rs`, `keychain.rs`, `relay_client.rs` unit + integration tests). This worktree has no cargo on PATH; run through the main checkout's devenv, targeting this worktree's manifest (per `phase_01.md` → "Environment"):

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c \
  cargo test --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion
```

The `--manifest-path` is load-bearing — a bare `cargo test -p admin-companion` from the main checkout tests the wrong branch. Clippy and fmt run with the same wrapper (`phase_01.md` Task 6).

**Frontend lane** (`errors.test.ts`, `server-identity.test.ts`, `ipc.test.ts`, `biometric.test.ts` — logic-only vitest, per the app convention; plus svelte-check across every screen). Runs in the worktree's app directory (`pnpm install` once first, per `phase_03.md` → "Environment"):

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c sh -c \
  'cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/apps/admin-companion && pnpm install && pnpm check && pnpm test'
```

`pnpm test` = `vitest run`; `pnpm check` = svelte-check (type-checks every screen).

**Human lane.** On-simulator verification of the switcher, Pair-while-paired, and per-server Settings flows needs a Mac/Xcode (`just admin-dev`) — the app's standing demo gap (design plan → "On-simulator verification"). The app has **no Svelte component/DOM test harness** (logic-only vitest by convention), so visual and screen-behavior assertions are human-verified; the automatable slice is `pnpm check` passing plus the `/preview` route exercising the states. Collected into the ordered walkthrough at the end.

**Convention note.** The app's frontend test convention is logic-only vitest — there are no component-DOM tests, and Phase 3 deliberately does not introduce a harness for them. Screen rendering and interaction are therefore human-verified throughout; only pure logic (server identity, error classification) is unit-tested on the frontend.

---

## AC1 — Multiple pairings persist

| Criterion | Text | Verification |
|---|---|---|
| **AC1.1** | *Success: Pairing a second relay appends; both pairings retrievable with id, nickname, relayUrl, deviceId, deviceLabel* | **Automated (unit, two layers).** Document layer: `pairings.rs` test `append_makes_the_new_pairing_active_and_keeps_earlier_entries` (phase_01 Task 2) asserts every field of both entries. Persistence layer: `keychain.rs` test `pairing_document_round_trips_two_relays` (phase_01 Task 4) saves two pairings and reloads them with all five fields intact. |
| **AC1.2** | *Success: The device public key (multibase) is identical before and after pairing a second relay* | **Split.** Automated proxy (unit): `keychain.rs` test `device_key_is_unchanged_by_pairing_document_writes` (phase_01 Task 4) — captures `device_key::get_or_create().multibase` before/after two document writes and asserts equality (the document lives in its own keychain account and never touches the device-key accounts). Human/interop: the full pair-a-second-**live**-relay variant needs a live relay and is verified in the simulator walkthrough (H2) / interop lane. |
| **AC1.3** | *Success: First load with the legacy account triple present deletes the triple and yields an empty document* | **Automated (unit).** `keychain.rs` tests `first_load_deletes_the_legacy_triple_and_yields_an_empty_document` and `legacy_cleanup_spares_device_key_and_biometric_accounts` (phase_01 Task 4) — the first asserts the empty doc and all three legacy accounts read not-found; the second asserts cleanup is scoped to the triple (device key + biometric pref survive). |
| **AC1.4** | *Failure: An unparseable `admin-pairings` item surfaces a keychain error; the document is not reset and pairings are not silently lost* | **Automated (unit).** `keychain.rs` test `corrupt_document_fails_loud_and_is_not_reset` (phase_01 Task 4) — bad JSON yields `Err(CorruptPairingDoc)`, the stored bytes are unchanged, and a second load errors again (no silent reset). Sibling variants `unsupported_version_fails_loud` and `dangling_active_reference_fails_loud` cover the other fail-loud paths; `pairings.rs` `validate_rejects_unsupported_version` / `validate_rejects_dangling_active_reference` / `validate_rejects_duplicate_ids` (phase_01 Task 2) pin the underlying validation. |
| **AC1.5** | *Edge: Re-pairing an already-paired relay URL appends a distinct entry (new local id); both entries remain usable* | **Automated (unit, two layers).** Document layer: `pairings.rs` test `append_allows_duplicate_relay_urls_under_distinct_ids` (phase_01 Task 2). Persistence layer: `keychain.rs` test `re_pairing_the_same_relay_url_persists_both_entries` (phase_01 Task 4) — both same-URL entries persist and resolve individually by id. |

---

## AC2 — One-tap switch, loud identity

| Criterion | Text | Verification |
|---|---|---|
| **AC2.1** | *Success: After `set_active_pairing(B)`, `generate_claim_code()` produces a signed request against B's relayUrl carrying B's deviceId* | **Automated (integration).** `relay_client.rs` test `set_active_then_signed_request_targets_the_new_active_relay` (phase_02 Task 2) — seeds A then B, calls `set_active_pairing`, builds the claim-code request from `resolve_active()`, and asserts URL + `X-Admin-Device` header follow the active relay, with the signature verifying via `crypto::verify_p256_signature`. |
| **AC2.2** | *Success: Home and Settings render the active nickname + host by text + position (never color alone); the claim-code reveal shows the server identity adjacent to the code* | **Split.** Automated slice: structural — `ScreenShell` server-context slot renders nickname + host as stacked text in a fixed position (phase_03 Task 3), attribution is text+position in `ErrorState` (phase_03 Task 4), Home passes `server={identity}` and the reveal shows identity above the code (phase_03 Task 5), Settings passes the active identity (phase_03 Task 7); all guaranteed non-broken by `pnpm check` (phase_03 Task 8) and exercised in `/preview`. Human: the visual claim that identity reads loudly and status is never color-alone is verified on-simulator (walkthrough H3, H6) — no DOM test harness exists by convention. |
| **AC2.3** | *Failure: `set_active_pairing` with an unknown id returns `NO_SUCH_PAIRING`; active unchanged* | **Automated (unit, two layers).** Document layer: `pairings.rs` test `set_active_unknown_id_errors_and_leaves_selection_unchanged` (phase_01 Task 2) — unknown id `Err(NoSuchPairing)`, active still A. Command layer: `relay_client.rs` test `set_active_pairing_unknown_id_is_no_such_pairing_and_selection_is_kept` (phase_02 Task 2) — `Err(RelayClientError::NoSuchPairing)`, `list_pairings().active` still A; plus `no_such_pairing_serializes_with_its_screaming_snake_code` pins the `NO_SUCH_PAIRING` wire code. |
| **AC2.4** | *Failure: `generate_claim_code()` with no active pairing returns `NOT_PAIRED`* | **Automated (unit, two layers).** Wrapper layer (phase_01 Task 5): `generate_claim_code()` resolves the active pairing and returns `NotPaired` when none. Command layer: `relay_client.rs` tests `resolve_active_is_not_paired_when_nothing_is_selected` and `resolve_active_is_not_paired_after_ambiguous_removal` (phase_02 Task 2) — `generate_claim_code()`'s first step is `resolve_active()`, so both the empty-doc and cleared-after-ambiguous-removal cases yield `NotPaired` without a network. |
| **AC2.5** | *Edge: Removing the active pairing auto-promotes when exactly one remains; with two or more remaining, active is cleared and Home requires an explicit pick* | **Split.** Automated backend (unit): `pairings.rs` tests `removing_the_active_pairing_with_one_remaining_auto_promotes`, `removing_the_active_pairing_with_two_or_more_remaining_clears_active`, `removing_a_non_active_pairing_keeps_the_selection` (phase_01 Task 2), plus `relay_client.rs` `unpair_with_two_remaining_clears_the_selection` (phase_01 Task 5) and `resolve_active_is_not_paired_after_ambiguous_removal` (phase_02 Task 2). Human (UI half): Home's explicit-pick state (`needsPick` — pending `pick a server` chip, mint button hidden, forced-open switcher) is verified on-simulator (walkthrough H7) — the "Home requires an explicit pick" screen behavior has no DOM test. |

---

## AC3 — Pair and manage servers

| Criterion | Text | Verification |
|---|---|---|
| **AC3.1** | *Success: Pair is reachable while already paired; a successful pair appends and becomes active* | **Split.** Automated backend: `pair()` appends into the document and becomes active; the append-becomes-active semantics are pinned by `pairings.rs` `append_makes_the_new_pairing_active_and_keeps_earlier_entries` (phase_01 Task 2) and the persistence round-trip (phase_01 Task 4). Human (UI reachability): Pair has no paired-guard and "Pair another server…" is reachable from the Home switcher while paired (phase_03 Tasks 5–6); verified on-simulator (walkthrough H2). |
| **AC3.2** | *Success: Settings lists every pairing; `rename_pairing` updates the nickname locally without contacting any relay* | **Split.** Automated backend (unit): `relay_client.rs` test `rename_pairing_updates_only_the_nickname_locally` (phase_02 Task 2) — nickname changes, all other fields + active unchanged, unknown id `Err(NoSuchPairing)`; `rename_pairing` is a sync fn that structurally cannot await network I/O (the "without contacting any relay" guarantee). Human (UI): Settings listing every pairing and the in-row rename field are verified on-simulator (walkthrough H5). |
| **AC3.3** | *Success: `revoke_self(id)` sends the signed revoke to that pairing's relay and removes the entry; `unpair(id)` removes locally with no network call* | **Split.** Automated backend (integration/unit): `revoke_self`'s signed-revoke construction against the addressed pairing's relay/path is pinned by `relay_client.rs` `revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path` (phase_02 Task 2, also AC6.2); the local removal-after-confirm is guaranteed by `revoke_self`'s remove-only-after-`ensure_success` structure. `unpair(id)` local-only removal (no network — sync fn) is covered by `unpair_by_id_removes_only_that_entry_and_keeps_the_biometric_pref` (phase_02 Task 2). Human (UI): the biometric-gated Settings revoke button and local-forget button end-to-end against a live relay are verified on-simulator (walkthrough H8–H9). |
| **AC3.4** | *Failure: `revoke_self` against an unreachable relay reports the failure attributed to that server's nickname + host; the pairing is retained and local unpair is offered as fallback* | **Split (three slices).** (1) Rust retains the pairing on a failed revoke — behavior guaranteed by `revoke_self`'s remove-only-after-`ensure_success` structure (the local removal is unreachable when the network await errors) and covered by the classification tests below at the boundary. (2) Classification/attribution logic (unit): `errors.test.ts` additions (phase_03 Task 2) — the unreachable classification carries a recovery contract the UI attributes to a named server. (3) Rendering with nickname + host + local-unpair fallback: `ErrorState` server attribution and the `onforgetlocally` "Forget on this device anyway" fallback (phase_03 Tasks 4, 7), exercised in `/preview`; the end-to-end "pull the network, revoke, see attributed failure, fall back to local forget" flow is human — verified on-simulator (walkthrough H9). |

---

## AC4 — XRPC survey delivered

| Criterion | Text | Verification |
|---|---|---|
| **AC4.1** | *Success: This document's appendix lists follow-up recommendations tiered by server-side effort with route references* | **Verified by inspection — no test.** Satisfied by the design document itself: `docs/design-plans/2026-07-06-admin-multi-server.md` § "Appendix: XRPC follow-up recommendations (not in scope for this design)" lists nine candidate Linear issues tiered Tier 1 / Tier 2 / Tier 3 by server-side effort, each with route references (`crates/pds/src/app.rs`, `guards.rs`). Confirm by reading that appendix (phase_04 records it as verified-by-inspection). |

---

## AC5 — ADR recorded

| Criterion | Text | Verification |
|---|---|---|
| **AC5.1** | *Success: An ADR in `docs/architecture/decisions/` documents the one-global-device-key-across-N-relays trust model and the single-document keychain storage with Rust-owned active pointer* | **Verified by inspection — no test.** Satisfied by `docs/architecture/decisions/0017-multi-relay-admin-pairings.md` existing and covering **both** decisions (phase_04 Task 1). Inspection steps (phase_04 Task 1 → "Verification"): `ls` the ADR file; confirm its Decision section covers (a) one global Secure-Enclave device key registered independently with each relay and (b) the single versioned JSON keychain item with Rust-owned active pointer; confirm the `README.md` decisions-log table has the 0017 row and the relative links resolve. |

---

## AC6 — Cross-cutting

| Criterion | Text | Verification |
|---|---|---|
| **AC6.1** | *The golden signing-envelope tests pass unmodified (the envelope is untouched)* | **Automated (integration) + inspection.** The four golden tests — `build_registration_self_signature_verifies`, `signed_claim_code_request_is_accepted_by_relay_verifier`, `signed_self_revoke_request_is_accepted_and_path_bound`, `build_signed_request_binds_body_so_tamper_is_detected` — pass unmodified in `cargo test -p admin-companion` (their only change was a one-time Phase 1 fixture-setup swap to a `Pairing` literal; every sign-string, header assertion, and `verify_p256_signature` call is byte-identical — phase_01 Design deviation 3). Plus the phase_02 Task 3 git-diff check: `git diff <first-phase-2-commit>^..HEAD -- apps/admin-companion/src-tauri/src/relay_client.rs` must show **no** changes to the four golden test bodies in any Phase 2 commit. Both must hold. |
| **AC6.2** | *A request built from a *non-active* pairing verifies against `crypto::verify_p256_signature` with its own relay URL path-bound* | **Automated (integration).** `relay_client.rs` test `revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path` (phase_02 Task 2) — seeds A (active) and B (non-active), builds the request `revoke_self(B.id)` sends from B (fetched via `load_pairings().get(B.id)`), asserts the URL is B's relay + B's revoke path, the signature verifies via `crypto::verify_p256_signature` over the canonical envelope, and the same signature does **not** verify against a different device's revoke path. |

---

## Coverage summary

- **Fully automated:** AC1.1, AC1.3, AC1.4, AC1.5, AC2.1, AC2.3, AC2.4, AC6.1, AC6.2 (9).
- **Split (backend automated + UI/live human):** AC1.2, AC2.2, AC2.5, AC3.1, AC3.2, AC3.3, AC3.4 (7).
- **Verified by inspection (no test):** AC4.1, AC5.1 (2).

Total: 18 criteria, each mapped exactly once.

---

## Human verification checklist

An ordered on-simulator walkthrough (`just admin-dev`, Mac/Xcode required) plus interop, collecting every manual item above. Two live relays are needed (e.g. staging + a second local relay at `http://10.0.0.41:3000` or a second staging environment); "unreachable" is simulated by stopping one relay or disabling the network mid-action. Each step names the criteria it discharges.

1. **H1 — Fresh install / legacy cleanup (cross-check AC1.3).** On a device that previously paired under the old single-server build, launch the multi-server build. Confirm Home shows the unpaired state (no stale server), and — where observable — that the old device entry can be revoked from that relay's device list after re-pairing. (Automated coverage exists; this is the on-device confirmation.)

2. **H2 — Pair first relay, then a second while paired (AC1.2 live, AC3.1).** Pair relay A (staging) with a nickname. On Home, tap the identity block → "Pair another server…". Confirm Pair is reachable while already paired. Pair relay B with a distinct nickname. Confirm B becomes active on return to Home, and that A is still listed. Confirm (via each relay's device list) that the **same** device public key is registered with both A and B — the global-device-key invariant end-to-end.

3. **H3 — Loud active identity on every screen (AC2.2).** On Home and Settings, confirm the active nickname (display type) sits above the host (monospace) in the same fixed position under the title, and that active-vs-inactive is signalled by glyph + text + position, never color alone. Verify the same under simulated/actual color-blind or grayscale rendering.

4. **H4 — One-tap switch (AC2.1 live).** From the Home switcher, tap relay A's row. Confirm the identity block updates to A and any stale claim code is cleared. Mint a claim code; confirm it is minted against A (cross-check on relay A). Switch to B, mint again, confirm it lands on B.

5. **H5 — Settings lists every server; rename (AC3.2, AC2.2 Settings half).** Open Settings. Confirm every paired server is listed (nickname + host in mono). Expand a row, rename it, save; confirm the nickname updates locally with no network call (relay device list unchanged) and the host still disambiguates.

6. **H6 — Attributed claim-code reveal (AC2.2 reveal half).** On Home, mint a claim code; confirm the active server's nickname + host render directly adjacent to (above) the code so the operator cannot misread which server the code is for.

7. **H7 — Ambiguous removal requires an explicit pick (AC2.5 UI half).** With three servers paired and one active, remove the active one (revoke or forget). Confirm Home enters the explicit-pick state: `pick a server` pending chip, the mint button hidden, and a forced-open switcher that cannot be dismissed until a server is chosen — active never silently lands on another relay. Separately, with exactly two paired and one active, remove the active one and confirm the sole remaining server is auto-promoted.

8. **H8 — Revoke on a reachable server (AC3.3 live).** In Settings, expand a server row, tap "Revoke on this server", pass the biometric gate, and confirm the signed revoke reaches that relay (device removed from its list) and the entry is removed locally. Separately, tap "Forget locally" on another row and confirm it is removed with no network call (the relay still lists the device).

9. **H9 — Revoke against an unreachable relay (AC3.4 end-to-end).** Stop relay B (or disable the network). In Settings, attempt "Revoke on this server" for B. Confirm the failure is reported **attributed to B's nickname + host**, the pairing is **retained** in the list, and a local "Forget on this device anyway" fallback is offered. Take the fallback and confirm B is removed locally while its credential remains valid server-side.

10. **H10 — Interop / device-key continuity (AC1.2 live, supplement).** Via the interop lane or a second re-pair, confirm that re-pairing the same relay URL appends a distinct entry (new local id) and that the device public key registered across all relays remains the single global key throughout.
