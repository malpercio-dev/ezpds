# Human Test Plan: Admin Multi-Server Support

Generated from `docs/implementation-plans/2026-07-06-admin-multi-server/test-requirements.md` after
coverage validation passed (16/16 automatable criteria covered; 57 Rust tests + 62 frontend tests green,
`pnpm check` clean).

## Prerequisites

- **Environment:** Mac + Xcode; run `just admin-dev` from repo root (simulator). Manual entry substitutes
  for the camera on the simulator (QR payload is JSON `{"relayUrl","pairingCode"}`).
- **Two live relays** — e.g. staging + a second local relay at `http://10.0.0.41:3000` (or a second
  staging env). "Unreachable" = stop one relay or disable the network mid-action.
- **Green automated gates first:** `cargo test -p admin-companion` (57 pass) and `pnpm check && pnpm test`
  in `apps/admin-companion` (0 check errors, 62 tests).
- Access to each relay's **device list** (to cross-check registrations/revocations server-side).

## Phase 1: Fresh install & legacy cleanup

| Step | Action | Expected |
|------|--------|----------|
| 1.1 | On a device/simulator that previously paired under the **old single-server** build, launch the multi-server build. Open Home. | Home shows the **unpaired** state — no stale server carried over. (AC1.3 on-device) |
| 1.2 | Where observable: pair a relay, then inspect that relay's device list. | The old (legacy) device entry is *not* silently reused; the re-pair registers a fresh device row. The stale entry can be revoked from the relay's device list. |

## Phase 2: Pair, switch, loud identity

| Step | Action | Expected |
|------|--------|----------|
| 2.1 | Pair relay **A** (staging) via manual entry; give nickname "staging". | Pair succeeds; Home shows A active. Relay A's device list gains this device's public key. (AC3.1) |
| 2.2 | On Home, tap the identity block → "Pair another server…". | Pair screen opens **while already paired** (no paired-guard blocks it). (AC3.1 reachability) |
| 2.3 | Pair relay **B** (second relay); nickname "prod". Return to Home. | B becomes active; A still listed in the switcher. (AC1.1 live, AC3.1) |
| 2.4 | Inspect **both** relays' device lists. | The **same** device public key (multibase) is registered with A and B — the global-device-key invariant end-to-end. (AC1.2 live) |
| 2.5 | On Home and Settings, inspect the active-server display. | Active **nickname** (display type) sits **above** the **host** (monospace) in the same fixed position under the title. Active vs inactive is signalled by **glyph + text + position**, never color alone. (AC2.2) |
| 2.6 | Enable grayscale / color-blind simulation; re-check 2.5. | Active/inactive still distinguishable without color. (AC2.2 — status never color-alone) |
| 2.7 | From the Home switcher, tap A's row. | Identity block updates to A; any stale claim code is **cleared**. (AC2.1 live) |
| 2.8 | Mint a claim code; cross-check on relay A. Switch to B, mint again; cross-check on relay B. | Each code lands on the **active** relay's server. (AC2.1 live) |
| 2.9 | On the claim-code reveal, read the server label adjacent to the code. | The active server's nickname + host render **directly above** the code — operator cannot misread which server the code is for. (AC2.2 reveal half) |

## Phase 3: Settings — list, rename, revoke, forget

| Step | Action | Expected |
|------|--------|----------|
| 3.1 | Open Settings. | **Every** paired server listed with nickname + host (mono). (AC3.2) |
| 3.2 | Expand a row, rename it, save. Then inspect that relay's device list. | Nickname updates locally; **no network call** — relay device list unchanged. Host still disambiguates. (AC3.2) |
| 3.3 | Expand a **reachable** server row → "Revoke on this server" → pass the biometric gate. Check the relay's device list. | Signed revoke reaches the relay (device **removed** from its list); entry removed locally. (AC3.3 live) |
| 3.4 | On another row → "Forget locally". Check that relay's device list. | Entry removed locally with **no** network call — the relay **still lists** the device. (AC3.3 live) |

## Phase 4: Ambiguous removal & explicit pick

| Step | Action | Expected |
|------|--------|----------|
| 4.1 | Pair **three** servers, one active. Remove the active one (revoke or forget). | Home enters the **explicit-pick** state: `pick a server` pending chip, **mint button hidden**, **forced-open switcher** that cannot be dismissed until a server is chosen. Active never silently lands on another relay. (AC2.5 UI half) |
| 4.2 | With **exactly two** paired and one active, remove the active one. | The **sole remaining** server is **auto-promoted** to active. (AC2.5 UI half) |

## End-to-End: Revoke against an unreachable relay (AC3.4)

**Purpose:** Validates the full failure→attribution→fallback path — the criterion's most
human-judgment-heavy behavior.

1. With server **B** paired, **stop relay B** (or disable the network).
2. In Settings, expand B's row → "Revoke on this server" → pass biometric.
3. Confirm the failure is reported **attributed to B's nickname + host** (not a generic error) — verify
   the attribution text names B specifically, styled by text + position.
4. Confirm B's **pairing is retained** in the list (not dropped).
5. Confirm a **"Forget on this device anyway"** local fallback is offered.
6. Take the fallback → confirm B is removed **locally** while its credential **remains valid server-side**
   (re-enable network, check B's device list still shows the device).

## End-to-End: Interop / device-key continuity (AC1.2 supplement)

**Purpose:** Confirms the single-global-key invariant survives re-pair and duplicate URLs.

1. Via the interop lane or a second re-pair, re-pair an **already-paired** relay URL.
2. Confirm a **distinct entry (new local id)** appends — both same-URL entries usable. (AC1.5 live)
3. Across all relays' device lists, confirm the registered device public key remains the **single global
   key** throughout.

## Human Verification Required

| Criterion | Why Manual | Steps |
|-----------|-----------|-------|
| AC2.2 | No DOM/component test harness (logic-only vitest by convention); the visual "reads loudly, never color-alone" claim needs human/grayscale inspection | Phase 2 steps 2.5–2.6, 2.9; Phase 3 step 3.1 |
| AC2.5 (UI half) | Screen-behavior (forced-open switcher, hidden mint button, pending chip) has no DOM test | Phase 4 steps 4.1–4.2 |
| AC1.2 (live) | Global-key-across-relays needs two live relays' device lists | Phase 2 step 2.4; interop E2E |
| AC3.1 (reachability) | "Pair reachable while paired" is a navigation/screen fact | Phase 2 step 2.2 |
| AC3.2 (UI) | Settings listing + in-row rename rendering | Phase 3 steps 3.1–3.2 |
| AC3.3 (live) | Biometric-gated revoke + server-side removal end-to-end | Phase 3 steps 3.3–3.4 |
| AC3.4 (E2E) | Pull-network → attributed failure → local-forget fallback | Revoke-unreachable E2E |

## Traceability

| Acceptance Criterion | Automated Test | Manual Step |
|----------------------|----------------|-------------|
| AC1.1 | `pairings.rs::append_makes_the_new_pairing_active_and_keeps_earlier_entries`, `keychain.rs::pairing_document_round_trips_two_relays` | Phase 2 (2.1–2.3) |
| AC1.2 | `keychain.rs::device_key_is_unchanged_by_pairing_document_writes` | Phase 2 step 2.4; interop E2E |
| AC1.3 | `keychain.rs::first_load_deletes_the_legacy_triple_and_yields_an_empty_document`, `legacy_cleanup_spares_device_key_and_biometric_accounts` | Phase 1 (1.1–1.2) |
| AC1.4 | `keychain.rs::corrupt_document_fails_loud_and_is_not_reset` (+ version/dangling variants), `pairings.rs::validate_rejects_*` | — (fully automated) |
| AC1.5 | `pairings.rs::append_allows_duplicate_relay_urls_under_distinct_ids`, `keychain.rs::re_pairing_the_same_relay_url_persists_both_entries` | Interop E2E step 2 |
| AC2.1 | `relay_client.rs::set_active_then_signed_request_targets_the_new_active_relay` | Phase 2 (2.7–2.8) |
| AC2.2 | `svelte-check`, `server-identity.test.ts` | Phase 2 (2.5–2.6, 2.9), Phase 3 (3.1) |
| AC2.3 | `pairings.rs::set_active_unknown_id_errors_and_leaves_selection_unchanged`, `relay_client.rs::set_active_pairing_unknown_id_is_no_such_pairing_and_selection_is_kept`, `no_such_pairing_serializes_with_its_screaming_snake_code` | — (fully automated) |
| AC2.4 | `relay_client.rs::resolve_active_is_not_paired_when_nothing_is_selected`, `resolve_active_is_not_paired_after_ambiguous_removal` | — (fully automated) |
| AC2.5 | `pairings.rs::removing_the_active_pairing_*` (3 tests), `relay_client.rs::unpair_with_two_remaining_clears_the_selection` | Phase 4 (4.1–4.2) |
| AC3.1 | `pairings.rs::append_makes_the_new_pairing_active_and_keeps_earlier_entries` + round-trip | Phase 2 (2.1–2.3) |
| AC3.2 | `relay_client.rs::rename_pairing_updates_only_the_nickname_locally` | Phase 3 (3.1–3.2) |
| AC3.3 | `relay_client.rs::revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path`, `unpair_removes_the_active_pairing_and_keeps_the_biometric_pref` | Phase 3 (3.3–3.4) |
| AC3.4 | `errors.test.ts` (UNREACHABLE classification), `revoke_self` remove-after-confirm structure | Revoke-unreachable E2E |
| AC4.1 | — (inspection: design-plan Appendix) | Read design-plan Appendix |
| AC5.1 | — (inspection: ADR-0017) | Read ADR 0017 + README row |
| AC6.1 | 4 golden envelope tests in the 57-test run + git-diff of golden bodies | — (automated + inspection) |
| AC6.2 | `relay_client.rs::revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path` | — (fully automated) |
