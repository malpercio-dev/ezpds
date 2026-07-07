# Admin Companion Multi-Server Support Design

## Summary

Today the Brass Console (admin-companion) app can only be paired to one relay at a time: a fixed keychain triple (`admin-device-id`, `admin-relay-url`, `admin-device-label`) is overwritten on every pair. This design replaces that triple with a single versioned JSON document (`admin-pairings`) holding a list of pairings plus an `active` pointer, so the app can hold pairings to several relays (e.g. staging and production) at once while the Secure-Enclave device key stays global and is simply re-registered with each relay independently. All active-pairing resolution happens on the Rust side — zero-arg commands like `generate_claim_code()` always act on whatever pairing the document currently marks active — so the server identity shown on screen and the server actually acted on can never diverge.

The change is layered bottom-up across four phases: the storage model and its invariants (Phase 1), the IPC command surface and relay-client wiring that resolve pairings by id instead of a single global slot (Phase 2), the frontend switcher and per-server UI in Home/Pair/Settings (Phase 3), and finally an ADR plus updated contract docs (Phase 4). The signing envelope, error-serialization pattern, and keychain primitives are all reused unchanged, so this is additive within the existing functional-core/imperative-shell structure rather than a rework of how the app talks to relays. A separate appendix captures operator-feature ideas surfaced while surveying the PDS route surface, deliberately scoped out as future Linear issues rather than part of this build.

## Definition of Done

1. admin-companion can hold pairings to multiple relays simultaneously (each with its own operator nickname, device id, and device label; the Secure-Enclave device key stays global and is reused across relays). One pairing is "active" at a time.
2. A one-tap switcher changes the active server; the active server's nickname + host are loudly visible on every screen (text + position, never color alone). All relay actions (claim-code mint, device revoke, unpair) target the active pairing.
3. Pair flow supports adding another server while already paired; Settings lists all paired servers with per-server unpair/revoke.
4. The XRPC survey findings are delivered as written follow-up-issue recommendations (not built in this design).
5. ADR-worthy decisions (e.g., one global device key across N relays) get documented in `docs/architecture/decisions/`.

**Out of scope:** migration of existing single-server pairings (re-pair instead), new operator features from the XRPC survey, server-side changes (none appear needed).

**Context:** personal tool — one operator running 2–3 environments (e.g., staging + production). Switching is free (one tap) with loud active-server identity rather than confirmation friction, preserving the Brass Console "speed is the feature" brief.

## Acceptance Criteria

### admin-multi-server.AC1: Multiple pairings persist
- **admin-multi-server.AC1.1 Success:** Pairing a second relay appends; both pairings retrievable with id, nickname, relayUrl, deviceId, deviceLabel
- **admin-multi-server.AC1.2 Success:** The device public key (multibase) is identical before and after pairing a second relay
- **admin-multi-server.AC1.3 Success:** First load with the legacy account triple present deletes the triple and yields an empty document
- **admin-multi-server.AC1.4 Failure:** An unparseable `admin-pairings` item surfaces a keychain error; the document is not reset and pairings are not silently lost
- **admin-multi-server.AC1.5 Edge:** Re-pairing an already-paired relay URL appends a distinct entry (new local id); both entries remain usable

### admin-multi-server.AC2: One-tap switch, loud identity
- **admin-multi-server.AC2.1 Success:** After `set_active_pairing(B)`, `generate_claim_code()` produces a signed request against B's relayUrl carrying B's deviceId
- **admin-multi-server.AC2.2 Success:** Home and Settings render the active nickname + host by text + position (never color alone); the claim-code reveal shows the server identity adjacent to the code
- **admin-multi-server.AC2.3 Failure:** `set_active_pairing` with an unknown id returns `NO_SUCH_PAIRING`; active unchanged
- **admin-multi-server.AC2.4 Failure:** `generate_claim_code()` with no active pairing returns `NOT_PAIRED`
- **admin-multi-server.AC2.5 Edge:** Removing the active pairing auto-promotes when exactly one remains; with two or more remaining, active is cleared and Home requires an explicit pick

### admin-multi-server.AC3: Pair and manage servers
- **admin-multi-server.AC3.1 Success:** Pair is reachable while already paired; a successful pair appends and becomes active
- **admin-multi-server.AC3.2 Success:** Settings lists every pairing; `rename_pairing` updates the nickname locally without contacting any relay
- **admin-multi-server.AC3.3 Success:** `revoke_self(id)` sends the signed revoke to that pairing's relay and removes the entry; `unpair(id)` removes locally with no network call
- **admin-multi-server.AC3.4 Failure:** `revoke_self` against an unreachable relay reports the failure attributed to that server's nickname + host; the pairing is retained and local unpair is offered as fallback

### admin-multi-server.AC4: XRPC survey delivered
- **admin-multi-server.AC4.1 Success:** This document's appendix lists follow-up recommendations tiered by server-side effort with route references

### admin-multi-server.AC5: ADR recorded
- **admin-multi-server.AC5.1 Success:** An ADR in `docs/architecture/decisions/` documents the one-global-device-key-across-N-relays trust model and the single-document keychain storage with Rust-owned active pointer

### admin-multi-server.AC6: Cross-cutting
- **admin-multi-server.AC6.1:** The golden signing-envelope tests pass unmodified (the envelope is untouched)
- **admin-multi-server.AC6.2:** A request built from a *non-active* pairing verifies against `crypto::verify_p256_signature` with its own relay URL path-bound

## Glossary

- **Relay**: This app's term for a PDS (Personal Data Server) instance — the backend service the admin-companion app pairs with and issues signed operator requests to.
- **Pairing**: A local record binding this device to one relay: a relay URL, a relay-assigned device id, a device label, and (new) an operator-chosen nickname. Multiple pairings can now coexist.
- **Active pairing**: The single pairing, among possibly several stored, that unqualified commands (like minting a claim code) currently act on.
- **Secure Enclave**: Apple's hardware-isolated key store on iOS devices; the device's P-256 signing key is generated and held there and never leaves the chip.
- **Device key**: The P-256 keypair identifying this physical device to relays. In this design it is global — one key, registered independently with each paired relay — rather than per-pairing.
- **Keychain**: iOS's encrypted system credential store (`security_framework`), used here to persist the pairing document and other device secrets outside of app-readable plaintext storage.
- **`kSecClassGenericPassword`**: The iOS Keychain item class used for arbitrary app secrets (as opposed to internet passwords or certificates); the pairing document is stored as one item of this class.
- **Claim code**: A single-use code the operator mints (signed `POST /v1/accounts/claim-codes`) so a new user can claim an account on that relay. Distinct from a **pairing code**, which enrolls an admin device.
- **`require_admin` / `require_admin_token`**: Two distinct PDS route guards — `require_admin` accepts a device-signed request from a paired admin device, while `require_admin_token` requires a separate long-lived master admin token. The appendix's "Tier 2" items are routes that could be opened to devices by swapping one guard for the other.
- **XRPC**: The AT Protocol's RPC convention (namespaced HTTP methods like `com.atproto.admin.updateSubjectStatus`) used for many PDS admin routes surveyed in the appendix.
- **Golden tests**: Fixed-input/fixed-output regression tests that pin the exact bytes/structure of the signing envelope against the relay's own verifier, so any accidental encoding drift is caught immediately.
- **Functional core / imperative shell**: The codebase's architectural pattern separating pure logic (e.g. `build_*` request-construction functions, testable without I/O) from thin wrappers that perform actual side effects (network calls, keychain reads/writes).
- **IPC (Inter-Process Communication) / `invoke()`**: The Tauri mechanism by which the Svelte frontend calls into the Rust backend; `src/lib/ipc.ts` is this app's single chokepoint for all such calls.
- **ADR (Architecture Decision Record)**: A short document in `docs/architecture/decisions/` capturing a significant design decision and its rationale, for future reference.
- **Brass Console**: The design/product name for the admin-companion app's terminal-native operator UI register (as opposed to Obsign's consumer-facing lane).
- **`ScreenShell` / `DeviceRow` / `StatusChip` / `ErrorState` / `CodeOutput`**: Existing Svelte UI primitives in this app's design system that this design reuses or repurposes (e.g. `DeviceRow`, originally built but unused, is repurposed for the per-server Settings list).
- **DID (Decentralized Identifier)**: The AT Protocol's persistent identity string for an account, mentioned in the appendix as the lookup key an account-takedown UI would need.

## Architecture

Multi-server state lives entirely on the phone. Each relay only ever knows what it knows today — "this device public key is registered with me." Relays never learn about each other; production has no idea staging exists.

**Storage: one versioned JSON keychain item.** The three fixed pairing accounts (`admin-device-id`, `admin-relay-url`, `admin-device-label`) are replaced by a single `kSecClassGenericPassword` item, account `admin-pairings`, under the existing service `ezpds-admin-companion`:

```json
{
  "version": 1,
  "active": "b7e2…",
  "pairings": [
    {
      "id": "b7e2…",
      "nickname": "staging",
      "relayUrl": "https://…",
      "deviceId": "…",
      "deviceLabel": "Jacob's iPhone"
    }
  ]
}
```

- `id` is a locally generated UUID — stable even when the relay-assigned `deviceId` changes on re-pair or the URL is renamed. (Same move the PDS makes keying accounts on DID rather than handle.)
- Invariants enforced by the Rust module: `active` always references an existing pairing id, or is absent when the list is empty. Every mutation is read-modify-write of the whole document ending in one atomic keychain write (research: single-item update is the established multi-account pattern for 2–5 credential sets; multiple dynamic accounts would require raw `security_framework_sys` enumeration and carry partial-write/orphan risk).
- Nicknames are required but not unique; the host is always displayed beneath the nickname, so duplicates disambiguate themselves.
- The P-256 device key accounts are **unchanged and global** — one key, registered independently with each relay. `admin-biometric-enabled` is unchanged (device setting).
- Legacy state: on first `load_pairings()`, if the old triple exists it is deleted (one-time cleanup; no migration per the DoD). The stale relay-side device entry can be revoked from that relay's device list after re-pairing.

**Active-selection ownership: the Rust side.** The `active` pointer lives in the document, and signing actions resolve it in Rust. Zero-arg commands like `generate_claim_code()` act on the stored active pairing; the UI renders whatever Rust reports. The displayed server and the acted-on server therefore cannot diverge — that is the safety property behind "free switch, loud identity."

**IPC command surface** (all frontend access through `src/lib/ipc.ts`, per the app contract):

| Command | Change |
|---|---|
| `pair_device(relay_url, pairing_code, label, nickname)` | gains `nickname`; **appends** instead of overwriting; new pairing becomes active |
| `list_pairings() -> { active, pairings }` | new; replaces `pairing_state()` |
| `set_active_pairing(id)` | new; `NO_SUCH_PAIRING` on unknown id |
| `rename_pairing(id, nickname)` | new; local-only nickname edit |
| `generate_claim_code()` | unchanged signature; resolves active; `NOT_PAIRED` when none |
| `revoke_self(id)` / `unpair(id)` | gain `id`; server-revoke (or local forget) that pairing, remove from doc |

Removal semantics when the active pairing is removed: exactly one remaining → auto-promoted (unambiguous); two or more remaining → `active` cleared and the UI requires an explicit pick — never silently landing on production.

**Relay client.** `build_signed_request` already takes `&Pairing`; only the thin imperative wrappers change from "load the pairing" to "load the doc, resolve active/by-id." The signing envelope is untouched — zero server changes; the golden tests that pin the envelope against the relay's verifier stay green unmodified. Errors stay in the `RelayClientError` `{ code: "SCREAMING_SNAKE_CASE" }` pattern, adding `NO_SUCH_PAIRING`.

**Frontend.**
- *Loud identity:* `ScreenShell` gains an optional server-context slot under the title — active nickname in display type, host in monospace beneath (text + position, never color alone). Home and Settings always pass it; on the claim-code reveal the server identity sits adjacent to the code.
- *Switcher:* the Home identity block is tappable and expands into a dense inline list of paired servers (nickname + host; active row marked by glyph + "active" text). One tap calls `set_active_pairing`. Last row: "Pair another server…" → Pair. No modal choreography; the mint-a-code loop stays two taps when already on the right server.
- *Pair* gains the nickname `TextField` and is reachable while already paired; QR/manual flow unchanged.
- *Settings* gains a "Servers" section — one row per pairing (repurposing the unused `DeviceRow` pattern), expanding to rename / unpair / revoke-self, biometric gate on revoke as today. The single relay-URL display row goes away.
- State stays per-screen via IPC on mount (existing pattern; no global Svelte store) — `list_pairings()` is cheap local keychain I/O.

**Error handling.** `classifyRelayError`'s matrix (not-paired / clock-skew / revoked / unreachable) is kept; every classified failure is now attributed to a named server (nickname + host) in `ErrorState`. Revoked (403) is scoped to the pairing that produced it, with "Forget this server" / "Switch server" CTAs; no persisted revoked flag (the relay is the source of truth). A document that fails to parse fails loud through `RelayClientError::Keychain` — it does **not** silently reset to empty, since that would look identical to a successful unpair. A future `version: 2` is a deliberate migration, not a fallback.

## Existing Patterns

Investigation mapped the current single-server binding and this design follows the app's established patterns:

- **Keychain primitives reused:** `apps/admin-companion/src-tauri/src/keychain.rs` already exposes `store_item`/`get_item`/`delete_item` over `security_framework::passwords` with a `#[cfg(test)]` in-memory double. The pairing document composes from these; no new keychain plumbing.
- **Functional core / imperative shell:** pure `build_*` request construction in `relay_client.rs` verified by golden tests against `crypto::verify_p256_signature` (the relay's own verifier); reqwest only in thin wrappers. Preserved as-is.
- **Error serialization:** the single `RelayClientError` Serialize type with `SCREAMING_SNAKE_CASE` codes; keychain errors surface through `RelayClientError::Keychain`. New codes extend the same enum.
- **IPC boundary:** `src/lib/ipc.ts` is the only file calling `invoke()`; screens load state on mount (no global store). Both preserved.
- **Non-secret prefs in keychain:** the app has no UserDefaults plumbing; `admin-biometric-enabled` already lives in the keychain. The `active` pointer follows suit (embedded in the document), diverging from generic iOS advice (UserDefaults) in favor of codebase consistency and single-write atomicity.
- **Fail-closed credential state:** the old `store_pairing` wrote the relay URL last for fail-closed semantics; the new module keeps the "visibly broken over quietly wrong" stance (fail-loud on parse errors, no silent resets).
- **Brass Console UI:** existing primitives (`ScreenShell`, `DeviceRow`, `TextField`, `ErrorState`, `StatusChip`, `CodeOutput`) cover the switcher and server list; status by glyph + text + position, tokens only (`var(--color-*)` etc.), WCAG 2.2 AAA.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Pairing document storage
**Goal:** Multi-pairing persistence with Rust-owned active pointer.

**Components:**
- `PairingDoc` serde model + invariants in `apps/admin-companion/src-tauri/src/keychain.rs` — versioned JSON document under account `admin-pairings`; `load_pairings()` (with one-time legacy-triple cleanup) and `save_pairings()`; append/rename/remove/set-active operations with the removal semantics above.
- Removal of the legacy `store_pairing`/`get_pairing`/`clear_pairing` triple helpers.

**Dependencies:** None.

**Done when:** Tests pass covering admin-multi-server.AC1.1–AC1.5 and AC2.3–AC2.5 (document round-trip, invariants, legacy cleanup, corrupted-doc fail-loud, removal semantics) via the in-memory keychain double; `cargo test -p admin-companion` green on the host target.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: IPC commands and relay-client rewiring
**Goal:** The full multi-server command surface, signing against the resolved pairing.

**Components:**
- Command changes in `apps/admin-companion/src-tauri/src/lib.rs`: `pair_device` (nickname, append, becomes-active), `list_pairings`, `set_active_pairing`, `rename_pairing`, `revoke_self(id)`, `unpair(id)`; `pairing_state` removed.
- `apps/admin-companion/src-tauri/src/relay_client.rs` wrappers resolve active/by-id from the document; `NO_SUCH_PAIRING` added to `RelayClientError`.

**Dependencies:** Phase 1.

**Done when:** Tests pass covering admin-multi-server.AC2.1, AC2.4, AC3.1 (backend half), AC3.3, and the cross-cutting AC6.1–AC6.2 (golden envelope tests unmodified; a request built from a non-active pairing verifies against its own relay URL); `cargo test -p admin-companion` green.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Frontend — switcher, loud identity, screens
**Goal:** Operator-visible multi-server UX.

**Components:**
- `apps/admin-companion/src/lib/ipc.ts` — new command bindings and types.
- `src/lib/components/ui/ScreenShell.svelte` — optional server-context slot (nickname + monospace host).
- `src/routes/+page.svelte` (Home) — tappable identity block expanding to the inline switcher list + "Pair another server…"; no-active-selection state; claim-code reveal shows server identity adjacent to the code.
- `src/routes/pair/+page.svelte` — nickname field; reachable while paired.
- `src/routes/settings/+page.svelte` — "Servers" section with per-pairing rename/unpair/revoke (biometric-gated), replacing the single relay-URL row.
- `src/lib/errors.ts` / `ui/ErrorState.svelte` — server attribution (nickname + host) in classified failures; revoked-state CTAs ("Forget this server" / "Switch server").

**Dependencies:** Phase 2.

**Done when:** Tests/checks pass covering admin-multi-server.AC2.2, AC2.5 (UI half), AC3.1–AC3.2, AC3.4; `pnpm check` and the frontend unit-test lane green; `/preview` route exercises the new states.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: ADR and documentation
**Goal:** Decision record and contract docs match the shipped behavior.

**Components:**
- New ADR in `docs/architecture/decisions/` — the multi-relay trust model: one global device key registered independently with N relays (revocation per-relay by design), and single-document keychain storage with Rust-owned active pointer.
- `apps/admin-companion/CLAUDE.md` — keychain accounts, IPC command list, and contracts updated.

**Dependencies:** Phases 1–3 (documents shipped behavior).

**Done when:** admin-multi-server.AC5.1 satisfied (ADR exists and covers both decisions); CLAUDE.md contracts match the implemented command surface.
<!-- END_PHASE_4 -->

## Additional Considerations

**Re-pairing the same relay URL** appends a distinct pairing entry (new local id, new relay-assigned device id). Both sign validly; the operator removes the stale one from Settings. No same-URL dedup — URL identity is unreliable and the doc is small.

**No server-side changes.** All routes the app calls (`POST /v1/accounts/claim-codes`, `POST /v1/admin/devices`, `POST /v1/admin/devices/{id}/revoke`) are already `require_admin`-guarded and accept the device signature; each relay independently registers the same device public key.

**On-simulator verification** of the switcher and Pair-while-paired flow needs a Mac/Xcode (`just admin-dev`), consistent with the app's existing demo gap.

## Appendix: XRPC follow-up recommendations (not in scope for this design)

Survey of the PDS route surface (`crates/pds/src/app.rs:241-489`, auth in `crates/pds/src/auth/guards.rs`) for operator capabilities worth exposing in admin-companion, tiered by server-side effort. Each item is a candidate Linear issue.

**Tier 1 — zero server changes (routes already accept the admin device signature):**
1. *Device list + remote revoke screen.* `GET /v1/admin/devices` and `POST /v1/admin/devices/{id}/revoke` are device-signed today; the unused `DeviceRow` primitive was built for this. Delivers PRODUCT.md's "loss response" promise (revoke a lost device from another paired device).
2. *Account takedown/restore UI.* `POST /xrpc/com.atproto.admin.updateSubjectStatus` + `GET …/getSubjectStatus` are already device-signed (`app.rs:337-344`) with no app UI. Needs a DID input; pairs with a takedown-confirmation pattern (this is the one action deserving friction).

**Tier 2 — one-line guard swaps (`require_admin_token` → `require_admin`):**
3. *Per-account usage/storage dashboards.* `GET /v1/accounts/{id}/usage` (records/commits/blobs/last-active) and `GET /v1/accounts/{id}/storage` (quota, largest blob) are master-token-only for no structural reason.
4. *Invite-code minting from the phone.* `createInviteCode`/`createInviteCodes` — same swap, if invite codes matter alongside claim codes.

**Tier 3 — new server routes required:**
5. *Account listing/search* (only per-DID lookup exists today; an operator list needs pagination + status filters).
6. *Claim/invite-code inventory* (list/revoke unused codes; tables exist, no routes).
7. *Operator session/app-password revocation* for a compromised account (user-only today).
8. *Server health/metrics for operators* (DB row counts, firehose lag, blob GC state; no `/metrics` route).
9. *In-flight device-transfer visibility/cancel* (`transfers` table has no operator route).
