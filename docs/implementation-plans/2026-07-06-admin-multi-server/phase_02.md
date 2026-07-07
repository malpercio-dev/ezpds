# Admin Multi-Server Support — Phase 2: IPC Commands and Relay-Client Rewiring

**Goal:** The full multi-server command surface — `pair_device` gains `nickname`, `list_pairings`/`set_active_pairing`/`rename_pairing` are new, `revoke_self`/`unpair` become id-parameterized, `pairing_state` is removed — with all signing resolved against the document and a new `NO_SUCH_PAIRING` error code.

**Architecture:** Phase 1 already routes the imperative wrappers through `keychain::{load_pairings, save_pairings}` with zero-arg "act on active" semantics. This phase changes the *surface*: id-addressed operations (`revoke_self(id)`, `unpair(id)`, `set_active_pairing(id)`, `rename_pairing(id, nickname)`), a `PairingsState` IPC view (`{ active, pairings }`), and a `From<NoSuchPairing>` conversion into the existing `RelayClientError` SCREAMING_SNAKE_CASE serialization. A small private `resolve_active()` helper makes the active-resolution seam testable offline against the relay's own verifier. The signing envelope (`signing.rs`, `build_signed_request`, `build_registration`) is untouched.

**Tech Stack:** Rust, serde, Tauri v2 `#[tauri::command]`/`generate_handler!`, `crypto::verify_p256_signature` (dev-dependency, already used by the golden tests).

**Scope:** Phase 2 of 4 from `docs/design-plans/2026-07-06-admin-multi-server.md`. Depends on Phase 1 being complete and green.

**Codebase verified:** 2026-07-06

---

## Acceptance Criteria Coverage

This phase implements and tests:

### admin-multi-server.AC2: One-tap switch, loud identity
- **admin-multi-server.AC2.1 Success:** After `set_active_pairing(B)`, `generate_claim_code()` produces a signed request against B's relayUrl carrying B's deviceId
- **admin-multi-server.AC2.3 Failure:** `set_active_pairing` with an unknown id returns `NO_SUCH_PAIRING`; active unchanged *(this phase completes the command-level half; the document half was Phase 1)*
- **admin-multi-server.AC2.4 Failure:** `generate_claim_code()` with no active pairing returns `NOT_PAIRED`

### admin-multi-server.AC3: Pair and manage servers
- **admin-multi-server.AC3.1 Success:** Pair is reachable while already paired; a successful pair appends and becomes active *(this phase: backend half — `pair()` appends into the document and the append-becomes-active semantics are pinned by Phase 1's document tests; UI reachability is Phase 3)*
- **admin-multi-server.AC3.2 Success:** Settings lists every pairing; `rename_pairing` updates the nickname locally without contacting any relay *(this phase: backend half — the command exists, mutates only the local document, and is a sync fn that cannot perform network I/O; the Settings UI is Phase 3)*
- **admin-multi-server.AC3.3 Success:** `revoke_self(id)` sends the signed revoke to that pairing's relay and removes the entry; `unpair(id)` removes locally with no network call

### admin-multi-server.AC6: Cross-cutting
- **admin-multi-server.AC6.1:** The golden signing-envelope tests pass unmodified (the envelope is untouched) *(this phase makes zero edits to the four golden tests; their fixture-setup change happened once in Phase 1 — see phase_01.md, Design deviation 3)*
- **admin-multi-server.AC6.2:** A request built from a *non-active* pairing verifies against `crypto::verify_p256_signature` with its own relay URL path-bound

---

## Environment

Identical to Phase 1 — read `phase_01.md` → "Environment: how to build and test" before running anything. In short: no cargo on PATH in this worktree; run through the main checkout's devenv with `--manifest-path` pointing at THIS worktree's `Cargo.toml`; sandbox disabled; `keychain::clear_for_test()` first line of every keychain-touching test.

Repo hard rules (same as Phase 1): no ticket/AC references in source comments; `// pattern:` classification on files with runtime behavior; comments explain *why*.

Mid-branch note: after this phase, the frontend still calls the old command shapes (`pairing_state`, no-arg `revoke_self`/`unpair`, 3-arg `pair_device`); those screens are runtime-broken until Phase 3 lands in the same branch. That is expected — the crate and its tests are the gate for this phase, `pnpm check` is Phase 3's.

No server/API changes in this phase ⇒ no Bruno collection updates are needed (`just bruno-check` is unaffected).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Backend switchover — new command surface in `relay_client.rs` + `lib.rs`

**Verifies:** None directly (Task 2 adds the tests). This task is one atomic compile unit: the signature changes in `relay_client.rs` and their `lib.rs` callers must land together or the crate does not build.

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/pairings.rs` (add `PairingsState`)
- Modify: `apps/admin-companion/src-tauri/src/relay_client.rs`
- Modify: `apps/admin-companion/src-tauri/src/lib.rs`

**Implementation:**

**A. `pairings.rs` — the IPC view type.** Add after `PairingDoc`'s impl block (same file, so the private fields are accessible):

```rust
/// The IPC-facing view of the document: which pairing is active, and every pairing.
/// The storage `version` field stays internal to the keychain layer — the frontend
/// renders state, it never migrates formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingsState {
    pub active: Option<String>,
    pub pairings: Vec<Pairing>,
}

impl From<PairingDoc> for PairingsState {
    fn from(doc: PairingDoc) -> Self {
        PairingsState {
            active: doc.active,
            pairings: doc.pairings,
        }
    }
}
```

**B. `relay_client.rs` — error variant and conversion.** Add to `RelayClientError` (after the `NotPaired` variant, `relay_client.rs:34-37`):

```rust
    /// An id-addressed pairing operation referenced an id not present in the document
    /// (e.g. the entry was removed on another screen between load and tap).
    #[error("no such pairing")]
    NoSuchPairing,
```

and next to the existing `From` impls (`relay_client.rs:59-73`):

```rust
impl From<pairings::NoSuchPairing> for RelayClientError {
    fn from(_: pairings::NoSuchPairing) -> Self {
        RelayClientError::NoSuchPairing
    }
}
```

Adjust the import at the top: `use crate::pairings::{self, Pairing, PairingsState};` (replacing Phase 1's `use crate::pairings::Pairing;`).

**C. `relay_client.rs` — the active-resolution seam.** Add near `current_pairing`'s old location:

```rust
/// Resolve the pairing that unqualified operator actions (claim-code mint) target.
/// `NotPaired` covers both "never paired" and "the active entry was removed without an
/// explicit re-pick" — in either case there is no server this device may safely act on.
fn resolve_active() -> Result<Pairing, RelayClientError> {
    keychain::load_pairings()?
        .active_pairing()
        .cloned()
        .ok_or(RelayClientError::NotPaired)
}
```

Change `generate_claim_code()`'s first statement (the Phase 1 inline load/resolve) to:

```rust
    let pairing = resolve_active()?;
```

**D. `relay_client.rs` — local document commands:**

```rust
/// Everything the UI needs to render the switcher and Settings list. Local keychain
/// read only — never contacts a relay.
pub fn list_pairings() -> Result<PairingsState, RelayClientError> {
    Ok(keychain::load_pairings()?.into())
}

/// Select which pairing unqualified actions target. Local-only; the relays are never
/// told which of them is "active".
pub fn set_active_pairing(id: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.set_active(id)?;
    keychain::save_pairings(&doc)?;
    Ok(())
}

/// Update a pairing's operator-chosen nickname. Local-only display state.
pub fn rename_pairing(id: &str, nickname: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.rename(id, nickname)?;
    keychain::save_pairings(&doc)?;
    Ok(())
}
```

**E. `relay_client.rs` — id-parameterized revoke/unpair.** Replace the Phase 1 zero-arg bodies:

```rust
/// Revoke the given pairing's credential on ITS relay (a signed self-revoke against
/// that relay), then remove the entry locally. The signed request is built from the
/// addressed pairing — not the active one — so revoking a background server never
/// signs against the wrong relay. Local removal happens only after the relay confirms;
/// a failed revoke leaves the entry intact so the operator can retry or fall back to a
/// local-only [`unpair`].
pub async fn revoke_self(id: &str) -> Result<(), RelayClientError> {
    let doc = keychain::load_pairings()?;
    let pairing = doc.get(id).cloned().ok_or(RelayClientError::NoSuchPairing)?;
    let path = format!("/v1/admin/devices/{}/revoke", pairing.device_id);
    // The revoke endpoint takes no body. The signature still binds method + path, so a
    // signature minted to revoke this device cannot be replayed to revoke another.
    let signed = build_signed_request(&pairing, "POST", &path, b"", unix_now(), &fresh_nonce())?;
    ensure_success(send(signed).await?).await?;
    // Reload before mutating: the document may have gained entries during the network
    // round-trip, and a stale write would silently drop them.
    let mut doc = keychain::load_pairings()?;
    if doc.remove(id).is_ok() {
        keychain::save_pairings(&doc)?;
    }
    Ok(())
}

/// Forget the given pairing locally **without** contacting any relay — the fallback
/// when [`revoke_self`] can't reach that relay. The credential remains valid
/// server-side until revoked another way. The device key is preserved so a re-pair is
/// recognised by the same public key.
pub fn unpair(id: &str) -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    doc.remove(id)?;
    keychain::save_pairings(&doc)?;
    Ok(())
}
```

**F. `relay_client.rs` — delete `current_pairing()`** (superseded by `list_pairings`). Its Phase 1 test `current_pairing_returns_the_active_document_entry` is deleted in Task 2 alongside the test updates.

**G. `lib.rs` — the command surface.** Replace `pair_device`, delete `pairing_state`, update `revoke_self`/`unpair`, add the three new commands, and update `generate_handler!`:

```rust
/// Pair this device with a relay by claiming a pairing code (typed manually or scanned
/// from the operator's QR). Registers the device's public key, appends the pairing to
/// the document, and makes it the active selection; returns the relay-assigned
/// `device_id`. `nickname` is the operator's local display name for this relay — it is
/// stored on-device only and never sent to the relay.
#[tauri::command]
async fn pair_device(
    relay_url: String,
    pairing_code: String,
    label: String,
    nickname: String,
) -> Result<String, relay_client::RelayClientError> {
    relay_client::pair(&relay_url, &pairing_code, &label, &nickname).await
}

/// Every stored pairing plus the active selection — the state behind the Home switcher
/// and the Settings server list. Local keychain read; no network.
#[tauri::command]
fn list_pairings() -> Result<pairings::PairingsState, relay_client::RelayClientError> {
    relay_client::list_pairings()
}

/// Select the pairing that unqualified actions (claim-code mint) target.
#[tauri::command]
fn set_active_pairing(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::set_active_pairing(&id)
}

/// Rename a pairing's operator-chosen nickname. Local-only; no relay is contacted.
#[tauri::command]
fn rename_pairing(id: String, nickname: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::rename_pairing(&id, &nickname)
}

/// Revoke the given pairing's admin credential on its relay (signed self-revoke), then
/// remove the entry locally. Removal only after the relay confirms.
#[tauri::command]
async fn revoke_self(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::revoke_self(&id).await
}

/// Forget the given pairing locally without contacting its relay — the fallback when a
/// server-side self-revoke can't reach it.
#[tauri::command]
fn unpair(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::unpair(&id)
}
```

`generate_handler!` becomes:

```rust
        .invoke_handler(tauri::generate_handler![
            get_or_create_device_key,
            sign_with_device_key,
            pair_device,
            list_pairings,
            set_active_pairing,
            rename_pairing,
            generate_claim_code,
            revoke_self,
            unpair,
            biometric_enabled,
            set_biometric_enabled
        ])
```

Also delete `pairing_state`'s function and doc comment entirely, and update `lib.rs`'s module doc (lines 1-8) to mention the multi-relay pairing document.

**H. Compile fallout in tests:** Phase 1's `relay_client` tests `unpair_removes_the_active_pairing_and_keeps_the_biometric_pref` and `unpair_with_two_remaining_clears_the_selection` call the old zero-arg `unpair()` — they will not compile. Task 2 rewrites them for the by-id surface; to keep this task's verification meaningful, update the call sites mechanically here (pass the relevant entry's id) and let Task 2 do the full test pass.

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: compiles; all tests pass (golden tests untouched by this task).

**Commit:** `feat(admin-companion): multi-server IPC surface with id-addressed pairing commands`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Backend tests — switch semantics, non-active signing, error codes

**Verifies:** admin-multi-server.AC2.1, admin-multi-server.AC2.3 (command half), admin-multi-server.AC2.4, admin-multi-server.AC3.2 (backend half), admin-multi-server.AC3.3 (local halves + non-active signing), admin-multi-server.AC6.2.

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/relay_client.rs` (`mod tests`)

**Implementation:**

All tests go in `relay_client.rs`'s existing `mod tests`, start with `keychain::clear_for_test();`, and build fixtures with the Phase 1 `test_pairing` helper (extend it with an id parameter, or add a sibling helper `test_pairing_with_id(id, device_id, relay_url)` — the AC2.1/AC6.2 tests need two entries with known distinct ids). Seed documents by building a `PairingDoc` with `append` and persisting via `keychain::save_pairings`.

```rust
    #[test]
    fn set_active_then_signed_request_targets_the_new_active_relay() {
        // AC2.1's substance, offline. Seed: A ("https://staging.example", "device-a"),
        // then B ("https://prod.example", "device-b") — append order makes B active.
        // set_active_pairing(A.id); build a claim-code request from resolve_active():
        //   - url == "https://staging.example/v1/accounts/claim-codes"
        //   - X-Admin-Device header == "device-a"
        // Then set_active_pairing(B.id) and repeat:
        //   - url == "https://prod.example/v1/accounts/claim-codes"
        //   - X-Admin-Device header == "device-b"
        //   - the signature verifies via crypto::verify_p256_signature over the
        //     reconstructed sign string (same pattern as the golden claim-code test:
        //     fixed timestamp 1_700_000_000, fixed nonce, body br#"{"count":1}"#).
    }

    #[test]
    fn resolve_active_is_not_paired_when_nothing_is_selected() {
        // Empty document: resolve_active() matches Err(RelayClientError::NotPaired).
        // generate_claim_code()'s first step is resolve_active(), so this pins AC2.4's
        // NOT_PAIRED without needing a network or async runtime.
    }

    #[test]
    fn resolve_active_is_not_paired_after_ambiguous_removal() {
        // Seed A, B, C (active C). unpair(C.id) — two remain, selection cleared.
        // resolve_active() is Err(NotPaired): a cleared selection refuses to sign
        // rather than silently landing on some relay.
    }

    #[test]
    fn set_active_pairing_unknown_id_is_no_such_pairing_and_selection_is_kept() {
        // Seed A (active). set_active_pairing("nope") matches
        // Err(RelayClientError::NoSuchPairing); list_pairings().active is still A.id.
    }

    #[test]
    fn rename_pairing_updates_only_the_nickname_locally() {
        // Seed A. rename_pairing(A.id, "prod") succeeds; list_pairings() shows the new
        // nickname with relay_url/device_id/device_label/id unchanged, and active
        // unchanged. rename_pairing("nope", "x") is Err(NoSuchPairing).
        // (rename_pairing is a sync fn — it structurally cannot await a network call,
        // which is the "without contacting any relay" half of AC3.2.)
    }

    #[test]
    fn unpair_by_id_removes_only_that_entry_and_keeps_the_biometric_pref() {
        // set_biometric_enabled(false). Seed A, B (active B). unpair(A.id):
        // A gone, B still present AND still active, biometric pref still false.
        // unpair("nope") is Err(NoSuchPairing). unpair is sync — no network possible.
    }

    #[test]
    fn revoke_request_for_a_non_active_pairing_binds_its_own_relay_and_path() {
        // AC6.2. Seed A (active, "https://staging.example") and B (non-active,
        // "https://prod.example", device "device-b"). Build the exact request
        // revoke_self(B.id) sends, from B (the doc's non-active entry, fetched via
        // keychain::load_pairings().get(B.id)):
        //   build_signed_request(&b, "POST", "/v1/admin/devices/device-b/revoke",
        //                        b"", 1_700_000_000, "nonce-rev")
        //   - url == "https://prod.example/v1/admin/devices/device-b/revoke"
        //   - signature verifies via verify_p256_signature over the canonical envelope
        //   - the SAME signature does NOT verify against a different device's revoke
        //     path (reuse the path-binding assertion pattern from
        //     signed_self_revoke_request_is_accepted_and_path_bound).
    }

    #[test]
    fn no_such_pairing_serializes_with_its_screaming_snake_code() {
        // serde_json::to_value(RelayClientError::NoSuchPairing)["code"]
        //   == "NO_SUCH_PAIRING" — the IPC contract Phase 3's classifyRelayError keys on.
    }
```

Write every body out fully (the comments are the required assertions). Also in this task:
- Delete `current_pairing_returns_the_active_document_entry` (its subject was removed in Task 1).
- Fold Phase 1's two zero-arg unpair tests into the by-id versions above (delete the old ones — `unpair_by_id_removes_only_that_entry_and_keeps_the_biometric_pref` and `resolve_active_is_not_paired_after_ambiguous_removal` cover their assertions).

**Testing:** the AC mapping is annotated per test above. The four golden envelope tests are deliberately NOT touched in this task or any Phase 2 task (admin-multi-server.AC6.1).

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: all tests pass, including all four unmodified golden tests.

**Commit:** `test(admin-companion): cover active-switch signing, id-addressed commands, and NO_SUCH_PAIRING`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->
### Task 3: Phase verification — suite, clippy, fmt, golden-test diff check

**Verifies:** admin-multi-server.AC6.1 (golden tests unmodified this phase) and the phase exit criteria.

**Files:** None (verification only; fix anything it surfaces).

**Step 1: Full test run** — same command as phase_01.md Task 6 Step 1. Expected: 0 failures.

**Step 2: Golden tests untouched this phase.** From the worktree root:

```bash
git log --oneline -- apps/admin-companion/src-tauri/src/relay_client.rs
git diff <first-phase-2-commit>^..HEAD -- apps/admin-companion/src-tauri/src/relay_client.rs
```

Inspect the diff: the bodies of `build_registration_self_signature_verifies`, `signed_claim_code_request_is_accepted_by_relay_verifier`, `signed_self_revoke_request_is_accepted_and_path_bound`, and `build_signed_request_binds_body_so_tamper_is_detected` must show no changes in any Phase 2 commit. (Their one-time fixture-setup change was a Phase 1 commit; see phase_01.md Design deviation 3.)

**Step 3: Clippy + fmt** — same commands as phase_01.md Task 6 Steps 2–3 (touch sources first for clippy). Expected: clean.

**Step 4: Commit** — only if fixes were needed; keep them focused.
<!-- END_TASK_3 -->
