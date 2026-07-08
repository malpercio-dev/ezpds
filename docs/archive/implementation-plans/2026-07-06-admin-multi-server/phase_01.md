# Admin Multi-Server Support — Phase 1: Pairing Document Storage

**Goal:** Replace the single-pairing keychain triple with a versioned multi-pairing JSON document (`admin-pairings`) whose invariants are enforced by a pure Rust core, persisted atomically as one keychain item.

**Architecture:** A new Functional Core module `pairings.rs` holds the `Pairing`/`PairingDoc` model and all invariant-preserving operations (append/rename/remove/set-active with the removal-promotion semantics). `keychain.rs` gains thin `load_pairings()`/`save_pairings()` imperative wrappers (with one-time legacy-triple cleanup and fail-loud corruption handling) and loses the legacy `store_pairing`/`get_pairing`/`clear_pairing` helpers. Because deleting those helpers breaks their five call sites in `relay_client.rs`, this phase also mechanically rewires those call sites to the document (preserving today's zero-arg "act on the active pairing" semantics) so the crate compiles and stays green at the end of the phase. The *new* IPC command surface (nickname parameter, `list_pairings`, `set_active_pairing`, `rename_pairing`, id-parameterized revoke/unpair, `NO_SUCH_PAIRING`) is Phase 2.

**Tech Stack:** Rust (workspace toolchain 1.96.0), `serde`/`serde_json` (workspace deps), `uuid` v4 (workspace dep, already used for nonces), `security_framework` keychain via the existing `store_item`/`get_item`/`delete_item` primitives, thread-local in-memory keychain double for tests.

**Scope:** Phase 1 of 4 from `docs/design-plans/2026-07-06-admin-multi-server.md`.

**Codebase verified:** 2026-07-06

---

## Acceptance Criteria Coverage

This phase implements and tests:

### admin-multi-server.AC1: Multiple pairings persist
- **admin-multi-server.AC1.1 Success:** Pairing a second relay appends; both pairings retrievable with id, nickname, relayUrl, deviceId, deviceLabel
- **admin-multi-server.AC1.2 Success:** The device public key (multibase) is identical before and after pairing a second relay
- **admin-multi-server.AC1.3 Success:** First load with the legacy account triple present deletes the triple and yields an empty document
- **admin-multi-server.AC1.4 Failure:** An unparseable `admin-pairings` item surfaces a keychain error; the document is not reset and pairings are not silently lost
- **admin-multi-server.AC1.5 Edge:** Re-pairing an already-paired relay URL appends a distinct entry (new local id); both entries remain usable

### admin-multi-server.AC2: One-tap switch, loud identity
- **admin-multi-server.AC2.3 Failure:** `set_active_pairing` with an unknown id returns `NO_SUCH_PAIRING`; active unchanged *(this phase: the document-level operation errors and leaves `active` unchanged; the `NO_SUCH_PAIRING` IPC error code lands in Phase 2)*
- **admin-multi-server.AC2.4 Failure:** `generate_claim_code()` with no active pairing returns `NOT_PAIRED` *(this phase: the wrapper resolves the active pairing and returns `NotPaired` when none; the command-level test is Phase 2)*
- **admin-multi-server.AC2.5 Edge:** Removing the active pairing auto-promotes when exactly one remains; with two or more remaining, active is cleared and Home requires an explicit pick *(this phase: document semantics; the Home UI half is Phase 3)*

---

## Design deviations (deliberate, with rationale)

1. **`PairingDoc` lives in a new `pairings.rs`, not inside `keychain.rs`.** The design says "PairingDoc serde model + invariants in keychain.rs", but the crate's established seam separates pure logic from I/O (`signing.rs` is `// pattern: Functional Core`; `relay_client.rs` is `// pattern: Imperative Shell`). The document model and its operations are pure and deterministic (no keychain, no UUID generation), so they get their own Functional Core file; `keychain.rs` keeps only the load/save I/O.
2. **The five legacy-helper call sites in `relay_client.rs` are rewired in this phase**, not Phase 2. The design's Phase 1 removes `store_pairing`/`get_pairing`/`clear_pairing`, and their only production callers are in `relay_client.rs` — deferring the rewiring would leave the crate uncompilable at the end of Phase 1. The rewiring here is behavior-preserving (zero-arg commands still act on "the" pairing, now the active one); the command-surface changes stay in Phase 2.
3. **Golden signing-envelope tests: fixture setup changes, envelope logic does not.** admin-multi-server.AC6.1 says the golden tests "pass unmodified (the envelope is untouched)". The four golden tests currently create their fixture via `keychain::store_pairing(...)` + `get_pairing()` — the helpers this phase deletes — so their *setup lines* must mechanically change to construct a `Pairing` literal. Every sign-string construction, header assertion, and `verify_p256_signature` call stays byte-identical, which is the property the AC pins.
4. **`Pairing.label` is renamed to `Pairing.device_label`** (serialized `deviceLabel`) to match the design's document schema and AC1.1's field list. The relay wire contract is untouched: `RegistrationBody.label` (the `POST /v1/admin/devices` body field) keeps its name.

---

## Environment: how to build and test (READ THIS FIRST)

This worktree has **no cargo on PATH and no built `.devenv/`**. Run all cargo commands through the **main checkout's** devenv, targeting **this worktree's** manifest. These commands need network + broad fs access, so run them with the sandbox disabled.

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c \
  cargo test --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion
```

- **`--manifest-path` is load-bearing.** The main checkout is on a different branch. A bare `cargo test -p admin-companion` from the main checkout silently tests the WRONG branch and reports a meaningless green. Always pass the worktree manifest path.
- `nix develop`'s enterShell prints devenv/rustup lines before your command output — read past them.
- The shell cwd resets between Bash calls; prefix every invocation with `cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds &&`.
- The keychain test double is a `thread_local!` in-memory store: tests on different threads are isolated automatically, but sequential tests reusing the same OS thread share state. **Every test that touches the keychain must therefore call `keychain::clear_for_test()` as its first line** (all existing keychain/device-key/relay-client tests do).
- For clippy, `touch` the changed source files first so a warm `target/` re-analyzes them:

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c \
  cargo clippy --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion --all-targets -- -D warnings
```

Repo hard rules that apply to every task below:
- No ticket/AC references in source code comments (no `// MM-123`, no `// AC1.1`). AC traceability lives in this plan only.
- Every `.rs` file with runtime behavior carries a `// pattern:` comment (`Functional Core` / `Imperative Shell`).
- Code comments explain *why* in terms of the system, with periods at the end.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: `pairings.rs` — the pairing document Functional Core

**Verifies:** None directly (model groundwork; Task 2 adds the tests).

**Files:**
- Create: `apps/admin-companion/src-tauri/src/pairings.rs`
- Modify: `apps/admin-companion/src-tauri/src/lib.rs:10-13` (module declarations)

**Implementation:**

Create `apps/admin-companion/src-tauri/src/pairings.rs` with exactly this content:

```rust
// pattern: Functional Core
//
// The multi-relay pairing document: which relays this device is paired to, and which
// one unqualified operator actions (claim-code mint, self-revoke) currently target.
// Pure data and invariant-preserving operations only — Keychain persistence lives in
// `keychain::{load_pairings, save_pairings}`, and id generation (UUID) stays with the
// imperative callers in `relay_client`, so every function here is deterministic.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Storage-format version pinned into every persisted document. A future format change
/// bumps this and ships an explicit migration; an unknown version is a load error, never
/// a silent reset (see `keychain::load_pairings`).
pub const PAIRING_DOC_VERSION: u32 = 1;

/// A single relay pairing: the relay this device registered with, the id the relay
/// assigned, the label sent at registration, and the operator-chosen nickname.
///
/// `id` is a locally generated UUID and is the stable handle for every operation —
/// relay-assigned `device_id`s change on re-pair and relay URLs can repeat, so neither
/// is an identity. Serializes camelCase for both the keychain JSON document and IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub id: String,
    pub nickname: String,
    pub relay_url: String,
    pub device_id: String,
    pub device_label: String,
}

/// Returned by id-addressed operations when no pairing has the given id. Mapped to the
/// `NO_SUCH_PAIRING` IPC error code at the relay-client boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct NoSuchPairing;

/// The versioned pairing document persisted as one keychain item.
///
/// Invariant: `active` is always the id of an entry in `pairings`, or `None` (and it is
/// always `None` when the list is empty). All mutation goes through methods that
/// preserve the invariant; the fields stay private so a caller can never construct or
/// edit a document that violates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingDoc {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<String>,
    pairings: Vec<Pairing>,
}

impl PairingDoc {
    /// The document a device has before it ever pairs: current version, no entries.
    pub fn empty() -> Self {
        PairingDoc {
            version: PAIRING_DOC_VERSION,
            active: None,
            pairings: Vec::new(),
        }
    }

    /// All pairings, in insertion (pairing) order.
    pub fn pairings(&self) -> &[Pairing] {
        &self.pairings
    }

    /// The id of the active pairing, if one is selected.
    pub fn active_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// The active pairing itself, if one is selected.
    pub fn active_pairing(&self) -> Option<&Pairing> {
        self.active.as_deref().and_then(|id| self.get(id))
    }

    /// Look up a pairing by its local id.
    pub fn get(&self, id: &str) -> Option<&Pairing> {
        self.pairings.iter().find(|p| p.id == id)
    }

    /// Append a pairing and make it the active one. Duplicate relay URLs are allowed by
    /// design (re-pairing a relay appends a distinct entry); duplicate ids are not —
    /// callers generate a fresh UUID per pairing.
    pub fn append(&mut self, pairing: Pairing) {
        self.active = Some(pairing.id.clone());
        self.pairings.push(pairing);
    }

    /// Select the pairing that unqualified operator actions target. Unknown ids leave
    /// the current selection untouched.
    pub fn set_active(&mut self, id: &str) -> Result<(), NoSuchPairing> {
        if self.get(id).is_none() {
            return Err(NoSuchPairing);
        }
        self.active = Some(id.to_string());
        Ok(())
    }

    /// Update a pairing's operator-chosen nickname. Local-only: nicknames are display
    /// names and never leave the device.
    pub fn rename(&mut self, id: &str, nickname: &str) -> Result<(), NoSuchPairing> {
        let pairing = self
            .pairings
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        pairing.nickname = nickname.to_string();
        Ok(())
    }

    /// Remove a pairing, returning it. When the *active* entry is removed: exactly one
    /// remaining pairing is auto-promoted (the choice is unambiguous); with two or more
    /// remaining, `active` is cleared so the UI must ask for an explicit pick — the
    /// selection never silently lands on another relay.
    pub fn remove(&mut self, id: &str) -> Result<Pairing, NoSuchPairing> {
        let index = self
            .pairings
            .iter()
            .position(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        let removed = self.pairings.remove(index);
        if self.active.as_deref() == Some(id) {
            self.active = if self.pairings.len() == 1 {
                Some(self.pairings[0].id.clone())
            } else {
                None
            };
        }
        Ok(removed)
    }

    /// Validate the invariants of a document that arrived from outside this module
    /// (i.e. was deserialized from the keychain): supported version, unique ids, and an
    /// `active` that references an existing entry. Returns a description of the first
    /// violation, suitable for a fail-loud keychain error.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PAIRING_DOC_VERSION {
            return Err(format!(
                "unsupported pairing document version {}",
                self.version
            ));
        }
        let mut seen = HashSet::new();
        for pairing in &self.pairings {
            if !seen.insert(pairing.id.as_str()) {
                return Err(format!("duplicate pairing id {}", pairing.id));
            }
        }
        if let Some(active) = self.active.as_deref() {
            if self.get(active).is_none() {
                return Err(format!("active pairing {active} not present in document"));
            }
        }
        Ok(())
    }
}
```

Then declare the module in `apps/admin-companion/src-tauri/src/lib.rs`. The current declarations (lines 10–13) are:

```rust
mod device_key;
mod keychain;
mod relay_client;
mod signing;
```

Change to:

```rust
mod device_key;
mod keychain;
// Consumed by `keychain`/`relay_client` at the end of this change-set; the allow keeps
// intermediate commits clippy-clean and is removed when the relay client switches over.
#[allow(dead_code)]
mod pairings;
mod relay_client;
mod signing;
```

(The `#[allow(dead_code)]` + comment is removed in Task 5 when `keychain.rs` and `relay_client.rs` start using the module. Without it, the lib target fails `clippy -D warnings` because the module is not referenced yet.)

**Verification:**

Run (see Environment section for the wrapper):
`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: compiles; all existing tests still pass (no behavior changed yet).

**Commit:** `feat(admin-companion): add multi-relay pairing document model`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: `pairings.rs` unit tests — invariants and removal semantics

**Verifies:** admin-multi-server.AC1.1 (document half: append + retrieve all five fields), admin-multi-server.AC1.5 (document half: same-URL entries coexist under distinct ids), admin-multi-server.AC2.3 (document half: unknown id errors, active unchanged), admin-multi-server.AC2.5 (removal semantics: auto-promote vs clear).

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/pairings.rs` (append a `#[cfg(test)] mod tests` block at the end)

**Implementation:**

These are pure-function tests — no keychain, no `clear_for_test()` needed. Add a test helper and the tests below. Follow the file's existing test conventions (inline `mod tests`, descriptive snake_case names, expectation messages).

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn pairing(id: &str, nickname: &str, relay_url: &str) -> Pairing {
        Pairing {
            id: id.to_string(),
            nickname: nickname.to_string(),
            relay_url: relay_url.to_string(),
            device_id: format!("device-for-{id}"),
            device_label: "Operator iPhone".to_string(),
        }
    }

    #[test]
    fn empty_doc_has_no_active_and_no_pairings() { /* ... */ }

    #[test]
    fn append_makes_the_new_pairing_active_and_keeps_earlier_entries() {
        // Append A then B: both retrievable with id, nickname, relay_url, device_id,
        // device_label intact; active is B.
    }

    #[test]
    fn append_allows_duplicate_relay_urls_under_distinct_ids() {
        // Two entries with the same relay_url but different ids coexist; get() resolves
        // each by id; active is the later one.
    }

    #[test]
    fn set_active_switches_selection() { /* append A, B; set_active(A); active_pairing is A */ }

    #[test]
    fn set_active_unknown_id_errors_and_leaves_selection_unchanged() {
        // append A; set_active("nope") == Err(NoSuchPairing); active still A.
    }

    #[test]
    fn rename_updates_nickname_and_nothing_else() {
        // rename(A, "prod"); nickname changed; relay_url/device_id/device_label/id
        // unchanged; unknown id errors.
    }

    #[test]
    fn removing_the_active_pairing_with_one_remaining_auto_promotes() {
        // A, B active=B; remove(B) -> active becomes A.
    }

    #[test]
    fn removing_the_active_pairing_with_two_or_more_remaining_clears_active() {
        // A, B, C active=C; remove(C) -> active is None; A and B still present.
    }

    #[test]
    fn removing_a_non_active_pairing_keeps_the_selection() {
        // A, B active=B; remove(A) -> active still B.
    }

    #[test]
    fn removing_the_last_pairing_leaves_an_empty_doc() {
        // A active=A; remove(A) -> no pairings, active None.
    }

    #[test]
    fn remove_unknown_id_errors_and_changes_nothing() { /* ... */ }

    #[test]
    fn document_serializes_camel_case_and_omits_absent_active() {
        // serde_json::to_value(PairingDoc::empty()) has "version": 1, "pairings": []
        // and NO "active" key. A doc with one entry serializes the entry with keys
        // exactly: id, nickname, relayUrl, deviceId, deviceLabel.
    }

    #[test]
    fn document_round_trips_through_json() {
        // to_vec then from_slice reproduces an equal PairingDoc (two entries + active).
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        // Deserialize r#"{"version":2,"pairings":[]}"# then validate() -> Err mentioning
        // "version 2".
    }

    #[test]
    fn validate_rejects_dangling_active_reference() {
        // Deserialize a doc whose "active" id is not among the entries -> validate() Err.
    }

    #[test]
    fn validate_rejects_duplicate_ids() { /* two entries with the same id -> Err */ }
}
```

Write out each test fully (the comments above state the required behavior; the test bodies are direct translations). `validate_*` tests construct their docs via `serde_json::from_str::<PairingDoc>(...)` — that is the only way to obtain an invariant-violating document, which is exactly the point: they simulate a hand-edited or corrupted keychain item.

**Testing:** covers the AC list above at document level:
- admin-multi-server.AC1.1: `append_makes_the_new_pairing_active_and_keeps_earlier_entries` asserts every field of both entries.
- admin-multi-server.AC1.5: `append_allows_duplicate_relay_urls_under_distinct_ids`.
- admin-multi-server.AC2.3: `set_active_unknown_id_errors_and_leaves_selection_unchanged`.
- admin-multi-server.AC2.5: the three `removing_*` tests.

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: all new tests pass; existing tests unaffected.

**Commit:** `test(admin-companion): cover pairing document invariants and removal semantics`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: `keychain.rs` — document persistence with legacy cleanup and fail-loud corruption

**Verifies:** None directly (persistence groundwork; Task 4 adds the tests).

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/keychain.rs`

**Implementation:**

All changes are *additive* in this task — the legacy `store_pairing`/`get_pairing`/`clear_pairing` helpers and the old `Pairing` struct stay until Task 5 removes them together with their call sites.

1. **Add the document account constant** next to the existing pairing account constants (`keychain.rs:105-112`):

```rust
/// Keychain account holding the versioned multi-relay pairing document (JSON — see
/// `pairings::PairingDoc`). Replaces the single-pairing triple below.
const PAIRINGS_ACCOUNT: &str = "admin-pairings";
```

2. **Add a fail-loud corruption variant** to `KeychainError` (`keychain.rs:29-41`):

```rust
/// The persisted pairing document exists but cannot be used (bad JSON, unknown
/// version, or violated invariants). Deliberately NOT recovered by resetting to an
/// empty document — a silent reset would be indistinguishable from a successful
/// unpair. Surfaces to the frontend through `RelayClientError::Keychain`.
#[error("pairing document is corrupt: {0}")]
CorruptPairingDoc(String),
```

Extend `is_not_found` (`keychain.rs:88-95`) with a `KeychainError::CorruptPairingDoc(_) => false` arm.

3. **Add the load/save wrappers** (place them after the legacy pairing section, before the biometric section). Import `crate::pairings::PairingDoc` at the top of the file.

```rust
/// Load the pairing document, or an empty one if none has been written yet.
///
/// First load on a device that paired before the multi-server document existed also
/// deletes the legacy single-pairing triple (`admin-device-id`, `admin-relay-url`,
/// `admin-device-label`) — a one-time cleanup, not a migration: the operator re-pairs,
/// and the stale relay-side device entry can be revoked from that relay's device list.
/// A document that exists but does not parse or validate is a hard error; pairings are
/// never silently reset, because an empty document is indistinguishable from a
/// successful unpair.
pub fn load_pairings() -> Result<PairingDoc, KeychainError> {
    match get_item(PAIRINGS_ACCOUNT) {
        Ok(bytes) => {
            let doc: PairingDoc = serde_json::from_slice(&bytes)
                .map_err(|e| KeychainError::CorruptPairingDoc(e.to_string()))?;
            doc.validate().map_err(KeychainError::CorruptPairingDoc)?;
            Ok(doc)
        }
        Err(e) if is_not_found(&e) => {
            clear_legacy_pairing_triple()?;
            Ok(PairingDoc::empty())
        }
        Err(e) => Err(e),
    }
}

/// Persist the whole pairing document as one keychain write. Every mutation is
/// read-modify-write of the full document ending here, so a reader never observes a
/// half-updated pairing list.
pub fn save_pairings(doc: &PairingDoc) -> Result<(), KeychainError> {
    let bytes = serde_json::to_vec(doc).expect("PairingDoc serializes");
    store_item(PAIRINGS_ACCOUNT, &bytes)
}

/// Delete the pre-multi-server pairing triple if present. Idempotent: absent items are
/// skipped, so repeated loads on a fresh install are no-ops.
fn clear_legacy_pairing_triple() -> Result<(), KeychainError> {
    for account in [DEVICE_ID_ACCOUNT, RELAY_URL_ACCOUNT, LABEL_ACCOUNT] {
        match delete_item(account) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
```

4. **Keep clippy green pre-wiring:** until Task 5 wires `relay_client.rs` to these functions, annotate each of `load_pairings`, `save_pairings`, and `clear_legacy_pairing_triple` with:

```rust
// Wired in by the relay-client switchover later in this change-set.
#[allow(dead_code)]
```

(Removed in Task 5. This mirrors the file's existing `#[allow(dead_code)]` precedent on `delete_item`.)

Note the required `use crate::pairings::PairingDoc;` import means the `#[allow(dead_code)]` on `mod pairings;` in `lib.rs` now only papers over the *operations* that are still unused — leave it in place until Task 5.

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: compiles, all existing tests pass.

**Commit:** `feat(admin-companion): persist the pairing document in the keychain with legacy cleanup`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: `keychain.rs` persistence tests — round-trip, legacy cleanup, fail-loud

**Verifies:** admin-multi-server.AC1.1 (persistence half), admin-multi-server.AC1.2, admin-multi-server.AC1.3, admin-multi-server.AC1.4, admin-multi-server.AC1.5 (persistence half).

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/keychain.rs` (extend the existing `#[cfg(test)] mod tests`)

**Implementation:**

Add these tests to the existing `mod tests` in `keychain.rs`. Every test starts with `clear_for_test();` (mandatory — the in-memory store is thread-local and shared across sequential tests). Use `crate::pairings::{Pairing, PairingDoc}`. Reuse Task 2's field pattern for building `Pairing` values (a small local helper is fine).

```rust
#[test]
fn load_pairings_is_empty_on_a_fresh_install() {
    // clear_for_test(); load_pairings() == PairingDoc::empty(): no entries, no active.
}

#[test]
fn pairing_document_round_trips_two_relays() {
    // Append two pairings (different relay URLs) to an empty doc, save_pairings, then
    // load_pairings. Assert BOTH entries come back with id, nickname, relay_url,
    // device_id, device_label all intact, and active is the second entry's id.
}

#[test]
fn re_pairing_the_same_relay_url_persists_both_entries() {
    // Two entries with the SAME relay_url but distinct ids; save; load; both present
    // and individually retrievable by id.
}

#[test]
fn first_load_deletes_the_legacy_triple_and_yields_an_empty_document() {
    // Seed the legacy accounts directly:
    //   store_item(DEVICE_ID_ACCOUNT, b"device-old")
    //   store_item(RELAY_URL_ACCOUNT, b"https://old.example")
    //   store_item(LABEL_ACCOUNT, b"Old iPhone")
    // load_pairings() returns an empty doc, AND all three legacy accounts now read as
    // not-found via get_item (use is_not_found on the error).
}

#[test]
fn legacy_cleanup_spares_device_key_and_biometric_accounts() {
    // Seed the legacy triple AND set_biometric_enabled(false) AND create the device key
    // (device_key::get_or_create()). load_pairings(). The biometric pref still reads
    // false and get_or_create() returns the same multibase — cleanup is scoped to the
    // triple only.
}

#[test]
fn corrupt_document_fails_loud_and_is_not_reset() {
    // store_item(PAIRINGS_ACCOUNT, b"{ not json");
    // load_pairings() is Err(KeychainError::CorruptPairingDoc(_)).
    // The stored bytes are UNCHANGED (get_item(PAIRINGS_ACCOUNT) still returns the
    // original garbage) and a second load_pairings() errors again — no silent reset.
}

#[test]
fn unsupported_version_fails_loud() {
    // store_item(PAIRINGS_ACCOUNT, br#"{"version":2,"pairings":[]}"#);
    // load_pairings() is Err(CorruptPairingDoc) whose message mentions "version".
}

#[test]
fn dangling_active_reference_fails_loud() {
    // Store a syntactically valid doc whose "active" id has no matching entry;
    // load_pairings() is Err(CorruptPairingDoc).
}

#[test]
fn device_key_is_unchanged_by_pairing_document_writes() {
    // let before = device_key::get_or_create().expect("key").multibase;
    // Append + save one pairing, then append + save a second (different relay URL).
    // let after = device_key::get_or_create().expect("key").multibase;
    // assert_eq!(before, after) — the document lives in its own account and never
    // touches the device-key accounts.
}
```

Write each body out fully; the comments state the exact required assertions.

**Testing:** maps to the AC list:
- admin-multi-server.AC1.1: `pairing_document_round_trips_two_relays`.
- admin-multi-server.AC1.2: `device_key_is_unchanged_by_pairing_document_writes` (unit-level proxy: the full pair-flow variant needs a live relay and is covered by the interop/manual lane).
- admin-multi-server.AC1.3: `first_load_deletes_the_legacy_triple_and_yields_an_empty_document` plus the sparing test.
- admin-multi-server.AC1.4: `corrupt_document_fails_loud_and_is_not_reset` (+ version/dangling-active variants).
- admin-multi-server.AC1.5: `re_pairing_the_same_relay_url_persists_both_entries`.

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: all tests pass.

**Commit:** `test(admin-companion): cover pairing document persistence, legacy cleanup, and fail-loud corruption`
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 5-6) -->

<!-- START_TASK_5 -->
### Task 5: Switch `relay_client.rs`/`lib.rs` to the document; delete the legacy triple helpers

**Verifies:** admin-multi-server.AC2.4 (wrapper half: no active pairing ⇒ `NotPaired`), admin-multi-server.AC2.5 (unpair path exercises document removal). Also preserves admin-multi-server.AC6.1's substance: the golden tests' envelope logic is untouched (fixture setup only — see Design deviation 3).

**Files:**
- Modify: `apps/admin-companion/src-tauri/src/relay_client.rs`
- Modify: `apps/admin-companion/src-tauri/src/keychain.rs` (deletions + doc-comment updates)
- Modify: `apps/admin-companion/src-tauri/src/lib.rs` (nickname pass-through, `mod pairings;` allow removal)

**Implementation:**

**A. `relay_client.rs` production changes:**

1. Change the import at line 18 from `use crate::keychain::Pairing;` to `use crate::pairings::Pairing;`.

2. `pair()` (lines 164-184): add a `nickname: &str` parameter after `label`, and replace the `keychain::store_pairing(...)` call (line 182) with document append-and-save. The relay-assigned device id is still returned. Generated UUID stays here in the imperative shell (the document operations are deterministic):

```rust
pub async fn pair(
    relay_url: &str,
    pairing_code: &str,
    label: &str,
    nickname: &str,
) -> Result<String, RelayClientError> {
    let body = build_registration(pairing_code, label, unix_now())?;
    let url = join_url(relay_url, "/v1/admin/devices")?;

    let response = http_client()
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(unreachable)?;

    let device_id = parse_success::<RegisterDeviceResponse>(response)
        .await?
        .device_id;
    let mut doc = keychain::load_pairings()?;
    doc.append(Pairing {
        id: uuid::Uuid::new_v4().to_string(),
        nickname: nickname.to_string(),
        relay_url: relay_url.to_string(),
        device_id: device_id.clone(),
        device_label: label.to_string(),
    });
    keychain::save_pairings(&doc)?;
    Ok(device_id)
}
```

(Keep the existing doc comment, updated: "persists the pairing as a new entry in the pairing document and makes it active".)

3. `generate_claim_code()` (line 189): replace the `get_pairing` line with:

```rust
    let doc = keychain::load_pairings()?;
    let pairing = doc
        .active_pairing()
        .cloned()
        .ok_or(RelayClientError::NotPaired)?;
```

Everything below (body serialization, `build_signed_request(&pairing, ...)`, send, parse) is unchanged.

4. `current_pairing()` (lines 211-213): now returns the *active* pairing:

```rust
/// The pairing unqualified actions currently target, or `None` when the device has no
/// active selection (never paired, or the active entry was removed without a pick).
pub fn current_pairing() -> Result<Option<Pairing>, RelayClientError> {
    Ok(keychain::load_pairings()?.active_pairing().cloned())
}
```

5. `revoke_self()` (lines 221-230): resolve the active pairing, send the signed revoke, then **reload** the document before removing — the network await is long, and re-reading avoids clobbering a pairing appended while the request was in flight:

```rust
pub async fn revoke_self() -> Result<(), RelayClientError> {
    let doc = keychain::load_pairings()?;
    let pairing = doc
        .active_pairing()
        .cloned()
        .ok_or(RelayClientError::NotPaired)?;
    let path = format!("/v1/admin/devices/{}/revoke", pairing.device_id);
    // The revoke endpoint takes no body. The signature still binds method + path, so a
    // signature minted to revoke this device cannot be replayed to revoke another.
    let signed = build_signed_request(&pairing, "POST", &path, b"", unix_now(), &fresh_nonce())?;
    ensure_success(send(signed).await?).await?;
    // Reload before mutating: the document may have gained entries during the network
    // round-trip, and a stale write would silently drop them.
    let mut doc = keychain::load_pairings()?;
    if doc.remove(&pairing.id).is_ok() {
        keychain::save_pairings(&doc)?;
    }
    Ok(())
}
```

(Keep the existing doc comment about local state clearing only after the relay confirms.)

6. `unpair()` (lines 236-239): remove the active entry locally, idempotent as before:

```rust
pub fn unpair() -> Result<(), RelayClientError> {
    let mut doc = keychain::load_pairings()?;
    if let Some(id) = doc.active_id().map(str::to_string) {
        doc.remove(&id)
            .expect("active id always resolves to an entry");
        keychain::save_pairings(&doc)?;
    }
    Ok(())
}
```

**B. `relay_client.rs` golden-test fixture swap (envelope logic untouched):**

In `mod tests`, add one helper next to the existing `decode_sig`/`header` helpers:

```rust
    /// A document-backed pairing fixture. The golden envelope tests below predate the
    /// multi-relay document; only this setup changed when the legacy triple helpers were
    /// removed — every sign-string, header assertion, and relay-verifier call is
    /// unchanged, which is what pins the envelope.
    fn test_pairing(device_id: &str, relay_url: &str) -> Pairing {
        Pairing {
            id: "test-pairing-id".to_string(),
            nickname: "test".to_string(),
            relay_url: relay_url.to_string(),
            device_id: device_id.to_string(),
            device_label: "Operator iPhone".to_string(),
        }
    }
```

Then in the three tests that pair (`signed_claim_code_request_is_accepted_by_relay_verifier` lines 417-419, `signed_self_revoke_request_is_accepted_and_path_bound` lines 465-467, `build_signed_request_binds_body_so_tamper_is_detected` lines 510-511), replace the two setup lines

```rust
        keychain::store_pairing("device-xyz", "https://relay.example", "Operator iPhone")
            .expect("store pairing");
        let pairing = keychain::get_pairing().unwrap().unwrap();
```

with

```rust
        let pairing = test_pairing("device-xyz", "https://relay.example");
```

(using each test's original device id). **Do not touch any other line of those tests** — every assertion, sign-string, and `verify_p256_signature` call stays byte-identical. `build_registration_self_signature_verifies` doesn't use a pairing and is fully unmodified.

**C. New `relay_client.rs` tests** (same `mod tests`):

```rust
    #[test]
    fn current_pairing_returns_the_active_document_entry() {
        // clear_for_test(); save a doc with two entries (active = second via append
        // order); current_pairing() returns the second entry.
    }

    #[test]
    fn unpair_removes_the_active_pairing_and_keeps_the_biometric_pref() {
        // clear_for_test(); set_biometric_enabled(false); save a doc with ONE entry;
        // unpair(); load_pairings() is empty with no active; biometric pref still false.
        // A second unpair() is a no-op success (idempotent).
    }

    #[test]
    fn unpair_with_two_remaining_clears_the_selection() {
        // Three entries, active = third. unpair() removes it; the two remaining
        // entries persist and active is None (the UI must ask for an explicit pick).
    }
```

**D. `keychain.rs` deletions and cleanup:**

1. Delete `store_pairing` (lines 125-136), `get_pairing` (lines 138-157), `clear_pairing` (lines 159-172), and the `Pairing` struct (lines 114-123).
2. Delete their tests: `store_and_get_pairing_round_trips`, `get_pairing_is_none_when_unpaired`, `get_pairing_is_none_when_only_one_half_present`, `get_pairing_tolerates_missing_label`, `clear_pairing_forgets_and_is_idempotent`, and `biometric_pref_survives_unpair` (its behavior is now covered by the new `relay_client` unpair test).
3. Keep `DEVICE_ID_ACCOUNT`/`RELAY_URL_ACCOUNT`/`LABEL_ACCOUNT` — `clear_legacy_pairing_triple` and the Task 4 tests use them. Update their doc comments to say they are legacy accounts retained only for one-time cleanup.
4. Update the module doc (lines 1-13) and the "Pairing state" section comment (lines 97-103) to describe the pairing document (multi-relay, one JSON item, active pointer) instead of the Phase-7 triple.
5. Remove the `#[allow(dead_code)]` annotations added in Task 3 (the functions are now used by `relay_client`), and `get_string`'s doc stays as-is (still used by the biometric pref).

**E. `lib.rs` changes:**

1. Remove the `#[allow(dead_code)]` + comment from `mod pairings;` (added in Task 1).
2. `pair_device` (lines 33-40): pass an empty nickname through for now — the IPC surface gains the real `nickname` argument in the next phase:

```rust
async fn pair_device(
    relay_url: String,
    pairing_code: String,
    label: String,
) -> Result<String, relay_client::RelayClientError> {
    // The nickname argument arrives with the multi-server IPC surface; until then a
    // pairing created through this command carries an empty nickname.
    relay_client::pair(&relay_url, &pairing_code, &label, "").await
}
```

3. `pairing_state` (lines 44-47): the return type changes to the new struct — update the path:

```rust
fn pairing_state() -> Result<Option<pairings::Pairing>, relay_client::RelayClientError> {
    relay_client::current_pairing()
}
```

(and adjust its doc comment: returns the *active* pairing).

**Verification:**

`cargo test --manifest-path <worktree>/Cargo.toml -p admin-companion`
Expected: all tests pass, including the four golden envelope tests (whose assertions are unmodified) and the three new document-path tests.

**Commit:** `feat(admin-companion): route the relay client through the pairing document`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Phase verification — full test suite, clippy, fmt

**Verifies:** Phase 1 exit criteria (`cargo test -p admin-companion` green on the host target; crate clippy/fmt clean).

**Files:** None (verification only; fix anything it surfaces).

**Step 1: Full test run**

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c \
  cargo test --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion
```

Expected: 0 failures.

**Step 2: Clippy (deny warnings), touching sources first to defeat a warm cache**

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  touch /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/apps/admin-companion/src-tauri/src/*.rs && \
  nix develop --impure --accept-flake-config -c \
  cargo clippy --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion --all-targets -- -D warnings
```

Expected: no warnings. In particular: no `dead_code` (all Task 1/3 allows must be gone), no unused imports in test modules.

**Step 3: Format check**

```bash
cd /Users/jacob.zweifel/workspace/malpercio-dev/ezpds && \
  nix develop --impure --accept-flake-config -c \
  cargo fmt --manifest-path /Users/jacob.zweifel/workspace/malpercio-dev/ezpds/.claude/worktrees/optimistic-mcnulty-3870f7/Cargo.toml -p admin-companion -- --check
```

Expected: no diffs. If there are, run without `--check` and amend the offending commit or commit as `style(admin-companion): rustfmt`.

**Step 4: Commit (only if fixes were needed)**

Any fixes surfaced here get their own focused commit; otherwise nothing to commit.
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_C -->
