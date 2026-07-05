# Relay URL Configuration — Phase 1: RelayClient Runtime URL Support

**Goal:** Make `RelayClient` accept a runtime URL while keeping the codebase compiling.

**Architecture:** Purely additive changes to `http.rs`. Change the `base_url` field from `&'static str` to `String` and add a `new_with_url` constructor. The existing static `base_url()` method is left intact in Phase 1 so all callers in `oauth.rs` and `oauth_client.rs` continue to compile unchanged. Phase 2 removes the static method and updates all callers.

**Tech Stack:** Rust (stable), no new dependencies

**Scope:** 1 of 4 phases

**Codebase verified:** 2026-03-27

---

## Acceptance Criteria Coverage

Infrastructure phase — no ACs tested here.

**Verifies: None** — this phase modifies the `RelayClient` struct. Correctness is verified by `cargo build` succeeding and existing tests passing unchanged.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Update `RelayClient` struct and constructors in `http.rs`

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/http.rs`

**Step 1: Change the `base_url` field type**

At `http.rs:44`, change:
```rust
    base_url: &'static str,
```
to:
```rust
    base_url: String,
```

**Step 2: Update `RelayClient::new()` to use `.to_string()`**

At `http.rs:49-54`, change:
```rust
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: RELAY_BASE_URL,
        }
    }
```
to:
```rust
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: RELAY_BASE_URL.to_string(),
        }
    }
```

**Step 3: Add `new_with_url` constructor**

Insert this method directly after `new()` (after the closing `}` of `new()`, before the `post` method):
```rust
    /// Create a new `RelayClient` with a runtime-provided base URL.
    ///
    /// The URL must not have a trailing slash. Used when the relay URL is
    /// configured at runtime rather than baked in at compile time.
    pub fn new_with_url(url: String) -> Self {
        Self {
            client: Client::new(),
            base_url: url,
        }
    }
```

**Step 4: Add an instance `base_url` accessor method**

The existing static `base_url()` method at `http.rs:195` returns the compile-time constant and is kept unchanged. Add a new instance method after it:

```rust
    /// Returns the base URL for this relay client instance.
    pub fn base_url_str(&self) -> &str {
        &self.base_url
    }
```

> Note: The method is named `base_url_str` (not `base_url`) to avoid a name collision with the existing static `const fn base_url() -> &'static str`. The static method is removed and callers updated in Phase 2.

**Step 5: Verify the file still compiles**

From the workspace root (inside the Nix dev shell):
```bash
cargo build -p identity-wallet-lib 2>&1 | head -40
```
Expected: No errors. Warnings about unused `new_with_url` or `base_url_str` are fine.

If `cargo build -p identity-wallet-lib` fails (package name mismatch), use:
```bash
cargo build --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1 | head -40
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Verify existing tests still pass and commit

**Files:**
- No new files

**Step 1: Run all tests in the identity-wallet crate**

```bash
cargo test --manifest-path apps/identity-wallet/src-tauri/Cargo.toml 2>&1
```

Expected: All tests pass (there are no tests in `http.rs`; the 31 tests in `lib.rs` and the `oauth_client.rs` tests should all still pass since no signatures visible to them have changed).

> Note: Some tests in `oauth.rs` are marked `#[ignore]` (integration tests that need a live server). These will be skipped and that is expected.

**Step 2: Commit**

```bash
git add apps/identity-wallet/src-tauri/src/http.rs
git commit -m "refactor: add RelayClient::new_with_url and base_url_str for runtime URL support"
```
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
