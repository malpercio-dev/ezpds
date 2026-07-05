# OAuth Token Endpoint — Phase 3: DPoP Nonce Management

**Goal:** Issue, validate, and prune server-side DPoP nonces. Add nonce functions to `auth/mod.rs` (the type alias and `new_nonce_store()` constructor were already added in Phase 2).

**Architecture:** Three free functions operating on `&DpopNonceStore` — `issue_nonce`, `validate_and_consume_nonce`, `cleanup_expired_nonces`. All are `pub(crate) async`. The nonce is a 22-char base64url string (16 random bytes). TTL is 5 minutes using monotonic `Instant`. Cleanup is called on every token request to prevent unbounded growth.

**Tech Stack:** `tokio::sync::Mutex`, `std::time::Instant`, `std::time::Duration`, `base64` (URL_SAFE_NO_PAD), `rand_core::OsRng`.

**Scope:** Phase 3 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

### MM-77.AC3: DPoP server nonces
- **MM-77.AC3.1 Success:** Request with valid unexpired nonce accepted
- **MM-77.AC3.2 Failure:** No `nonce` claim in DPoP proof → 400 `use_dpop_nonce` + `DPoP-Nonce:` response header
- **MM-77.AC3.3 Failure:** Expired nonce → 400 `use_dpop_nonce` + fresh `DPoP-Nonce:` header
- **MM-77.AC3.4 Failure:** Unknown/fabricated nonce → 400 `use_dpop_nonce`
- **MM-77.AC3.5 Success:** Successful token response includes `DPoP-Nonce:` header with a fresh nonce

AC3.2–AC3.5 are fully tested in Phase 5 (where the token endpoint calls these functions). This phase verifies the nonce store itself in unit tests (AC3.1, AC3.3, AC3.4).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Implement nonce store functions

**Files:**
- Modify: `crates/relay/src/auth/mod.rs`

The `DpopNonceStore` type alias and `new_nonce_store()` function were added to `auth/mod.rs` in Phase 2. Add three new functions directly below them.

**Step 1: Add nonce functions to `auth/mod.rs`**

After the `new_nonce_store()` function (already added in Phase 2), add:

```rust
/// Issue a fresh DPoP nonce with a 5-minute TTL.
///
/// Returns a 22-character base64url string (16 random bytes). The nonce is
/// inserted into the store with an expiry of `Instant::now() + 5 minutes`.
pub(crate) async fn issue_nonce(store: &DpopNonceStore) -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    let expiry = std::time::Instant::now() + std::time::Duration::from_secs(300);
    store.lock().await.insert(nonce.clone(), expiry);
    nonce
}

/// Validate and consume a DPoP nonce.
///
/// Returns `true` if the nonce is present in the store and has not expired.
/// Removes the nonce unconditionally (whether valid or expired) to prevent reuse.
/// Returns `false` for unknown nonces.
pub(crate) async fn validate_and_consume_nonce(store: &DpopNonceStore, nonce: &str) -> bool {
    let mut map = store.lock().await;
    match map.remove(nonce) {
        Some(expiry) => expiry > std::time::Instant::now(),
        None => false,
    }
}

/// Remove all expired nonces from the store.
///
/// Call this on every token request to prevent unbounded memory growth.
/// Under normal relay load (low request volume) this is sufficient without a background task.
pub(crate) async fn cleanup_expired_nonces(store: &DpopNonceStore) {
    let now = std::time::Instant::now();
    store.lock().await.retain(|_, expiry| *expiry > now);
}
```

**Step 2: Confirm compilation**

```bash
cargo build -p relay
```

Expected: compiles without errors.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Unit tests for nonce store functions

**Verifies:** MM-77.AC3.1, MM-77.AC3.3, MM-77.AC3.4

**Files:**
- Modify: `crates/relay/src/auth/mod.rs` (test section)

Add nonce unit tests to the existing `#[cfg(test)]` block in `auth/mod.rs`.

**Step 1: Add tests**

At the end of the `mod tests { ... }` block in `auth/mod.rs`, add:

```rust
    // ── DPoP nonce store tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn issued_nonce_validates_once() {
        // AC3.1: Valid unexpired nonce is accepted.
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;

        // First use: valid.
        assert!(
            validate_and_consume_nonce(&store, &nonce).await,
            "freshly issued nonce must validate"
        );

        // Second use: consumed — must fail (even though not expired).
        assert!(
            !validate_and_consume_nonce(&store, &nonce).await,
            "already-consumed nonce must not validate again"
        );
    }

    #[tokio::test]
    async fn unknown_nonce_is_rejected() {
        // AC3.4: Fabricated nonce not in store.
        let store = new_nonce_store();
        assert!(
            !validate_and_consume_nonce(&store, "this-nonce-was-never-issued").await,
            "unknown nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn expired_nonce_is_rejected() {
        // AC3.3: Expired nonce returns false.
        let store = new_nonce_store();
        // Manually insert a nonce that expired 1 second in the past.
        let nonce = "expired-nonce-test";
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert(nonce.to_string(), past);
        }

        assert!(
            !validate_and_consume_nonce(&store, nonce).await,
            "expired nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_only_expired_nonces() {
        let store = new_nonce_store();

        // Insert one fresh nonce (not yet expired).
        let fresh_nonce = issue_nonce(&store).await;

        // Insert one already-expired nonce directly.
        {
            let mut map = store.lock().await;
            let past = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap();
            map.insert("stale-nonce".to_string(), past);
        }

        cleanup_expired_nonces(&store).await;

        let map = store.lock().await;
        assert!(map.contains_key(&fresh_nonce), "fresh nonce must survive cleanup");
        assert!(!map.contains_key("stale-nonce"), "stale nonce must be pruned by cleanup");
    }

    #[tokio::test]
    async fn issued_nonce_is_22_chars_base64url() {
        let store = new_nonce_store();
        let nonce = issue_nonce(&store).await;
        assert_eq!(nonce.len(), 22, "nonce must be 22 chars (16 bytes base64url no-pad)");
        assert!(
            nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "nonce must be base64url charset"
        );
    }
```

**Step 2: Run tests**

```bash
cargo test -p relay auth::tests
```

Expected: all tests pass including the five new nonce tests.

**Step 3: Commit**

```bash
git add crates/relay/src/auth/mod.rs
git commit -m "feat(auth): DPoP nonce store — issue, validate_and_consume, cleanup_expired"
```
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->
