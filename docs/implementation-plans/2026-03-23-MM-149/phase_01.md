# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Pre-register the identity-wallet app as a known OAuth client in the relay database.

**Architecture:** A single forward-only SQL migration adds one row to the existing `oauth_clients` table. The PAR handler already performs client lookup by `client_id`; registering the row is the only change needed for the relay to accept identity-wallet PAR requests.

**Tech Stack:** SQLite (migration SQL), Rust/sqlx (migration runner in `crates/relay/src/db/mod.rs`)

**Scope:** 7 phases from original design (phase 1 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC1: PAR flow completes successfully
- **MM-149.AC1.3 Failure:** PAR request with unknown `client_id` returns a client error (relay rejects it)

> Note: MM-149.AC1.3 is already tested by the existing test suite in `oauth_par.rs`. This phase's "Done when" verifies that the seed row exists and that a PAR request with this client_id is accepted — the inverse of the existing failure test. Full AC1.1 and AC1.2 success criteria are verified in Phase 4 (PAR call from the mobile client).

---

<!-- START_TASK_1 -->
### Task 1: Write the V013 migration SQL

**Verifies:** None (infrastructure — verified operationally)

**Files:**
- Create: `crates/relay/src/db/migrations/V013__identity_wallet_oauth_client.sql`

**Step 1: Create the migration file**

```sql
-- Seed the identity-wallet as a registered OAuth client.
--
-- client_metadata is a RFC 7591 JSON object. The PAR handler parses
-- metadata["redirect_uris"] to validate the redirect_uri parameter.
-- INSERT OR IGNORE makes this migration idempotent on re-run.
INSERT OR IGNORE INTO oauth_clients (client_id, client_metadata, created_at)
VALUES (
    'dev.malpercio.identitywallet',
    json('{
        "client_id": "dev.malpercio.identitywallet",
        "application_type": "native",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "redirect_uris": ["dev.malpercio.identitywallet:/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "atproto",
        "client_name": "Malpercio Identity Wallet"
    }'),
    datetime('now')
);
```

**Step 2: Verify the migration file**

Confirm the file exists at the correct path:
```bash
ls crates/relay/src/db/migrations/V013__identity_wallet_oauth_client.sql
```

Expected: file is listed.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Register V013 in the migration runner

**Verifies:** None (infrastructure)

**Files:**
- Modify: `crates/relay/src/db/mod.rs`

The migration runner maintains a static `MIGRATIONS` array. Each entry is `(version: i64, sql: &str)`. V012 is the current last entry.

**Step 1: Read the current MIGRATIONS array**

Open `crates/relay/src/db/mod.rs` and find the `MIGRATIONS` constant (around line 33). The codebase uses a private `Migration` struct with `version: u32` and `sql: &'static str` fields, so each entry is a struct literal:

```rust
static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("migrations/V001__init.sql"),
    },
    // ...
    Migration {
        version: 12,
        sql: include_str!("migrations/V012__oauth_token_endpoint.sql"),
    },
];
```

**Step 2: Append V013**

Add a new `Migration` entry after the V012 entry:

```rust
    Migration {
        version: 13,
        sql: include_str!("migrations/V013__identity_wallet_oauth_client.sql"),
    },
```

The full array tail should read:
```rust
    Migration {
        version: 12,
        sql: include_str!("migrations/V012__oauth_token_endpoint.sql"),
    },
    Migration {
        version: 13,
        sql: include_str!("migrations/V013__identity_wallet_oauth_client.sql"),
    },
];
```

**Step 3: Build to verify the migration compiles**

```bash
cargo build -p relay
```

Expected: builds without errors. The `include_str!` macro fails at compile time if the file path is wrong — a successful build proves the path is correct.

<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Add a migration test to verify the seed row

**Verifies:** MM-149.AC1.3 (PAR with this client_id is now accepted, not rejected as unknown)

**Files:**
- Modify: `crates/relay/src/db/mod.rs` (add one test at the bottom of the file)

The relay's existing test infrastructure in `crates/relay/src/db/mod.rs` provides an `in_memory_pool()` helper that opens a fresh in-memory SQLite pool without running migrations. The test must call `run_migrations(&pool)` explicitly to apply all migrations, including V013.

**Step 1: Read the existing tests at the bottom of `crates/relay/src/db/mod.rs`**

Find the `#[cfg(test)]` module to understand the test pattern. Note the `in_memory_pool()` helper that creates a fresh in-memory SQLite pool (does NOT run migrations).

**Step 2: Add a test that asserts the seed row exists**

Add inside the existing `#[cfg(test)]` mod (or create one if absent):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::oauth::get_oauth_client;

    #[tokio::test]
    async fn v013_seeds_identity_wallet_oauth_client() {
        let pool = in_memory_pool().await;
        run_migrations(&pool).await.expect("migrations must apply cleanly");

        let row = get_oauth_client(&pool, "dev.malpercio.identitywallet")
            .await
            .expect("db query must not fail");

        assert!(
            row.is_some(),
            "V013 migration must insert the identity-wallet client row"
        );

        let row = row.unwrap();
        let metadata: serde_json::Value =
            serde_json::from_str(&row.client_metadata).expect("client_metadata must be valid JSON");

        assert_eq!(
            metadata["redirect_uris"][0].as_str(),
            Some("dev.malpercio.identitywallet:/oauth/callback"),
            "redirect_uri must match the custom URL scheme"
        );
        assert_eq!(
            metadata["dpop_bound_access_tokens"].as_bool(),
            Some(true),
            "DPoP must be required for this client"
        );
    }
}
```

**Step 3: Run the test**

```bash
cargo test -p relay v013_seeds_identity_wallet_oauth_client
```

Expected output:
```
test db::tests::v013_seeds_identity_wallet_oauth_client ... ok
```

**Step 4: Run all relay tests to confirm no regressions**

```bash
cargo test -p relay
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add crates/relay/src/db/migrations/V013__identity_wallet_oauth_client.sql
git add crates/relay/src/db/mod.rs
git commit -m "feat(relay): register identity-wallet as OAuth client (MM-149 phase 1)"
```

<!-- END_TASK_3 -->
