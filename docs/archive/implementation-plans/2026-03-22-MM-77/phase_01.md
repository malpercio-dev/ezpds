# OAuth Token Endpoint — Phase 1: Schema (V012 Migration)

**Goal:** Add the `jkt` column to `oauth_tokens` and create the `oauth_signing_key` table.

**Architecture:** Single SQL migration file + entry in the static MIGRATIONS array. No application-level code changes. The migration runner applies V012 to every in-memory test DB at test startup, so all existing tests act as a smoke test.

**Tech Stack:** SQLite (raw DDL), `include_str!()` for compile-time file embedding.

**Scope:** Phase 1 of 6

**Codebase verified:** 2026-03-22

---

## Acceptance Criteria Coverage

This phase is infrastructure-only. It enables the `oauth_signing_key` table used by AC6 and the `jkt` column used by AC4.4, but does not implement or directly test those criteria.

**Verifies: None** — done when `cargo test` passes (migrations apply without error).

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Create V012 SQL migration file

**Files:**
- Create: `crates/relay/src/db/migrations/V012__oauth_token_endpoint.sql`

**Step 1: Create the SQL file**

Create `crates/relay/src/db/migrations/V012__oauth_token_endpoint.sql` with this exact content:

```sql
-- V012: OAuth token endpoint schema additions
-- Applied in a single transaction by the migration runner.
--
-- Adds DPoP key thumbprint (jkt) to oauth_tokens for DPoP-bound refresh tokens.
-- Creates oauth_signing_key single-row table for the server's persistent ES256 keypair.

-- DPoP key thumbprint — NULL for tokens issued before V012 or without DPoP binding.
ALTER TABLE oauth_tokens ADD COLUMN jkt TEXT;

-- Single-row table for the server's persistent ES256 signing keypair.
-- WITHOUT ROWID: the key is always fetched by its id (primary key lookup).
CREATE TABLE oauth_signing_key (
    id                    TEXT NOT NULL,  -- UUID key identifier
    public_key_jwk        TEXT NOT NULL,  -- JWK JSON string (EC P-256 public key)
    private_key_encrypted TEXT NOT NULL,  -- base64(nonce(12) || ciphertext(32) || tag(16))
    created_at            TEXT NOT NULL,  -- ISO 8601 UTC
    PRIMARY KEY (id)
) WITHOUT ROWID;
```

**Step 2: Commit**

```bash
git add crates/relay/src/db/migrations/V012__oauth_token_endpoint.sql
git commit -m "feat(db): V012 migration — oauth_tokens.jkt column + oauth_signing_key table"
```
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Register V012 in the migration runner

**Files:**
- Modify: `crates/relay/src/db/mod.rs:73-77`

The MIGRATIONS array ends at line 77 (`];`). V011 is the last entry, spanning lines 73–76. Add V012 after V011, before the closing `];`.

**Step 1: Edit `db/mod.rs`**

Find this block in `crates/relay/src/db/mod.rs` (lines 73–77):

```rust
    Migration {
        version: 11,
        sql: include_str!("migrations/V011__pending_shares.sql"),
    },
];
```

Replace with:

```rust
    Migration {
        version: 11,
        sql: include_str!("migrations/V011__pending_shares.sql"),
    },
    Migration {
        version: 12,
        sql: include_str!("migrations/V012__oauth_token_endpoint.sql"),
    },
];
```

**Step 2: Run tests**

```bash
cargo test
```

Expected: all tests pass. The migration runner applies V012 to every in-memory test DB, confirming the SQL is valid.

**Step 3: Commit**

```bash
git add crates/relay/src/db/mod.rs
git commit -m "feat(db): register V012 migration in runner"
```
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->
