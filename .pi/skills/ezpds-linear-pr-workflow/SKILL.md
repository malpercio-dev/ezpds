---
name: ezpds-linear-pr-workflow
description: "Standard workflow for implementing one Linear issue in the ezpds repo: pick, implement, verify, ship, review (two-pass), fix, pause."
---

# ezpds Linear PR Workflow

## When to Use

When picking up any Linear issue for the ezpds project. One issue per branch/PR — do not batch multiple issues unless they are inseparable (e.g. a storage layer and its only consumer).

## Procedure

1. **Pick** — Use `linear_list_issues` to list the team backlog. Analyze by wave/priority/dependency chain. Select one issue. Read its description and acceptance criteria via `linear_get_issue`.
2. **Prep** — Mark the issue In Progress (`linear_update_issue`). Create a feature branch from main (`git checkout -b feat/<short-desc>`). Read existing code first: similar routes, the migration folder, DB modules, and the relay CLAUDE.md.
3. **Implement** — Migration SQL → DB query module (`db/<entity>.rs`) → register migration in `db/mod.rs` → route handler (`routes/<name>.rs`) → register in `routes/mod.rs` and `app.rs` → Bruno `.bru` file. Check the actual table schema (PRAGMA table_info or migration SQL) before writing queries that reference FK columns.
4. **Verify** — Run: `cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace`. Fix all issues before committing.
5. **Ship** — Commit with a structured message (module prefix, what, which Linear issue). Push branch to origin. Open PR via `tangled_open_pr` with a description listing what changed and the acceptance criteria.
6. **Review (pass 1 — code quality)** — Read the full diff (`git diff main...HEAD`). Check: dead code and stale comments, unused imports, missing test coverage for new code paths, API response shape matches spec (Content-Type, field names, camelCase), error variants are actually used, all new error codes have status_code_mapping test entries.
7. **Review (pass 2 — adversarial)** — Think like an attacker. Check: TOCTOU races (exists-then-act vs atomic operations), idempotency (content-addressable operations must not fail on duplicate), resource exhaustion (per-user quotas, rate limits, disk fill), crash-orphaned resources (files without DB rows, DB rows without files), `assert!` in library code (use `debug_assert!` to avoid panics in release), known-answer tests for deterministic outputs (CIDs, hashes), edge cases (empty input, boundary values, max limits), path traversal and symlink attacks on filesystem operations, timing side channels in crypto, MIME/type spoofing.
8. **Fix all findings** — Every review finding gets fixed in this PR. Do not defer to follow-up unless the finding requires a separate Linear issue (e.g. GC for orphaned files). Commit fixes separately from the feature commit.
9. **Pause** — Mark the Linear issue as In Review (`linear_update_issue`). Do not start the next issue until the PR is reviewed and merged. Mark Done only after merge.

## Pitfalls

- Check the actual database schema before writing queries. The `accounts` table uses `did` (TEXT) as its primary key — there is no integer `id` column. Verify FK column types match the referenced table's PK.
- Do not mark Linear issues as Done when the PR opens. Use 'In Review' state. Done is only for merged work.
- Do not batch multiple Linear issues into one PR unless truly inseparable.
- Run clippy with `-D warnings` (warnings as errors) — the project enforces this.
- Always register new routes in both `routes/mod.rs` AND `app.rs` router.
- The `infer` crate returns None for content without magic bytes (plain text, etc.). Always provide a fallback MIME type.
- JWT `exp` claims must use a current timestamp, not a hardcoded past value. Use `SystemTime::now()` in tests.
- Push the branch to origin before attempting to open a PR on Tangled.
- `axum::body::to_bytes(body, limit)` already enforces the limit — do not add redundant post-read size checks. Map its error directly to PayloadTooLarge.
- Content-addressable storage (same content → same CID) must be idempotent: use `ON CONFLICT DO UPDATE` instead of bare INSERT, or the second upload panics the handler.
- Filesystem operations should be atomic: prefer `remove_file` + match on `NotFound` over `exists()` + `remove_file` (TOCTOU race).
- Do not use `assert_eq!` in library code that could be reached in production — use `debug_assert_eq!` to avoid panics in release builds. Tests use `assert_eq!` as normal.

## Verification

1. `cargo fmt --all --check` exits 0
2. `cargo clippy --workspace -- -D warnings` exits 0
3. `cargo test --workspace` passes all tests
4. All review findings (pass 1 + pass 2) are fixed and committed
5. Branch is pushed to origin
6. PR is open on Tangled
7. Linear issue is in 'In Review' state
