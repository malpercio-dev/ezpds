# Verification Requirements — relay → pds rename

This is a **behavior-preserving refactor**. There are no new acceptance criteria and no new behavioral tests to author. Verification = the existing test suite stays green + a repo-wide grep gate proves the rename is complete and correctly scoped.

## Per-phase operational verification

| Phase | Gate command | Pass condition |
|---|---|---|
| 01 | `cargo build --workspace` | builds; `target/debug/pds` exists |
| 02 | `docker build -t pds:latest .` + `just ci-pds` (renamed recipe) | image builds, binary runs; CI gate green |
| 03 | `cargo test -p pds` + `cargo clippy -p pds --all-targets -- -D warnings` | green; renamed tests run with same assertions |
| 04 | `cargo test -p pds` (incl. new path + alias route test) | both `/v1/.../pds` and deprecated `/v1/.../relay` resolve identically |
| 05 | `pnpm --dir apps/identity-wallet check` + `cargo build -p identity-wallet` | typecheck + build green; IPC command names match across TS↔Rust |
| 06 | grep gate (below) + `just ci` | gate clean; full workspace gate green |

## The grep gate (definition of done)

```bash
git grep -in 'relay' \
  | grep -v -E '^(docs/design-plans|docs/implementation-plans|docs/test-plans|\.llm-wiki)/' \
  | grep -v 'crawler' | grep -v -i 'requestCrawl' \
  | grep -v 'relays/BGS' | grep -v 'relay/BGS' \
  | grep -v 'relay_signing_keys' | grep -v 'bsky.network'
```

**Every remaining hit must be on the intentional-keep list** (overview + phase_06 Task 4):
- Sense-B crawler/Relay/BGS references (`crawler.rs`, `CrawlersConfig`, `default_crawler_urls`, `[crawlers]`, `app.rs:158/160`, `firehose.rs:213`, `list_repos.rs:46`, `sync_subscribe_repos.rs:5`, `car_export.rs:74`, `main.rs:170-171`).
- Sense-B crawler-URL **test fixtures** in `crates/common/src/config.rs` (~1011/1017/1066).
- Immutable: `relay_signing_keys` table + `V003__relay_signing_keys.sql`.
- Kept prod state: `/data/relay.db` (incl. its `config.rs` derivation ~366 + tests), Litestream `path: relay`, `relay` unix user, `relay.db` example comments.
- Deprecated route aliases in `app.rs` (transition shims).
- The app keychain account string `"relay-base-url"` (value kept; `RELAY_URL_ACCOUNT` const name renamed).
- `docs/design/override-confirm-mock.html:154` placeholder `did:key:zRelay…`.

Any hit **not** on that list is a missed Sense-A rename and must be fixed before merge.

## Manual / human verification (cannot be automated here)

1. **Prod backup continuity** — confirm (in Railway/Litestream) that keeping `/data/relay.db` + S3 prefix `relay` means the production replica + restore path are untouched by this PR. No data migration should occur.
2. **Coordinated release** — Phase 04 (server) and Phase 05 (app) are mutually breaking. Verify the rollout sequence: deploy server (serving both `/pds` and deprecated `/relay`) → ship the TestFlight build using `/pds` → later remove aliases.
3. **App runtime smoke** — on a real build: configure the server URL, create/import an identity, confirm the home screen "Connected" status (now `pdsHealthy`) works against the renamed IPC commands and `/pds` endpoints.
4. **UX copy** — `/impeccable` pass on the renamed config screen and the Custos/server wording (Phase 05 decision).
