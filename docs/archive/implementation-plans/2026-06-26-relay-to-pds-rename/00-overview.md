# Rename `relay` → `pds` (brand: Custos) — Implementation Plan

**Goal:** Rename the server component from `relay` to `pds` throughout the codebase, because "relay" collides with AT Protocol's own `Relay` (the network-wide firehose *aggregator*). Our component is, by the spec's definition, a **PDS**.

**Naming model (decided 2026-06-26):**

| Layer | Name |
|---|---|
| Product / wallet app | **Obsign** (existing) |
| Product / server | **Custos** (brand) |
| atproto role term (docs/code) | **PDS** |
| Crate / directory / binary | `pds` (was `relay`) |

Prose convention: *"Custos is Obsign's PDS."*

**Scope decision:** FULL rename, **including the public wire API** (route paths, response field names) — a coordinated, breaking server + iOS-app + Bruno change that must land as one branch. Review mode: batch (all phases written to disk).

**Tech stack:** Rust (cargo workspace), axum, sqlx/SQLite, Tauri v2 + SvelteKit (identity-wallet), Docker + Litestream, tangled + GitHub Actions CI.

**Codebase verified:** 2026-06-26 (codebase-investigator sweep + spot-checks).

---

## The "two senses of relay" rule (applies to every phase)

The token `relay` appears in **two opposite meanings**. Only Sense-A is renamed.

- **Sense-A — OUR component** → rename to `pds`.
- **Sense-B — the external AT Protocol Relay** we *notify* via `com.atproto.sync.requestCrawl` (e.g. `bsky.network`) → **MUST KEEP**.

**Sense-B locations that MUST NOT change** (verbatim keep-list):
- `crates/relay/src/crawler.rs` — all of it (`requestCrawl`, `bsky.network`, "relay/BGS").
- `crates/common/src/config.rs` — `CrawlersConfig`, `default_crawler_urls()`, the `crawlers.*` validation and doc-comments referencing relay/BGS. **Also the crawler-URL *test fixtures* at ~lines 1011/1017/1066** (e.g. `"https://relay1.example"`, `"ftp://relay.example"`) — these are Sense-B (crawler config values), NOT our component → KEEP. (Contrast: `relay.example.com` fixtures that describe *our server's* URL are Sense-A → renamed in Phase 03.)
- `docs/design/override-confirm-mock.html:154` — a placeholder `did:key:zRelay7K…` whose random base58 happens to contain "Relay". Not a component reference → KEEP.
- `crates/relay/src/app.rs:158` and `:160` — doc-comments saying "fans out to connected relays/BGSes" / "pings the configured relays/BGSes". (The `crawlers` AppState field is Sense-B — keep.)
- `crates/relay/src/main.rs:170-171` — crawler-notifier comments ("ping the configured relays/BGSes via requestCrawl") — Sense-B, keep. (Other `main.rs` relay refs are Sense-A — see Phase 03.)
- `crates/relay/src/firehose.rs:213` — "matching how **a real relay's** buffer ages out" — Sense-B (a generic upstream relay), keep. ⚠️ Contrast `firehose.rs:166` ("**The relay** holds a single `Arc<Firehose>`") which is **Sense-A → rename** in Phase 03.
- `crates/relay/src/routes/list_repos.rs:46` — "a BGS/relay discover and crawl" — Sense-B, keep.
- `crates/relay/src/routes/sync_subscribe_repos.rs:5` — "BGSes and relays open a long-lived WebSocket" — Sense-B, keep.
- `crates/repo-engine/src/car_export.rs:74` — "consumers (a BGS/relay)" — Sense-B, keep.
- `relay.dev.toml` `[crawlers]` section body + its comments (the *file name* is Sense-A and is renamed; the `[crawlers]` content is Sense-B and stays).
- `README.md` line listing "requestCrawl" under Wave 5 federation.
- `.llm-wiki/.../atproto-extension-sync-with-relay.md` and other `.llm-wiki/` content — Sense-B and/or generated; left alone (regenerates).

When in doubt about a `relay` occurrence: if it is about *receiving a firehose from many servers* or *notifying bsky.network* (a BGS/relay aggregator), it is Sense-B — keep. If it is about *our* server's own state/identity/config, it is Sense-A — rename.

---

## Hard constraints

1. **Applied migrations are immutable.** `crates/relay/src/db/migrations/V003__relay_signing_keys.sql` (filename) and the `relay_signing_keys` **table/column names** stay exactly as-is — the forward-only runner checksums applied migrations and prod is live (v0.1.0). The internal SQL identifier `relay_signing_keys` is invisible over the wire; renaming it would require a risky `ALTER TABLE` migration against the production DB for zero user-visible benefit. **Out of scope.** (If ever desired, do it as a separate, dedicated migration PR with a Litestream-aware cutover.)

2. **Prod on-disk artifacts stay (Phase 02 decision).** `/data/relay.db`, the Litestream S3 prefix `relay`, and the `relay` unix runtime user are **kept** by default. Renaming the DB filename or S3 prefix orphans existing production Litestream backups. These are internal and invisible to users. See Phase 02 for the explicit decision and the alternative if a full cutover is ever wanted. **This includes the code that derives the filename:** `crates/common/src/config.rs` `.join("relay.db")` (~line 366), its doc-comment (~344), and its tests (~487/532/569/586) — **KEEP** the `relay.db` literal there (it must match the kept on-disk path). Only Sense-A *prose* in `config.rs` is renamed (Phase 03).

3. **Skip generated + dated-historical artifacts only.** Do not rewrite dated `docs/design-plans/`, `docs/implementation-plans/`, `docs/test-plans/` (point-in-time records) or `.llm-wiki/` (regenerates itself). **BUT living top-level specs (`docs/*.md` such as `pds-architecture.md`, `provisioning-api-spec.md`, `mobile-architecture-spec.md`, `deploy.md`, `ios-cicd.md`) ARE in scope** and are swept in Phase 06 — they describe the current system and would otherwise reference a component that no longer exists.

4. **Lockstep merge.** Phases 04 (server wire API) and 05 (iOS app) are mutually breaking and MUST merge together. The relay CI gate runs `--exclude identity-wallet`, so the Rust gate stays green between them, but the deployed app and the server must be released as a coordinated pair.

5. **Every phase ends green.** `cargo build --workspace` and the relevant tests must pass at each phase boundary. This is a behavior-preserving refactor — no existing test should change *meaning*, only renamed identifiers/paths.

6. **App client name collision → use the brand.** The iOS app has `RelayClient` (`src-tauri/src/http.rs`, the client for *our* server) AND a separate, unrelated `PdsClient` (`src-tauri/src/pds_client.rs`, generic handle/DID resolution against plc.directory). Renaming `RelayClient`→`PdsClient` would collide. **Rename `RelayClient` → `CustosClient`** (brand name; unambiguous). Leave the existing `PdsClient` untouched — it is correctly named for generic-PDS resolution.

7. **Persisted-key safety (like the DB-filename rule).** The app stores the configured server URL under a keychain key (`keychain.rs` `store_relay_url`/`load_relay_url`, account string `"relay-base-url"`). **KEEP the on-disk storage-key string** so users who upgrade in place don't lose their configured URL — rename only the surrounding Rust fns. Same principle as constraints 1–2: code names change, persisted identifiers don't.

---

## Phase map

| Phase | Title | Type | Verification |
|---|---|---|---|
| 01 | Crate & build rename | Infrastructure | `cargo build --workspace` |
| 02 | Deploy / runtime infra | Infrastructure | `docker build`, `just ci-relay` (recipe renamed) |
| 03 | Internal Rust symbols (Sense-A) | Refactor | `cargo test -p pds` |
| 04 | Public wire API (server side) | Refactor (breaking) | `cargo test -p pds`, route tests |
| 05 | Frontend lockstep (iOS app) | Refactor (breaking) | `pnpm` typecheck / app build |
| 06 | Bruno, docs, CLAUDE/AGENTS, final gate | Docs/cleanup | grep gate + `just ci` |

**Acceptance criteria:** none in the traditional sense — this is a behavior-preserving rename. Each phase states `Verifies: None (refactor)` and is verified operationally + by the existing test suite staying green. See `verification-requirements.md` for the gate.

**Suggested branch:** `rename/relay-to-pds`. One PR.
