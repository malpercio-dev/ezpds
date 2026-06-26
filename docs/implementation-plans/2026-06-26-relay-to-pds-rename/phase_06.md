# Phase 06 — Bruno, docs, CLAUDE/AGENTS, final gate

**Goal:** Update the Bruno API collection, the crate/project documentation, and run the final repo-wide grep gate confirming every Sense-A `relay` is gone and every Sense-B/immutable one remains.

**Architecture:** Docs + test-collection cleanup, then a verification sweep. Introduces the Custos/PDS naming into the living docs. Skips generated (`.llm-wiki/`) and dated historical plans.

**Scope:** Phase 6 of 6.

**Codebase verified:** 2026-06-26.

**Verifies:** None (docs/cleanup — verified by the grep gate + `just ci`).

---

<!-- START_TASK_1 -->
### Task 1: Rename and update the Bruno files

**Files:**
- Rename: `bruno/get_relay_keys.bru` → `bruno/get_pds_keys.bru`
- Rename: `bruno/get_device_relay.bru` → `bruno/get_device_pds.bru`
- Modify (within each): `name:` field and the `url:` to the new canonical paths.

**Implementation:**
```bash
git mv bruno/get_relay_keys.bru bruno/get_pds_keys.bru
git mv bruno/get_device_relay.bru bruno/get_device_pds.bru
```
- `get_pds_keys.bru`: `name: Get PDS Keys`; `url: {{baseUrl}}/v1/pds/keys`. Keep the `seq` number.
- `get_device_pds.bru`: `name: Get Device PDS`; `url: {{baseUrl}}/v1/devices/{{deviceId}}/pds`.
- **`bruno/create_signing_key.bru`** — NOT renamed (its name isn't relay-based), but its `url:` is `{{baseUrl}}/v1/relay/keys` (the POST to the renamed route). Update → `{{baseUrl}}/v1/pds/keys`.

(Per root CLAUDE.md, route changes mandate Bruno updates — all three `.bru` files touching the renamed routes are now covered.)

**Verification:** `grep -rn 'relay' bruno/` → no matches (incl. `create_signing_key.bru`).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update the crate-level docs (moved with the crate in Phase 01)

**Files:**
- Modify: `crates/pds/CLAUDE.md` — title "# Relay Crate" → "# PDS Crate (Custos)"; "The relay is the axum-based web server…" → "The pds crate is the axum-based web server (the Custos PDS)…"; the module-map mentions of "relay" that are Sense-A. **KEEP** the `crawler.rs` description's Sense-B references to relays/BGSes and `requestCrawl`. Update the route table entries `get_device_relay`/`get_relay_signing_key` → `get_device_pds`/`get_pds_signing_key` and the paths.
- Modify: `crates/pds/src/db/CLAUDE.md` — note that the `relay_signing_keys` table name is retained for migration-history reasons despite the rename (add a one-line "Naming note").
- Update `Last verified:` dates to 2026-06-26.

**Verification:** `grep -n 'relay' crates/pds/CLAUDE.md` → only Sense-B (crawler/BGS) + the explicit `relay_signing_keys` naming note remain.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Update top-level project docs

**Files:**
- Modify: `AGENTS.md` — Project Structure: `crates/relay/` → `crates/pds/` and its description; add a one-line naming note ("the PDS crate, product name Custos; not to be confused with atproto's Relay"). Update the `crates/relay/CLAUDE.md` link → `crates/pds/CLAUDE.md`. Update `Last verified:` to 2026-06-26. Also sweep the **command docs** (not just paths): `docker build -t relay .`, `just ci-relay`, `cargo build ... -p relay`, `--exclude identity-wallet`-adjacent lines → `pds` / `ci-pds` / `-t pds`. Grep patterns: `grep -nE 'ci-relay|-p relay|-t relay|crates/relay' AGENTS.md`.
- Modify: `README.md` — any Sense-A "relay" describing our server → "pds"/"PDS"/"Custos". **KEEP** the Wave 5 line mentioning `requestCrawl` (Sense-B).
- Modify: root `CLAUDE.md` only if it has Sense-A relay references (it `@AGENTS.md` includes; check).
- Check `crates/relay/CLAUDE.md` link references elsewhere: `grep -rn 'crates/relay' --include=*.md .` (excluding dated `docs/` plans) and fix living docs.

**Do NOT touch:** dated `docs/design-plans/*relay*`, `docs/implementation-plans/*relay*`, `docs/test-plans/*relay*` (historical records), or `.llm-wiki/` (regenerates).

**Verification:** `grep -rn 'crates/relay' --include='*.md' . | grep -v docs/design-plans | grep -v docs/implementation-plans | grep -v docs/test-plans | grep -v .llm-wiki` → no matches.
<!-- END_TASK_3 -->

<!-- START_TASK_3B -->
### Task 3b: Sweep living specs, `.pi/` tooling, and the design mock

These are NOT dated point-in-time records — they describe the current system and must be updated (overview constraint 3). Large but mechanical; apply the two-senses rule (keep `requestCrawl`/BGS/aggregator-Relay references).

**Living top-level specs** (`docs/*.md`, ~11 files):
```bash
for f in docs/pds-architecture.md docs/provisioning-api-spec.md docs/mobile-architecture-spec.md \
         docs/oauth-integration-spec.md docs/blob-handling-spec.md docs/data-migration-spec.md \
         docs/deploy.md docs/ios-cicd.md docs/cross-spec-analysis.md docs/unified-milestone-map.md; do
  echo "== $f =="; grep -ni 'relay' "$f"
done
```
For each hit: Sense-A (our server) → "PDS"/"Custos"/`pds`; Sense-B (the atproto Relay we notify, firehose aggregator, `requestCrawl`) → keep. In `deploy.md` apply the Phase 02 kept-state decisions (the `/data/relay.db`, S3 prefix, unix user references describe retained prod state — keep those, update only Sense-A prose). `docs/v01-issue-plan.md` and `unified-milestone-map.md` may legitimately keep "relay" inside *historical wave descriptions* — use judgment; prefer updating component references, leaving quoted past plans.

> Scope note: these specs total ~600 `relay` hits. If the executor judges the full prose sweep too large for one task, it MAY split `mobile-architecture-spec.md` (119) and `provisioning-api-spec.md` (98) into their own follow-up commit within this phase — but they are IN scope, not skipped. Log the split; do not silently drop them.

**`.pi/` tooling:**
- `\.pi/extensions/atproto/index.ts` — `relayRequest<T>()` helper → `pdsRequest`/`custosRequest`; ~15 tool descriptions "the relay issues…" → "the PDS issues…".
- `\.pi/skills/ezpds-linear-pr-workflow/SKILL.md` — fix the broken `crates/relay/CLAUDE.md` link → `crates/pds/CLAUDE.md` (broken by Phase 01's `git mv`), and Sense-A prose.

**Design mock:**
- `docs/design/relay-oauth-mock.html` — `git mv` → `pds-oauth-mock.html`; update `relay.ezpds.com` host and "Relay OAuth" title to Custos/PDS.

**Verification:** `grep -rn 'crates/relay' . | grep -v -E '(docs/design-plans|docs/implementation-plans|docs/test-plans|\.llm-wiki)/'` → no matches (the `.pi` SKILL.md link is fixed). Living specs no longer describe a "relay" component except where Sense-B.
<!-- END_TASK_3B -->

<!-- START_TASK_4 -->
### Task 4: Final repo-wide grep gate

**Step 1: Enumerate every remaining `relay` and confirm each is intentional**
```bash
git grep -in 'relay' \
  | grep -v -E '^(docs/design-plans|docs/implementation-plans|docs/test-plans|\.llm-wiki)/' \
  | grep -v 'crawler' \
  | grep -v -i 'requestCrawl' \
  | grep -v -i 'BGS' \
  | grep -v 'relay_signing_keys' \
  | grep -v 'bsky.network' \
  | grep -v 'relay-base-url'
```
(Note the broadened `-i 'BGS'` filter — it catches both "relay/BGS" and "BGS/relay" token orders, the bug that would otherwise flag genuine Sense-B firehose/sync comments.)

**Expected remaining hits — ALL intentional, cross-check against the overview keep-list:**
- Sense-B prose: `crates/pds/src/firehose.rs:213` ("a real relay's buffer"), `routes/list_repos.rs:46`, `routes/sync_subscribe_repos.rs:5`, `repo-engine/src/car_export.rs:74`, `app.rs:158/160`, `main.rs:170-171` — all caught by the `BGS`/`crawler` filters; if any slip through (no BGS token on the line), confirm against the overview per-line keep-list.
- `crates/common/src/config.rs` — `CrawlersConfig` / `default_crawler_urls` doc-comments (Sense-B).
- `pds.dev.toml` — `[crawlers]` block + comments (Sense-B).
- Prod-state kept items: `/data/relay.db`, Litestream `path: relay`, `gosu relay` / `useradd ... relay` in Dockerfile + docker-entrypoint.sh + litestream.yml; the `relay.db` example comment in `main.rs`; `relay uid 10001` in `nix/module.nix` (all kept per Phase 02 decision).
- The deprecated route aliases `/v1/devices/:id/relay` and `/v1/relay/keys` in `app.rs` (intentional transition shims).
- The app keychain account string `"relay-base-url"` in `src-tauri/src/keychain.rs` (kept per overview constraint 7; filtered above).
- `crates/common/src/config.rs` crawler-URL **test fixtures** (~1011/1017/1066, e.g. `"https://relay1.example"`, `"ftp://relay.example"`) — Sense-B crawler config values, KEEP. (No `crawler`/`BGS` token on those exact lines, so they survive the filters — they are intentional keeps, NOT missed renames.)
- `crates/common/src/config.rs` `relay.db` derivation + tests (~344/366/487/532/569/586) — kept per constraint 2 (must match the on-disk prod DB path).
- `docs/design/override-confirm-mock.html:154` — placeholder `did:key:zRelay7K…` (random base58 containing "Relay"; not a component reference), KEEP.

**If any hit is NOT on this list → it's a missed Sense-A rename. Fix it.** (The four `config.rs`/mock items above are the known Sense-B/kept hits that have no `crawler`/`BGS` token on their line — do NOT rename them.)

**Step 2: Full gate**
```bash
just ci            # fmt-check, clippy, test, audit (whole workspace incl. identity-wallet)
# If identity-wallet's Apple toolchain isn't present locally, fall back to:
# just ci-pds  + pnpm --dir apps/identity-wallet check
```
Expected: green.

**Step 3: Commit**
```bash
git add -A
git commit -m "docs(pds): update Bruno, CLAUDE/AGENTS, README to pds/Custos naming

Final grep gate confirms all Sense-A relay references renamed; Sense-B
(crawler/Relay/BGS), immutable migrations, and kept prod-state remain."
```
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Open the PR

**Step 1: Push the branch and open one PR**
```bash
git push -u origin rename/relay-to-pds
gh pr create --title "Rename relay → pds (Custos)" --body "$(cat <<'EOF'
Renames the server component from `relay` to `pds` (product brand: Custos),
because `relay` collides with AT Protocol's network-wide Relay (firehose
aggregator). Our server is, by spec, a PDS.

## Scope
- Crate/binary/build wiring → pds (phases 01–02)
- Internal Sense-A symbols → pds (phase 03)
- **Breaking** wire API → /pds paths + pds_url field, with deprecated /relay aliases for one release (phase 04)
- identity-wallet app moved to the new API in lockstep (phase 05)
- Bruno + docs (phase 06)

## Intentionally NOT renamed
- Sense-B: crawler.rs / requestCrawl / bsky.network / crawlers config (the *actual* atproto Relay we notify)
- Immutable: `relay_signing_keys` table + `V003__relay_signing_keys.sql`
- Prod on-disk state: `/data/relay.db`, Litestream S3 prefix, `relay` unix user (backup continuity)

## Follow-ups
- Remove the deprecated `/relay` route aliases after the next coordinated app release.
- `/impeccable` copy pass on the renamed config screen.
EOF
)"
```

**Step 2:** Note in the PR that Phases 04+05 are mutually breaking and must release together (server deploy + TestFlight build).
<!-- END_TASK_5 -->
