# Phase 02 — Deploy / runtime infra

**Goal:** Update every build/deploy artifact that references the old `relay` binary, crate path, config file, or `just` recipe so Docker, CI, and the dev shell work against `pds`.

**Architecture:** Mechanical rename across Docker, Litestream, compose, justfile, CI workflows, devenv, and the dev config file. **Critical ops decision documented below:** the production on-disk DB filename, the Litestream S3 prefix, and the `relay` unix user are KEPT to preserve prod backup continuity.

**Scope:** Phase 2 of 6.

**Codebase verified:** 2026-06-26.

**Verifies:** None (infrastructure — verified operationally: `docker build`, `just ci-relay`→`just ci-pds`).

> Depends on Phase 01 (binary is now `pds`).

---

## ⚠️ Production-ops decision (read before editing)

Three `relay` references are **on-disk production state**, not code:

| Artifact | Where | Decision |
|---|---|---|
| DB filename `/data/relay.db` | `Dockerfile`, `docker-entrypoint.sh`, `litestream.yml`, `devenv.nix` state dir | **KEEP** — renaming orphans the live Litestream replica + restore path |
| Litestream S3 prefix `path: relay` | `litestream.yml` | **KEEP** — renaming orphans existing backups |
| `relay` unix runtime user | `Dockerfile`, `docker-entrypoint.sh` | **KEEP** — cosmetic; renaming touches prod container with zero user benefit |

**Rationale:** "Full rename incl. wire API" targets the *wire*, not prod's storage layer. These three are invisible to users and to atproto peers. Renaming them is a separate, dedicated ops task requiring a Litestream cutover (stop replication → rename replica + restore key → restart), out of scope here. **This phase leaves all three as `relay`.** The tasks below rename everything *except* these.

If the reviewer/user wants the full cutover too, add a Phase 02b that: (1) renames `/data/relay.db`→`/data/pds.db` in all four files, (2) renames the S3 `path: relay`→`path: pds`, (3) renames the unix user, and (4) documents the prod migration runbook (drain, re-seed S3 prefix, validate restore). Do NOT fold it into this phase.

---

<!-- START_TASK_1 -->
### Task 1: Dockerfile — build/copy/run the `pds` binary (keep DB file + user)

**Files:**
- Modify: `Dockerfile` (lines ~7, ~12, ~29, ~38; leave ~16/~23/~24/~31/~34 user+db references)

**Implementation:** Rename only the *binary build/copy/run*. Keep the `relay` unix user and `/data/relay.db`.

```bash
grep -n 'relay' Dockerfile
```
Change:
- `RUN cargo build --release --locked -p relay` → `-p pds`
- `COPY --from=build /src/target/release/relay /usr/local/bin/relay` → `.../release/pds /usr/local/bin/pds`
- `exec gosu relay litestream ...` — the `gosu relay` part is the *user* (KEEP); but if the final exec runs the binary path, update the binary path only. Verify the exact final-exec line.

**KEEP (do not change):** `useradd ... relay` (line ~23), `gosu relay` user references, `/data/relay.db` mentions, litestream comments about "the relay user".

**Verification:** `grep -n 'release/relay\|-p relay' Dockerfile` → no matches; `grep -n 'useradd.*relay\|gosu relay' Dockerfile` → still present (intended).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: docker-entrypoint.sh — run the `pds` binary (keep user + db)

**Files:**
- Modify: `docker-entrypoint.sh` (the final `exec gosu relay /usr/local/bin/relay` line — binary path only)

**Implementation:**
```bash
grep -n 'relay' docker-entrypoint.sh
```
Change `exec gosu relay /usr/local/bin/relay` → `exec gosu relay /usr/local/bin/pds` (user `relay` stays, binary path → `pds`). **KEEP** `chown relay:relay /data`, `/data/relay.db` restore/replicate paths, and the comment about "the relay user".

**Verification:** `grep -n '/usr/local/bin/relay' docker-entrypoint.sh` → no matches; `grep -n 'gosu relay\|relay.db\|chown relay' docker-entrypoint.sh` → still present (intended).
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: justfile — rename recipes and docker tag

**Files:**
- Modify: `justfile` (lines ~20-21 `run-relay`, ~25 docker tag, ~39 `ci-relay`, ~51-52 comments)

**Implementation:** Rename the recipes and the docker image tag (Sense-A). Update the comments referencing the relay pipeline.

- `run-relay:` → `run-pds:` and body `cargo run -p relay` → `cargo run -p pds`
- `docker build -t relay:latest .` → `docker build -t pds:latest .`
- `ci-relay: fmt-check` → `ci-pds: fmt-check` (and its body)
- Comments at ~28, ~36, ~51-52 mentioning "the relay" pipeline → "the pds" / "the PDS".

**Note:** Renaming `ci-relay` → `ci-pds` is a breaking recipe rename — the CI workflows call it. Task 4 updates the workflows in the same phase, so they stay consistent.

**Verification:** `grep -n 'relay' justfile` → no Sense-A matches (any remaining must be Sense-B crawler comments, none expected here).
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: CI workflows — call the renamed recipe

**Files:**
- Modify: `.tangled/workflows/pr.yaml` — `just ci-relay` → `just ci-pds`
- Modify: `.tangled/workflows/staging.yaml` — `just ci-relay` → `just ci-pds`
- Modify: `.tangled/workflows/release.yaml` — `just ci-relay` → `just ci-pds`
- Check: `.github/workflows/ios-testflight.yml` — confirm whether it references the relay crate/recipe; update only Sense-A references (the iOS workflow likely doesn't build the relay — verify).

**Implementation:**
```bash
grep -rn 'ci-relay\|-p relay\|crates/relay' .tangled/workflows/ .github/workflows/
```
Replace `ci-relay` → `ci-pds`, `-p relay` → `-p pds`, `crates/relay` → `crates/pds` in each.

**Verification:** `grep -rn 'ci-relay\|crates/relay\|-p relay' .tangled/ .github/` → no matches.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: compose.yaml + litestream.yml (keep DB file + S3 prefix)

**Files:**
- Modify: `compose.yaml` — service key / `container_name` (Sense-A); keep any `/data/relay.db` volume target
- Modify: `litestream.yml` — comments only; **KEEP** `path: /data/relay.db` and `path: relay` (S3 prefix)

**Implementation:**
```bash
grep -n 'relay' compose.yaml litestream.yml
```
- `compose.yaml`: rename the service block `relay:` → `pds:` and `container_name: ezpds-relay` → `ezpds-pds`. If a volume maps to `/data/relay.db`, KEEP that path (it's prod state).
- `litestream.yml`: update only the human comment "# relay directly." → "# pds directly." **Do NOT change** `- path: /data/relay.db` or `path: relay` (overview constraint 2).

**Verification:** `grep -n 'relay' litestream.yml` → only the kept `/data/relay.db` and S3 `path: relay` remain.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Rename the dev config file + devenv wiring (keep state dir DB)

**Files:**
- Rename: `relay.dev.toml` → `pds.dev.toml`
- Modify: `devenv.nix` — `EZPDS_CONFIG = ".../relay.dev.toml"` → `".../pds.dev.toml"`; **KEEP** `EZPDS_DATA_DIR = ".../.devenv/state/relay"` (local state dir mirrors prod `/data/relay.db` convention — keep for consistency, or rename only if Task-2/Task-1 DB decision is revisited)
- Modify (within the renamed file): `pds.dev.toml` — **KEEP** the `[crawlers]` section and its body/comments (Sense-B). The file *name* changes; the crawler content does not.

**Implementation:**
```bash
git mv relay.dev.toml pds.dev.toml
grep -n 'relay' devenv.nix
```
Update the `EZPDS_CONFIG` path. Leave `EZPDS_DATA_DIR` state path as-is (keep parity with the kept prod DB decision).

**Note:** `EZPDS_*` env var *names* already use the `ezpds` prefix — no env-var renames needed anywhere.

**Verification:** `grep -rn 'relay.dev.toml' .` → no matches; `cat pds.dev.toml` still contains the `[crawlers]` block unchanged.
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->
### Task 7: Remaining infra config + comments (Sense-A)

**Files:**
- Modify: `.env.local.example` — comments "The relay requires…", "the relay's public HTTPS URL", and the example host `EZPDS_PUBLIC_URL=https://relay.local` → `https://pds.local` (Sense-A). (Env var *names* stay `EZPDS_*`.)
- Modify: `.dockerignore` — comments at lines ~9, ~19, ~25 ("the relay build needs none of this", "to compile the relay", "even for `-p relay`") → `pds`. The `-p relay` in the comment is illustrative; update to `-p pds`.
- Modify: `nix/module.nix` — description strings only: `mkEnableOption "ezpds relay (OCI container)"` → `"ezpds PDS (OCI container)"`; "Relay OCI image reference…/relay@sha256" → "PDS OCI image reference…/pds@sha256"; "Public https URL of the relay." → "…of the PDS."; the "relay uid 10001" hardening comment → keep `relay uid` if it documents the kept unix user, else update prose. **KEEP** the option path `services.ezpds` and container name `ezpds` (public NixOS interface — not renamed; only the OCI image *reference* string default changes if the image is retagged, coordinate with Phase 02 Task 3's `pds:latest` tag).
- Modify: `nix/AGENTS.md` — Sense-A "relay" prose → "pds"/"PDS"; update `Last verified:` to 2026-06-26.
- Modify: `railway.toml` — comment "the relay returns 200…" → "the pds returns 200…".
- Modify: `scripts/ci/railway-deploy.sh` — comment "Deploy the relay to a Railway environment" → "Deploy the pds…".
- Modify: `apps/identity-wallet/src-tauri/Info.ios.plist` — Sense-A comment (if any) → pds.
- Check: `.github/workflows/ios-testflight.yml` — Sense-A comment → pds (already partly handled in Task 4's grep).

**Verification:** `grep -rn 'relay' .env.local.example .dockerignore nix/ railway.toml scripts/ci/railway-deploy.sh` → only intentional keeps remain (e.g. `relay uid 10001` documenting the kept unix user).
<!-- END_TASK_7 -->

<!-- START_TASK_8 -->
### Task 8: Verify operationally, then commit

**Step 1: Dev shell + build**
```bash
nix develop --impure --accept-flake-config --command just ci-pds
```
Expected: fmt-check, clippy, test all pass under the renamed recipe. (If not in Nix, run `cargo build --workspace` + `cargo test --workspace --exclude identity-wallet` + `cargo clippy --workspace --exclude identity-wallet --all-targets -- -D warnings`.)

**Step 2: Docker build**
```bash
just docker-build   # or: docker build -t pds:latest .
```
Expected: image builds; the binary `/usr/local/bin/pds` is present and runs.

**Step 3: Commit**
```bash
git add -A
git commit -m "refactor(pds): update build/deploy wiring to pds binary

Dockerfile, entrypoint, compose, justfile recipes (ci-pds), CI
workflows, devenv, and dev config (pds.dev.toml) now target pds.
Production on-disk artifacts (/data/relay.db, Litestream S3 prefix,
relay unix user) intentionally kept to preserve backup continuity."
```
<!-- END_TASK_7 -->
