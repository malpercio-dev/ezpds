# Relay Containerization — Phase 6: Documentation + reproducibility note

**Goal:** Docs describe the Docker/Railway/oci-containers reality; the stale Nix-build references and the `/health` health-path error are corrected; the reproducibility tradeoff is recorded.

**Architecture:** Documentation only.

**Tech Stack:** Markdown.

**Scope:** Phase 6 of 6.

**Codebase verified:** 2026-06-20.

> **Verified anchors:** root `AGENTS.md` Commands (`:11-21`), Flake Outputs (`## Flake Outputs` section listing `packages.<system>.relay`, `docker-image`), `nix/AGENTS.md` (docker.nix/module.nix contracts), `crates/relay/AGENTS.md` (health line says `GET /health` — **stale**, actual route is `GET /xrpc/_health` per `app.rs:162`).
>
> **Locating method:** locate sections by heading TEXT, not raw line numbers.

---

## Acceptance Criteria Coverage

### relay-containerization.AC5
- **relay-containerization.AC5.2 Success:** `nix/AGENTS.md`, root `AGENTS.md` (Commands + Flake Outputs), and a deploy note describe the Docker/Railway/oci-containers workflow; no doc presents the removed Nix build outputs as current; "Last verified" dates are bumped.

### relay-containerization.AC6
- **relay-containerization.AC6.2 Success (negative):** the SQLite single-instance model and schema are unchanged; the devenv dev shell and the iOS app are untouched by this plan.

**Verifies (this phase):** AC5.2, and documents AC6.2's scope boundary. Documentation — verified by read/grep.

---

<!-- START_TASK_1 -->
### Task 1: Rewrite `nix/AGENTS.md` for the oci-containers reality

**Files:**
- Modify: `nix/AGENTS.md`

**Step 1:** Update Purpose/Contracts so:
- `module.nix` is described as a `virtualisation.oci-containers` wrapper running the published image (options: `image`, `port`, `dataDir`, `publicUrl`, `availableUserDomains`, `environmentFile`), with the secret injected via `environmentFiles` (agenix/sops) — not a Nix-built systemd binary.
- Remove the `docker.nix` contract section (the file is deleted). State that the relay image is now built from the repo `Dockerfile` and published to GHCR.
- Update Dependencies/Key Files: no more `packages.<system>.relay`/`docker-image`; the module consumes a GHCR image ref.
- Bump `Last verified:` to `2026-06-20`.

**Step 2: Commit** `git commit -am "docs(nix): document oci-containers module; drop docker.nix contract"`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Update root `AGENTS.md` (Commands + Flake Outputs) and add a deploy note

**Files:**
- Modify: `AGENTS.md` (root)
- Create: `docs/deploy.md`

**Step 1: Root `AGENTS.md`:**
- **Commands:** replace `nix build .#docker-image ...` with `docker build -t ghcr.io/<owner>/relay:<tag> .` (and `docker push`). Keep `nix build .#relay` **removed** (no longer an output) — or note it's gone.
- **Flake Outputs:** remove `packages.<system>.relay` and `packages.<system>.docker-image`; keep `nixosModules.default` (now an oci-containers wrapper) and `devShells.<system>.default`.
- Bump `Last verified:` to `2026-06-20`.

**Step 2: Create `docs/deploy.md`** covering: the container runtime contract (the `EZPDS_*` env vars, `/data` volume, `/xrpc/_health`), Railway setup (volume + variables + domain), the colmena/oci-containers path (GHCR image ref + agenix/sops `environmentFile` + backend enablement), the image-distribution choice (GHCR), and the **reproducibility tradeoff** (flake-locked → pinned base digest + `Cargo.lock`; accepted for a solo/experimental relay).

**Step 3: Commit** `git add AGENTS.md docs/deploy.md && git commit -m "docs: document Docker/Railway/oci-containers deploy + reproducibility tradeoff"`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Fix the stale health-path in `crates/relay/AGENTS.md`

**Files:**
- Modify: `crates/relay/AGENTS.md` (the `routes/` table row for `health.rs`)

**Step 1:** Change the `health.rs` endpoint from `GET /health` to `GET /xrpc/_health` (the actual registered route per `app.rs:162`). Bump `Last verified:` to `2026-06-20`.

**Step 2: Commit** `git commit -am "docs(relay): correct health route to /xrpc/_health"`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Confirm scope boundary (AC6.2 negative)

**Files:** none (verification).

**Step 1:** Confirm this plan changed only build/deploy + minimal config/TLS wiring — not relay routes, the SQLite schema, the dev shell, or the iOS app:
```bash
# No migration files added/changed by this plan:
git diff --name-only main... -- crates/relay/src/db/migrations/ ; echo "migrations-changed-exit=$?"
# devenv.nix + apps/identity-wallet untouched by THIS plan's commits (spot check):
git log --oneline main... -- devenv.nix apps/identity-wallet | head
```
Expected: no migration changes; no relay-containerization commit touches `devenv.nix` or `apps/identity-wallet` (the iOS de-Nix work is a separate set of commits). The single-instance SQLite model is unchanged (documented in `docs/deploy.md`).

**Step 2: No dangling references to the removed Nix outputs (AC5.2).** Grep the whole repo (code + scripts + docs), not just `flake.nix`:
```bash
grep -rnI -E "\.#(relay|docker-image)|packages\.[^.]*\.(relay|docker-image)|nix/docker\.nix" \
  --exclude-dir=.git --exclude-dir=docs . ; echo "dangling-exit=$?"
```
Expected: `dangling-exit=1` (no matches) — confirming `justfile`, `tests/`, `nix/AGENTS.md`, and root `AGENTS.md` no longer reference the removed `.#relay`/`.#docker-image` outputs or the deleted `nix/docker.nix`. (Historical mentions inside `docs/` design/impl plans are allowed and excluded.)

**Step 3: No commit** (verification only).
<!-- END_TASK_4 -->

---

## Phase 6 Done When

- `nix/AGENTS.md`, root `AGENTS.md` (Commands + Flake Outputs), and `docs/deploy.md` describe the Docker/Railway/oci-containers workflow; no doc presents the removed Nix outputs as current; dates bumped (AC5.2).
- `crates/relay/AGENTS.md` health route corrected to `/xrpc/_health`.
- Scope boundary confirmed (AC6.2): no schema/dev-shell/iOS changes in this plan.
- All edits committed.
