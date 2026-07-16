# iOS CI Lane Consolidation

Status: **landed** — the reusable TestFlight workflow + composite setup action shipped in #236.
Tracked in Linear: [MM-348](https://linear.app/malpercio/issue/MM-348).
Related: [MM-347](https://linear.app/malpercio/issue/MM-347) (justfile restructure,
which the ios-* recipe dedup overlaps).

## Problem

Three GitHub workflows build the iOS apps, and they share most of their body:

- `.github/workflows/ios-testflight.yml` — identity-wallet → TestFlight on push to `main`
- `.github/workflows/admin-testflight.yml` — admin-companion → TestFlight, path-filtered
- `.github/workflows/ios-pr-check.yml` — secret-free PR gate for both apps

The two TestFlight workflows are ~95% identical: after normalizing app names the
diff is prose comments, one extra `paths:` entry (the swift-rs-patch dir), the
cache `shared-key`, and `IOS_MOBILE_PROVISION` vs `IOS_MOBILE_PROVISION_ADMIN`.
Every future change — a new brew shim, a runner bump, a cache-key tweak, a
tauri-cli bump — must be applied in two or three places, and the cache-strategy
comments have **already** drifted in wording between the files.

## What is duplicated

**1. The full TestFlight body** (ios-testflight ↔ admin-testflight): checkout,
setup, build, sign, upload — everything but the four substitutions above.

**2. The 8-step runner preamble** (all three lanes):

- checkout with `persist-credentials: false`
- setup-just
- pnpm pinned to 9.15.9
- node 22 + pnpm cache
- rustup + `target add aarch64-apple-ios`
- rust-cache with `cache-bin: false`
- cargo-binstall pin
- tauri-cli pinned to 2.11.4
- the arm64 Homebrew Rosetta-shim heredoc (verbatim in all three)
- the `.p8` App Store Connect key decode (verbatim in the two TestFlight lanes)

Every pin comment already says "bump all lanes together" — the factoring makes
that automatic rather than a manual discipline.

## The coupling that makes this non-trivial

Two repo guard scripts parse these workflow files by structure, so a naive
refactor breaks CI in a way that looks unrelated:

- **`scripts/ios-paths-check.sh`** verifies each iOS workflow's `on.push.paths`
  filter matches the app's cargo dependency graph exactly (an unwatched app
  dependency, or a filter re-widened to `crates/**`, both fail). Its `actual_for`
  parser reads the literal workflow files and has a per-workflow-file self-watch
  entry. A reusable workflow + thin callers must keep the per-app `paths:`
  filters **in the caller files**, and the script's parser + self-watch list
  must be updated in the same change.
- **`scripts/ios-template-check.sh`** greps the workflows for the tauri-cli pin
  line to keep it in lockstep with the XcodeGen template. If the pin moves into a
  composite action, the script's sed must learn the new location.

Neither is a blocker — both are the intended forcing functions — but both must
move in the same PR as the workflow change or the gate fails loudly.

## Approach

Land in two independent steps (either order; step 2 is worthwhile alone):

### Step 1 — reusable TestFlight workflow (size L)

- New `.github/workflows/ios-testflight-reusable.yml` with
  `on: workflow_call`, inputs `app` and `recipe-prefix`, and the provision
  profile passed through `secrets:` (so the caller names
  `IOS_MOBILE_PROVISION` vs `IOS_MOBILE_PROVISION_ADMIN`).
- `ios-testflight.yml` and `admin-testflight.yml` become thin callers that keep
  **only** their per-app `on.push.paths` filters and the `uses:` +
  `with:`/`secrets:` block.
- Update `scripts/ios-paths-check.sh` (`actual_for` parser + self-watch list) in
  the same PR.

### Step 2 — composite setup action (size M)

- New `.github/actions/ios-setup/action.yml` (`runs.using: composite`) holding
  the 8-step preamble, taking `app` as an input for the pnpm/cache scoping.
- All three lanes call it, collapsing the verbatim brew-shim and `.p8` decode
  copies to one home each.
- Update `scripts/ios-template-check.sh`'s tauri-cli-pin grep to the
  composite-action location.

### Also fold in from MM-347

The justfile's `ios-*` / `admin-*` recipe pairs (`ios-dev`/`admin-dev`,
`ios-build`/`admin-build`, `ios-pr-check`/`admin-pr-check`,
`ios-upload`/`admin-upload`) are the local-command analogue of the same
duplication and should be parameterized in the same spirit (private
`_dev`/`_upload`/`_pr-check` recipes with one-line public delegates, exactly
like the existing `ios-ipa`/`admin-ipa` → `_ipa` pattern). The shared
`scripts/ios/lib.sh` for the duplicated `sha256_file` helper belongs here too.

## Verification

- `just ios-paths-check`, `just ios-template-check`, `just ios-pr-check`,
  `just admin-pr-check` all green locally.
- The TestFlight lanes cannot be exercised on a PR (they hold signing secrets
  and never run on `pull_request`), so their first real run is the post-merge
  push to `main`. Keep the caller `paths:` filters conservative and confirm the
  reusable workflow's `secrets:` wiring against a dry-run push before relying on
  it for a release.

## Non-goals

- No change to signing, provisioning-profile binding, or the secrets
  themselves — purely structural deduplication.
- No change to which events trigger which lane; the per-app `paths:` filters are
  preserved exactly (and still enforced by `ios-paths-check.sh`).
