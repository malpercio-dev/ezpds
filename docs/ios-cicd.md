# iOS CI/CD — TestFlight

**Last verified:** 2026-06-30

## Overview

CI/CD runs on **GitHub Actions**, split into two lanes by platform. The Linux PDS lane
(`.github/workflows/ci.yml`) runs the `just ci-pds` test gate, and Railway deploys the
PDS natively from GitHub (see [`docs/deploy.md`](deploy.md)). The `identity-wallet`
Tauri iOS app can't build on the Linux runners — `cargo tauri ios build` needs macOS +
Xcode + the Apple toolchain (this is exactly why `just ci-pds` builds the workspace with
`--exclude identity-wallet`), so it gets its own macOS lane.

That macOS lane is this workflow. GitHub-hosted macOS runners (Apple Silicon) are **free
for public repositories**, so the cloud iOS lane costs nothing. The workflow builds a
signed App Store IPA and uploads it to **TestFlight**; you install/update the app from the
TestFlight app on your device.

```
  git push main ──►  Actions: ci.yml             →  Railway: PDS staging/production   (Linux)
                ├─►  Actions: ios-testflight      →  TestFlight: Obsign               (macOS)
                └─►  Actions: admin-testflight    →  TestFlight: Admin Companion      (macOS)
```

There are **two** iOS apps, each with its own macOS lane and TestFlight app: the
`identity-wallet` (Obsign) wallet and the `admin-companion` operator console. The runbook
below covers the wallet end-to-end; the [Admin Companion lane](#admin-companion-lane-second-ios-app)
section documents the (small) delta for the second app.

The two lanes never overlap: the PDS lane proves the shared Rust core is correct on Linux
and ships the server; the iOS lane only proves the iOS-specific surface (cross-compile →
sign → package → ship).

- **Trigger:** push to `main` (paths-filtered) + manual `workflow_dispatch`. Never
  `pull_request` — a public repo must not expose signing secrets to fork PRs.
- **Workflow:** [`.github/workflows/ios-testflight.yml`](../.github/workflows/ios-testflight.yml)
- **Shared recipes:** `just ios-ipa`, `just ios-upload`, `just ios-release` (the same
  commands CI runs; usable locally as an escape hatch).
- **PR gate:** [`.github/workflows/ios-pr-check.yml`](../.github/workflows/ios-pr-check.yml)
  runs on `pull_request` with **no secrets**: frontend type-check + unit tests (ubuntu) and,
  on the same `macos-26` runner image, `cargo tauri ios init` (renders the committed
  `scripts/ios/project.yml` template) → `just ios-postinit` / `admin-postinit` (the
  template-seam gate) → `just ios-pr-check` / `admin-pr-check`
  (frontend build + staticlib cross-compile for `aarch64-apple-ios`). Everything short of
  xcodebuild archiving/signing, so iOS breakage surfaces on the PR instead of post-merge.

## One-Time Setup

These steps need your Apple and GitHub accounts; do them once.

### 1. Public GitHub repo

The repo lives on **GitHub** and must be **public** so the macOS runners are free (and so
Railway can connect to it for native PDS deploys). Point `origin` at it and push `main`:

```bash
git remote set-url origin git@github.com:youruser/ezpds.git
git remote -v
git push origin main
```

### 2. App Store Connect

1. **App record** — App Store Connect → Apps → **+** → New App. Platform iOS, bundle
   ID **`dev.malpercio.identitywallet`** (must match `tauri.conf.json > identifier`).
   You may need to register the App ID first at Certificates, Identifiers & Profiles.
2. **Distribution certificate** — Xcode → Settings → Accounts → your team → **Manage
   Certificates** → **+** → **Apple Distribution**. Then in **Keychain Access** (login
   keychain → Certificates) select the `Apple Distribution: … (<TeamID>)` cert **and its
   private key** → right-click → **Export 2 items** → `Distribution.p12` with a password.
3. **App Store provisioning profile** — Certificates, Identifiers & Profiles → **Profiles**
   → **+** → **App Store Connect** (Distribution) → App ID `dev.malpercio.identitywallet`
   → select the Distribution cert from step 2 → download the `.mobileprovision`.

   **iCloud capability (media backup, MM-434):** the wallet signs with the iCloud
   Documents entitlements in `apps/identity-wallet/src-tauri/Entitlements.ios.plist`
   (container `iCloud.dev.malpercio.identitywallet`), so the App ID must have the
   **iCloud** capability enabled with that container assigned, and the provisioning
   profile must be **regenerated after** the capability is added — a profile minted
   before it will fail signing with an entitlements mismatch. Update the
   `IOS_MOBILE_PROVISION` secret with the regenerated profile.
4. **API key (upload)** — Users and Access → **Integrations** → App Store Connect API →
   **Team Keys** (NOT "Individual Keys" — those don't expose an Issuer ID) → generate a key
   with the **App Manager** role (it uploads builds; Admin also works). Download the `.p8`
   **once**; note the **Key ID** (the key's row) and the **Issuer ID** (the team-wide UUID
   at the top of the Team Keys list).
5. **Internal tester** — TestFlight tab → Internal Testing → add yourself (no review;
   builds appear minutes after upload).
6. **Team ID** — Apple Developer → Membership → your 10-character Team ID.

### 3. GitHub repo secrets

Settings → Secrets and variables → Actions → **New repository secret**:

| Secret | Value | Where it comes from |
|---|---|---|
| `IOS_CERTIFICATE` | base64 of `Distribution.p12` | `base64 -i Distribution.p12 \| pbcopy` |
| `IOS_CERTIFICATE_PASSWORD` | the `.p12` export password | you set it in step 2 |
| `IOS_MOBILE_PROVISION` | base64 of the `.mobileprovision` | `base64 -i *.mobileprovision \| pbcopy` |
| `APPLE_API_ISSUER` | Issuer ID (UUID) | Top of the **Team Keys** list (team-wide) |
| `APPLE_API_KEY` | Key ID | The key's row under **Team Keys** |
| `APPLE_API_KEY_B64` | base64 of the `.p8` | `base64 -i AuthKey_<KeyID>.p8 \| pbcopy` |
| `APPLE_DEVELOPMENT_TEAM` | Team ID | Apple Developer → Membership |

The first three **sign** the app (Tauri reads them directly); the rest authenticate the
TestFlight **upload**. Nothing secret is committed — secrets are injected at build time and
the public repo only ever holds source.

## How the Pipeline Works

Each run on `macos-26`:

1. Checkout, install `just`, pnpm, Node 22, and the Rust iOS target (driven by
   `rust-toolchain.toml`), then `cargo binstall tauri-cli`.
2. **Decode** `APPLE_API_KEY_B64` to `~/.appstoreconnect/private_keys/AuthKey_<KeyID>.p8`
   and export `APPLE_API_KEY_PATH` (for the `altool` upload). Signing itself is **explicit**:
   Tauri reads `IOS_CERTIFICATE` / `IOS_CERTIFICATE_PASSWORD` / `IOS_MOBILE_PROVISION`
   directly and signs with your Apple Distribution cert + App Store profile.
3. `cargo tauri ios init` regenerates the **gitignored** Xcode project from the committed
   `scripts/ios/project.yml` template (which keeps the Rust staticlib `libapp.a` out of the
   app bundle — App Store rejects loose libraries); `just ios-postinit` then checks the
   swift-rs fork, installs the app icon, and verifies the rendered project.
4. `just ios-ipa` **stamps** a unique, monotonic `bundle.iOS.bundleVersion` (UTC epoch
   seconds; TestFlight rejects duplicate build numbers) and then runs
   `cargo tauri ios build --export-method app-store-connect`, producing a signed IPA at
   `src-tauri/gen/apple/build/arm64/*.ipa`. Because the stamp lives in the recipe (not
   the workflow), a local `just ios-release` uses the same scheme and can never collide
   with CI; the stamped `tauri.conf.json` is restored when the recipe exits.
6. `just ios-upload` → `xcrun altool --upload-app` sends it to TestFlight.

Signing is **explicit, not automatic**. Tauri's automatic iOS signing emits an
`Apple Distribution: Tauri (unset)` placeholder that App Store Connect rejects (tauri#11092),
so the pipeline signs with a stored Apple Distribution cert + App Store profile
(`IOS_CERTIFICATE` / `IOS_MOBILE_PROVISION`); the App Store Connect API key (`APPLE_API_*`)
is **upload-only** — it authenticates `altool`, not the signature. The cert and profile are
therefore two artifacts you store as secrets and renew when Apple expires them (both are
annual). A credential manager such as `fastlane match` could automate that rotation across
both apps, but it adds a Ruby toolchain plus some Tauri-signing glue — not worth it at this
scale.

## Local Usage (escape hatch)

The same recipes run on your Mac when you want a build without pushing:

```bash
export APPLE_API_ISSUER=...        # Issuer ID
export APPLE_API_KEY=...           # Key ID
export APPLE_DEVELOPMENT_TEAM=...  # Team ID
# place AuthKey_<KeyID>.p8 in ~/.appstoreconnect/private_keys/

just ios-release      # = ios-ipa (build+sign) then ios-upload (TestFlight)
# or run them separately:
just ios-ipa
just ios-upload
```

The first bring-up should be **local**, not CI: run `just ios-release` on your Mac
once to shake out signing and the App Store Connect app record where you can see
errors directly — only then trust the push-triggered cloud job. Don't debug signing
for the first time inside a CI log.

## Gotchas / Verification

- **Export-method token.** `--export-method app-store-connect` follows current Tauri
  docs (Xcode 15+ renamed `app-store` → `app-store-connect`). If a Tauri/Xcode version
  rejects it, confirm the accepted values with `cargo tauri ios build --help` and
  update the `ios-ipa` recipe.
- **`bundle.iOS.frameworks` is the framework-link source of truth.** The
  `scripts/ios/project.yml` template renders it into `OTHER_LDFLAGS` (plus xcodegen `sdk:`
  dependencies) on every `cargo tauri ios init`, and `just ios-check` verifies every listed
  framework landed. (Historically this config was cosmetic — it only seeded a fresh
  project.yml — and a pbxproj patch enforced the link instead.) See
  [`apps/identity-wallet/AGENTS.md`](../apps/identity-wallet/AGENTS.md) (Troubleshooting).
- **First TestFlight upload.** It can only succeed after the App Store Connect app
  record exists for the bundle ID, and each upload's build number must exceed anything
  previously seen. The run-number scheme handles the latter automatically.
- **`Apple Distribution: Tauri (unset)` placeholder cert / `Invalid Provisioning Profile`.**
  Tauri's *automatic* iOS signing is unreliable (tauri#11092). Sign **explicitly** with
  `IOS_CERTIFICATE` + `IOS_CERTIFICATE_PASSWORD` + `IOS_MOBILE_PROVISION` (Apple
  Distribution cert + App Store profile), not the API key.
- **`base64: invalid option -- 'o'` during signing (local only).** In the devenv, Nix's
  GNU `base64` shadows macOS's BSD one, but Tauri's cert decode uses BSD flags. `ios-env.sh`
  shims `/usr/bin/base64` ahead of it under `EZPDS_IOS_BUILD`. No-op on CI (BSD base64 there).
- **`libapp.a … is not permitted` / `Invalid bundle structure`.** cargo-mobile2 copies the
  Rust staticlib into the `.app`; App Store rejects loose libraries (tauri#13578). The
  `scripts/ios/project.yml` template sets `Externals → buildPhase: none`, so the generated
  project never bundles it; the `framework: libapp.a` link entry stays. `just ios-check`
  verifies. CI runs `ios-postinit`, which ends with that check.
- **Export compliance ("Missing Compliance" in TestFlight).** `src-tauri/Info.ios.plist`
  sets `ITSAppUsesNonExemptEncryption = false` (standard-crypto exemption), merged into the
  Info.plist on every build, so uploads clear the encryption gate automatically — no per-build
  click. It's a legal self-declaration; flip to `true` + supply docs if a review concludes
  the app's encryption is non-exempt.
- **CocoaPods** is pre-installed on GitHub macOS runners; `cargo tauri ios init`
  invokes it. A transient pod failure usually clears on re-run.
- **Runner Xcode / iOS SDK.** `macos-26` ships Xcode 26 / the iOS 26 SDK, which Apple
  *requires* for uploads (older SDKs are rejected at the altool validation step) and which
  matches the local macOS 26 / Xcode 26 dev environment. If Apple raises the minimum SDK
  again, bump `runs-on` to the next `macos-NN` image.
- **Hardening follow-up.** Actions are pinned to tags (`@v4`, `@v2`). For a public repo,
  pinning to commit SHAs is the stricter supply-chain posture; consider it once the
  pipeline is stable.

## Admin Companion lane (second iOS app)

The operator console (`apps/admin-companion/`, bundle id `dev.malpercio.admincompanion`)
ships through its own macOS lane,
[`.github/workflows/admin-testflight.yml`](../.github/workflows/admin-testflight.yml). Both
TestFlight lanes are thin callers of one reusable workflow,
[`.github/workflows/ios-testflight-reusable.yml`](../.github/workflows/ios-testflight-reusable.yml)
(the whole build/sign/upload body): each caller keeps only its per-app `on.push.paths`
filter and passes `app`, `recipe-prefix`, and its provisioning-profile secret. The admin
caller is driven by `admin-*` recipes (`just admin-ipa`, `just admin-upload`,
`just admin-release`) and triggers on push to `main` under `apps/admin-companion/**` (plus
the shared `crates/crypto/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
`scripts/ios/**`, and the shared `.github/actions/ios-setup/**` composite action + reusable
workflow) and on manual `workflow_dispatch`. The reusable workflow and the ios-pr-check
`ios-compile` job share the `.github/actions/ios-setup` composite action for the toolchain
preamble (pnpm/node, Rust iOS target, warm rust-cache, the pinned tauri-cli, the arm64 brew
shim).

**Reused as-is** (team-wide; already configured for the wallet): the Apple Distribution
cert (`IOS_CERTIFICATE` / `IOS_CERTIFICATE_PASSWORD`), the App Store Connect API key
(`APPLE_API_ISSUER` / `APPLE_API_KEY` / `APPLE_API_KEY_B64`), and `APPLE_DEVELOPMENT_TEAM`.

**New, one-time, for this app:**

1. **App ID** — register `dev.malpercio.admincompanion` at Certificates, Identifiers & Profiles.
2. **App Store Connect app record** — New App with that bundle ID (its own name + SKU), then
   add yourself as an internal tester (TestFlight tab).
3. **App Store provisioning profile** — a Distribution profile bound to the new App ID,
   signed by the **same** Apple Distribution cert from the wallet setup. A profile is
   per-bundle-id, so it cannot be shared with identity-wallet — this is the one artifact
   that must be minted fresh.
4. **GitHub secret `IOS_MOBILE_PROVISION_ADMIN`** — base64 of that profile
   (`base64 -i *.mobileprovision | pbcopy`). The workflow maps this secret into the
   `IOS_MOBILE_PROVISION` env var Tauri reads, so the admin build signs with the admin
   profile while the wallet lane keeps using its own `IOS_MOBILE_PROVISION` secret.

Everything else is identical — the template's `libapp.a` bundle exclusion, the build-number stamp, the
`ITSAppUsesNonExemptEncryption=false` plist, and the Rosetta `brew` shim — so the
[Gotchas](#gotchas--verification) above apply unchanged (admin-companion links only
`SystemConfiguration`, not `AuthenticationServices`, since it has no OAuth auth-session).
Do the **first build locally** the same way: `just admin-release` on your Mac, with the
admin profile's base64 in `IOS_MOBILE_PROVISION`, before trusting the cloud job.

## Relationship to the PDS lane

The lanes share the repo but never overlap. A push to `main` fires
`.github/workflows/ci.yml` (PDS test gate → Railway deploys staging) plus, when their
paths match, the two iOS lanes (`ios-testflight.yml` and `admin-testflight.yml` → their
respective TestFlight apps); production PDS deploys are driven separately by advancing the
`production` branch to a release tag. See [`docs/deploy.md`](deploy.md) for the PDS side.
