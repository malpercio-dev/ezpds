# iOS CI/CD — TestFlight

**Last verified:** 2026-06-24

## Overview

The relay ships through **tangled spindles** (`.tangled/workflows/`), which run on
Linux. The `identity-wallet` Tauri iOS app cannot build there — `cargo tauri ios
build` needs macOS + Xcode + the Apple toolchain, which Linux CI does not have
(this is exactly why `just ci-relay` builds the workspace with `--exclude
identity-wallet`).

So the iOS build lives in **GitHub Actions** on a **public mirror** of this repo.
GitHub-hosted macOS runners (Apple Silicon) are **free for public repositories**,
so the cloud iOS lane costs nothing. The workflow builds a signed App Store IPA and
uploads it to **TestFlight**; you install/update the app from the TestFlight app on
your device.

```
  git push  ──►  tangled (knot.malpercio.dev)  ──►  spindles: relay → Railway   (Linux)
            └─►  github mirror (public)         ──►  Actions: iOS → TestFlight   (macOS)
```

The two pipelines never overlap: tangled owns the relay, GitHub owns iOS. The
tangled pipeline already proves the shared Rust core is correct on Linux; the GitHub
lane only proves the iOS-specific surface (cross-compile → sign → package → ship).

- **Trigger:** push to `main` (paths-filtered) + manual `workflow_dispatch`. Never
  `pull_request` — a public repo must not expose signing secrets to fork PRs.
- **Workflow:** [`.github/workflows/ios-testflight.yml`](../.github/workflows/ios-testflight.yml)
- **Shared recipes:** `just ios-ipa`, `just ios-upload`, `just ios-release` (the same
  commands CI runs; usable locally as an escape hatch).

## One-Time Setup

These steps need your Apple and GitHub accounts; do them once.

### 1. Public GitHub mirror + dual-push remote

Create a **public** repo on GitHub (e.g. `youruser/ezpds`). Then point `origin` at
both knots so a single `git push` updates tangled *and* GitHub:

```bash
# Re-add the existing tangled URL explicitly: the FIRST `--add --push` replaces the
# implicit (fetch-derived) push URL, so tangled must be listed alongside GitHub.
git remote set-url --add --push origin git@knot.malpercio.dev:malpercio.dev/ezpds
git remote set-url --add --push origin git@github.com:youruser/ezpds.git

git remote -v   # expect TWO (push) URLs for origin
git push origin main
```

(Alternative: keep `origin` single and add a separate `github` remote, pushing it
explicitly or from a tangled spindle step. The dual-push above is the lowest-effort
option for a solo dev — your normal push is the CI trigger.)

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
3. `cargo tauri ios init` regenerates the **gitignored** Xcode project, then
   `just ios-postinit` re-applies the pbxproj patches — including **Patch F**, which keeps
   the Rust staticlib `libapp.a` out of the app bundle (App Store rejects loose libraries).
4. **Stamp** `bundle.iOS.bundleVersion = $GITHUB_RUN_NUMBER`. TestFlight rejects
   duplicate build numbers and the app `version` is pinned at `0.1.0`, so the run
   number supplies a unique, monotonic `CFBundleVersion`.
5. `just ios-ipa` → `cargo tauri ios build --export-method app-store-connect` produces
   a signed IPA at `src-tauri/gen/apple/build/arm64/*.ipa`.
6. `just ios-upload` → `xcrun altool --upload-app` sends it to TestFlight.

Automatic signing (vs. fastlane match) is possible **because** distribution is
TestFlight: the API key lets Xcode create/download the App Store cert + provisioning
profile on the fly, so there are no certificates or profiles to store or rotate.

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
- **`bundle.iOS.frameworks` is cosmetic.** The Tauri config schema doesn't define it;
  the real `SystemConfiguration.framework` link is enforced by `ios-postinit.sh`
  Patch E. CI runs `ios-postinit`, so this is covered. See
  [`apps/identity-wallet/CLAUDE.md`](../apps/identity-wallet/CLAUDE.md) (Troubleshooting).
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
  Rust staticlib into the `.app`; App Store rejects loose libraries (tauri#13578).
  `ios-postinit.sh` **Patch F** strips it (project.yml `Externals → buildPhase: none` + the
  pbxproj `in Resources` entry); the `in Frameworks` link entry stays. CI runs `ios-postinit`.
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

## Coexistence with tangled

Nothing about this changes the relay pipeline. `git push` still drives tangled
spindles (`pr.yaml` / `staging.yaml` / `release.yaml`) exactly as before; the mirror
push simply also lands on GitHub and fires the iOS lane. See
[`docs/deploy.md`](deploy.md) for the relay side.
