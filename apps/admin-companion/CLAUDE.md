# Admin Companion (operator console) Mobile App

Last verified: 2026-06-28
Last updated: 2026-06-28

## Purpose

Tauri v2 iOS app — SvelteKit 2 + Svelte 5 frontend in a WKWebView over a Rust
backend, communicating through Tauri IPC. The operator-facing console for an ezpds
relay: generate/share account claim codes, pair admin devices via QR, and revoke
devices. A **separate product** from identity-wallet (Obsign) with its own
terminal-native design register — see [PRODUCT.md](PRODUCT.md) / [DESIGN.md](DESIGN.md)
and the design plan [docs/design-plans/2026-06-26-admin-companion-app.md](../../docs/design-plans/2026-06-26-admin-companion-app.md).

The relay side (pairing/auth/device endpoints, Phases 1–5) is already shipped. This
app is built across Phases 6–8.

## Current status (Phase 6 — scaffold)

Buildable skeleton only. Wired so far:
- **Device admin key** — `src-tauri/src/device_key.rs` (`#[cfg]` dispatch: Secure
  Enclave on a real device, software P-256 on macOS/simulator), backed by
  `src-tauri/src/keychain.rs` (service `"ezpds-admin-companion"`).
- Two IPC commands: `get_or_create_device_key`, `sign_with_device_key`.
- The terminal-native token layer (`src/lib/styles/{tokens,fonts,base}.css`).

Not yet built (later phases): QR pairing + request-signing envelope (Phase 7);
claim-code / settings screens + error states (Phase 8).

## Contracts

### Rust backend (`src-tauri/`)
- `device_key::get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` — idempotent;
  returns `{ multibase, keyId }` (camelCase for IPC). Same crypto as identity-wallet's
  module; here the key is the device's **admin credential** (signs requests), not a
  did:plc rotation key.
- `device_key::sign(data) -> Result<Vec<u8>, DeviceKeyError>` — raw 64-byte (r‖s),
  **low-S normalized** P-256 signature (the relay's verifier rejects high-S).
- `DeviceKeyError` serializes as `{ code: "SCREAMING_SNAKE_CASE" }`.
- Keychain accounts: `admin-device-key-priv` (software path), `admin-device-key-pub` +
  `admin-device-key-app-label` (Secure Enclave path).

### Frontend
- `src/lib/ipc.ts` is the **only** file that calls `invoke()`; pages import from it.
- SSR/prerender disabled globally (`src/routes/+layout.ts`); static SPA in `dist/`.
- **Design tokens are the live system.** Reference `var(--color-*)` / `var(--font-*)` /
  `var(--space-*)`; never hardcode hex/px. Every text pair in `tokens.css` is verified to
  clear **WCAG 2.2 AAA (≥7:1)** on its intended ground (the seed anchors were AA; they
  were lifted to clear AAA). Status is color **+ glyph + text**, never color alone.

## Build & run (macOS + Xcode)

```bash
nix develop --impure --accept-flake-config   # from workspace ROOT
cd apps/admin-companion && pnpm install
cargo tauri ios init                          # generates gitignored src-tauri/gen/
cd ../.. && just admin-postinit               # re-apply Xcode patches (idempotent)
just admin-dev                                # simulator   (or: just admin-build)
```

Host build / tests (no Xcode): `cargo build -p admin-companion`, `cargo test -p admin-companion`.

## Key decisions

- **Forked from identity-wallet, not shared.** The iOS toolchain *scripts*
  (`scripts/ios-env.sh`, `ios-postinit.sh`, `ios-check.sh`) are copied (path-relative,
  so they patch this app's own Xcode project) and the OKLCH token *architecture* is
  forked — but the token *values*, components, and product/design briefs are this app's
  own terminal-native register. See the root `apps/identity-wallet/CLAUDE.md` for the
  full explanation of every iOS patch and the toolchain seam; it is the single source of
  truth for those gotchas (this app reuses the same swift-rs `[patch.crates-io]`).
- **Excluded from the Linux CI gate** (`just ci-pds`) like identity-wallet: it needs the
  Apple `security-framework` toolchain. Built/checked on macOS via `just admin-*`.
- **Grotesk UI font is provisional** (system SF Pro via `--font-sans`) until the
  `/impeccable` font pass; JetBrains Mono (the signature voice) is bundled in `static/fonts/`.
- **Distinct Keychain namespace** (`"ezpds-admin-companion"`) and bundle id
  (`dev.malpercio.admincompanion`) so the two apps never collide on one device.
