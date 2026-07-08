# Admin Companion (operator console) Mobile App

Last verified: 2026-07-08
Last updated: 2026-07-08

## Purpose

Tauri v2 iOS app — SvelteKit 2 + Svelte 5 frontend in a WKWebView over a Rust
backend, communicating through Tauri IPC. The operator-facing console for an ezpds
relay: generate/share account claim codes, pair admin devices via QR, and revoke
devices. A **separate product** from identity-wallet (Obsign) with its own
terminal-native design register — see [PRODUCT.md](PRODUCT.md) / [DESIGN.md](DESIGN.md)
and the design plan [docs/design-plans/2026-06-26-admin-companion-app.md](../../docs/design-plans/2026-06-26-admin-companion-app.md).

The relay side (pairing/auth/device endpoints, Phases 1–5) is already shipped. This
app is built across Phases 6–8.

## Current status (Phase 8 — operator screens + biometric/share)

Phases 6–8 complete: device key + token layer + Brass Console primitives (Phase 6), the
pairing + request-signing client (Phase 7), and the operator screens, biometric gate,
share sheet, and server-side self-revoke (Phase 8). Wired:
- **Device admin key** — `src-tauri/src/device_key.rs` (`#[cfg]` dispatch: Secure
  Enclave on a real device, software P-256 on macOS/simulator), backed by
  `src-tauri/src/keychain.rs` (service `"ezpds-admin-companion"`).
- **Canonical signing envelopes** — `src-tauri/src/signing.rs` (Functional Core): the
  registration and per-request `sign_string`s + `sha256_hex` + base64url-no-pad,
  byte-for-byte matching the relay's `crates/pds/src/routes/auth.rs`. Golden tests pin
  both to the relay's own pinned literals (the `pds` crate is binary-only, so the
  contract is shared by value, not import).
- **Relay client** — `src-tauri/src/relay_client.rs` (Imperative Shell, reqwest): `pair`
  (self-signed `POST /v1/admin/devices`), `generate_claim_code` (signed
  `POST /v1/accounts/claim-codes`), `revoke_self` (signed `POST /v1/admin/devices/:id/revoke`
  for the target pairing's device id), `unpair` (local-only forget — no relay call), plus
  pairing-document mutations (`list_pairings`, `set_active_pairing`, `rename_pairing`). Request
  construction is factored into pure `build_*` fns so a test verifies a built request with
  `crypto::verify_p256_signature` — the relay's own verifier — proving acceptance (and path-binding
  of the revoke) without a live relay.
- **Pairing + preference persistence** — `pairings.rs` (Functional Core: the versioned
  `PairingDoc` — `{ version, active, pairings[] }` with UUID-keyed entries and invariant-preserving
  append/rename/remove/set-active operations) persisted by `keychain.rs` `load_pairings`/`save_pairings`
  as ONE JSON item (account `admin-pairings`). Multiple relays pair simultaneously; one is *active*
  and all unqualified actions resolve it Rust-side. The legacy triple accounts (`admin-device-id`,
  `admin-relay-url`, `admin-device-label`) are deleted on first load (no migration — re-pair).
  `get/set_biometric_enabled` (`admin-biometric-enabled`, default on, survives unpair — a device
  setting) is unchanged.
- IPC commands: `pair_device` (relay URL, pairing code, label, nickname — appends and becomes
  active), `list_pairings` (`{ active, pairings[] }`), `set_active_pairing(id)`, `rename_pairing(id, nickname)`
  (local-only), `generate_claim_code` (acts on the active pairing; `NOT_PAIRED` when none), `revoke_self(id)`
  (signed revoke on that pairing's relay, then local removal), `unpair(id)` (local-only forget),
  `biometric_enabled`, `set_biometric_enabled` (plus Phase 6's `get_or_create_device_key`,
  `sign_with_device_key`). `pairing_state` is gone — superseded by `list_pairings`.
- **Screens**: **Pair** (`src/routes/pair/` — QR/manual + required nickname, reachable while
  paired), **Home** (`src/routes/+page.svelte` — biometric-gated claim code for the *active*
  server, tappable identity block → inline switcher, explicit-pick state when no active pairing),
  **Settings** (`src/routes/settings/` — per-server list with per-entry rename / revoke-on-server /
  forget-locally, global admin key display, biometric toggle, all revokes biometric-gated). The
  error-state matrix (not-paired / clock-skew / revoked / unreachable) is rendered by the shared
  `ui/ErrorState.svelte` off `errors.ts`'s `classifyRelayError`. Server identity display (`src/lib/server-identity.ts`)
  pairs the operator nickname with the relay host in monospace everywhere, so staging and production
  are always disambiguated. The `ScreenShell` UI primitive reserves a server slot for the active
  pairing display.
- **New UI primitives**: `ui/Toggle.svelte` (switch; state by position + on/off text, not
  color), `ui/ErrorState.svelte` (a classified failure → chip + message + recovery CTA),
  and `CodeOutput`'s optional `onshare` Share affordance. All exercised at `/preview`.

## Contracts

### Rust backend (`src-tauri/`)
- `device_key::get_or_create() -> Result<DevicePublicKey, DeviceKeyError>` — idempotent;
  returns `{ multibase, keyId }` (camelCase for IPC). Same crypto as identity-wallet's
  module; here the key is the device's **admin credential** (signs requests), not a
  did:plc rotation key.
- `device_key::sign(data) -> Result<Vec<u8>, DeviceKeyError>` — raw 64-byte (r‖s),
  **low-S normalized** P-256 signature (the relay's verifier rejects high-S).
- `DeviceKeyError` / `RelayClientError` serialize as `{ code: "SCREAMING_SNAKE_CASE", … }`.
  The biometric-pref IPC commands surface keychain errors through `RelayClientError::Keychain`
  (the app's single Serialize error type) rather than exposing `KeychainError` directly.
- Keychain accounts: device-key accounts unchanged (`admin-device-key-priv`, `admin-device-key-pub` +
  `admin-device-key-app-label`); `admin-pairings` (the versioned multi-relay document, replaces the
  legacy triple); `admin-biometric-enabled` (the gate preference, unchanged). Removal semantics:
  a sole remaining pairing is always auto-promoted to active (unambiguous — even when the selection
  was already cleared by an earlier ambiguous removal); removing the active pairing with two or
  more remaining clears the selection and the UI must ask for an explicit pick (never silent
  relay switch). A corrupt document (parse error, version mismatch, invalid active reference) is a
  hard error surfaced as `RelayClientError::Keychain` — never a silent reset, which would be
  indistinguishable from a successful unpair. Removing a pairing returns the `NO_SUCH_PAIRING` error
  code when the id does not exist. "Unpair" is local-only (removes a pairing document entry) and keeps
  the device key (so a re-pair is recognised by the same public key) and keeps `admin-biometric-enabled`
  (a device setting, not pairing state).
- **Signing contract is single-source-of-truth and must stay in lockstep with the relay.**
  `signing.rs`'s golden tests pin the exact literals the relay's `auth.rs` tests pin; if the
  relay changes an envelope, both tests break together. Signatures are low-S P-256, raw r‖s,
  base64url-no-pad; the body field is `sha256_hex(exact_request_bytes)`. The client serializes
  a request body **once** and signs+sends those same bytes so the relay's recomputed hash matches.

### Frontend

- `src/lib/ipc.ts` is the **only** file that calls `invoke()`; pages import from it.
- SSR/prerender disabled globally (`src/routes/+layout.ts`); static SPA in `dist/`.
- **Pairing QR payload** is JSON `{"relayUrl","pairingCode"}` (parsed by
  `parsePairingPayload`); the operator's code-minting tool encodes it. Manual entry fills the
  same two fields, so pairing works on the simulator (no camera).
- **Mobile-only plugins** (camera QR, biometric, share) follow one pattern: the Rust dep is
  `cfg(target_os ios/android)`-gated in `Cargo.toml`, registered behind `#[cfg(mobile)]` in
  `lib.rs`, granted in `src-tauri/capabilities/mobile.json` (`platforms: [iOS, android]`), and
  imported **dynamically** in JS so the host/desktop build never resolves it. The host build
  skips the mobile capability, so `cargo build/test -p admin-companion` stays Apple-toolchain-free.
  - `@tauri-apps/plugin-barcode-scanner` (camera QR on Pair) — `NSCameraUsageDescription`.
  - `@tauri-apps/plugin-biometric` (`barcode-scanner`/`biometric`/`sharesheet` `:default` ACLs)
    drives the **user-presence gate**: `src/lib/biometric.ts` `requireUserPresence(reason)` is
    called before every signing action (claim code, self-revoke). Needs `NSFaceIDUsageDescription`.
    Whenever the plugin is present the gate ALWAYS runs `authenticate()` (biometric-or-passcode via
    `allowDeviceCredential`) — it never pre-skips on `checkStatus().isAvailable`, which is false on a
    passcode-only device even though the passcode could still gate authentication. The gate resolves to allow only when the
    plugin module can't be imported at all (off-device desktop/host) or with the Settings toggle off;
    a cancelled/failed prompt, or no credential enrolled, blocks. The toggle is
    `set_biometric_enabled` (default on).
  - `@buildyourwebapp/tauri-plugin-sharesheet` — `src/lib/share.ts` `shareText()` opens the iOS
    Share Pane for a claim code; returns `false` off-device so the UI falls back to copy.
  - `capabilities/default.json` grants only `log:default` on all platforms (least
    privilege — the frontend uses no core API; see `docs/security/tauri-ipc-boundary.md`
    and `just cap-check`). App-defined commands are allowed by default and need no entry.
- **Design tokens are the live system.** Reference `var(--color-*)` / `var(--font-*)` /
  `var(--space-*)`; never hardcode hex/px. Every text pair in `tokens.css` is verified to
  clear **WCAG 2.2 AAA (≥7:1)** on its intended ground (the seed anchors were AA; they
  were lifted to clear AAA). Status is color **+ glyph + text**, never color alone.

## Build & run (macOS + Xcode)

```bash
nix develop --impure --accept-flake-config   # from workspace ROOT
cd apps/admin-companion && pnpm install
cargo tauri ios init                          # generates gitignored src-tauri/gen/ (renders scripts/ios/project.yml)
cd ../.. && just admin-postinit               # swift-rs check + app icon + verify (idempotent)
just admin-dev                                # simulator   (or: just admin-build)
```

Host build / tests (no Xcode): `cargo build -p admin-companion`, `cargo test -p admin-companion`.

## Key decisions

- **Toolchain scripts are SHARED, design is forked.** The iOS toolchain scripts
  (`scripts/ios-env.sh`, `ios-postinit.sh`, `ios-check.sh`) are thin wrappers over the
  single shared implementation in the repo-root `scripts/ios/` (each wrapper pins this
  app's dir and the `admin` recipe prefix), and the Xcode-project workarounds come from
  the SHARED XcodeGen template `scripts/ios/project.yml` (rendered on every
  `cargo tauri ios init` via `bundle > iOS > template`), so neither the script logic nor
  the project workarounds can diverge between the two app lanes. This app's framework
  list lives in its `tauri.conf.json` `bundle > iOS > frameworks` — just
  `SystemConfiguration`; no AuthenticationServices, this app has no in-app OAuth
  plugin. The
  OKLCH token *architecture* is forked from identity-wallet — but the token *values*,
  components, and product/design briefs are this app's own terminal-native register.
  See the root `apps/identity-wallet/CLAUDE.md` for the full explanation of every iOS
  patch and the toolchain seam; it is the single source of truth for those gotchas
  (this app reuses the same swift-rs `[patch.crates-io]`).
- **Excluded from the Linux CI gate** (`just ci-pds`) like identity-wallet: it needs the
  Apple `security-framework` toolchain. Built/checked on macOS via `just admin-*`.
- **Grotesk UI font is provisional** (system SF Pro via `--font-sans`) until the
  `/impeccable` font pass; JetBrains Mono (the signature voice) is bundled in `static/fonts/`.
- **App icon: `app-icon.svg` is the source of truth** (brand rationale in DESIGN.md §6);
  `app-icon.png` is its 1024×1024 render and the input `cargo tauri icon` consumes.
  `just admin-postinit` regenerates the gitignored AppIcon asset catalog from
  it after every `cargo tauri ios init` (desktop/android outputs go to the gitignored
  `src-tauri/icons-build/`), and `just admin-check` verifies the catalog was built from
  the current PNG via a sha256 marker. To change the icon: edit the SVG, re-render the
  PNG at 1024×1024 (e.g. resvg), commit both, re-run `just admin-postinit`.
  **`AppIcon.icon/` is the layered Icon Composer document** (icon.json + `Assets/*.svg`
  layers split from the same master — no baked shadows; Liquid Glass supplies lighting):
  the XcodeGen template (`scripts/ios/project.yml`) references it in place as a resource
  so Xcode 26 renders the layered iOS 26 icon (the flat appiconset stays as the
  older-toolchain fallback), and `just admin-pr-check` compiles it with actool
  (`just _icon-compile`) so a bad icon.json fails the PR gate. Keep the layer geometry
  in sync with `app-icon.svg`.
- **Distinct Keychain namespace** (`"ezpds-admin-companion"`) and bundle id
  (`dev.malpercio.admincompanion`) so the two apps never collide on one device.
