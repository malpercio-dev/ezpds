# Admin Companion (operator console) Mobile App

Last verified: 2026-07-10
Last updated: 2026-07-17 (documented the MM-281 relay-status readout — `get_relay_status`/`request_crawl` IPC + the Home relay-status block)

## Purpose

Tauri v2 iOS app — SvelteKit 2 + Svelte 5 frontend in a WKWebView over a Rust
backend, communicating through Tauri IPC. The operator-facing console for an ezpds
relay: generate/share account claim codes, pair admin devices via QR, and revoke
devices. A **separate product** from identity-wallet (Obsign) with its own
terminal-native design register — see [PRODUCT.md](PRODUCT.md) / [DESIGN.md](DESIGN.md)
and the design plan [docs/archive/design-plans/2026-06-26-admin-companion-app.md](../../docs/archive/design-plans/2026-06-26-admin-companion-app.md).

The relay side (pairing/auth/device endpoints, Phases 1–5) is already shipped. This
app is built across Phases 6–8.

## Browser test harness (drive the app without a simulator)

The whole frontend runs in a plain desktop browser under `vite dev`; the harness
intercepts the Tauri `invoke()` seam with the official `mockIPC` so an agent can reach
every operator screen and reproduce any state without a Mac/Xcode/simulator. Mirrors the
identity-wallet harness exactly (same `window.__harness` API shape). Design + acceptance
criteria: [docs/archive/design-plans/2026-07-12-browser-harness.md](../../docs/archive/design-plans/2026-07-12-browser-harness.md).

**Start it** (or use the `.claude/launch.json` config `admin-harness` / `admin-harness-proxy`):
- **Fake mode** (default, no backend): `pnpm --dir apps/admin-companion dev:harness` → http://localhost:5174.
- **Proxy mode** (real signed operator requests against a hermetic local PDS): `cargo build -p pds`,
  then `just harness-pds` (prints URL + admin token), then
  `VITE_HARNESS_PDS_URL=<url> VITE_HARNESS_ADMIN_TOKEN=<token> pnpm --dir apps/admin-companion dev:harness:proxy`.
  Proxy mode starts **unpaired** by default — pair for real from the Pair screen (the
  harness mints the pairing code via the admin API and self-signs the registration).
- Plain `pnpm dev` never activates the harness (double-gated on `import.meta.env.DEV && VITE_HARNESS`);
  `pnpm check:harness-absence` proves it is tree-shaken out of production builds.

**`window.__harness` console API:** `.scenario(name)` (presets: `unpaired`, `single-relay`,
`multi-relay`, `degraded-health`; `.scenarios` lists them), `.failNext(command, error)`
(e.g. `window.__harness.failNext('generate_claim_code', { code: 'NOT_PAIRED' })`),
`.emit(event, payload)` (kept for parity — this app subscribes to no Tauri events),
`.state()` (read-only snapshot), `.mode`.

**Biometric gate:** the plugin is allowed to resolve in the browser (`plugin:biometric|authenticate`),
so signing actions proceed. To exercise the disabled path, set it off via the Settings
toggle / `set_biometric_enabled(false)` (outcome `skipped`); to force a denial, use
`window.__harness.failNext('plugin:biometric|authenticate', {})`. Do **not** try to drive
QR-scan pairing in the browser — barcode scanning is out of scope; use the Pair screen's
manual-entry fields (fake) or auto-mint (proxy).

**Proxy mode is real for the signed-request surface** — `pair_device`, `generate_claim_code`,
and `list_admin_devices` sign the canonical envelopes (`src/lib/harness/proxy/signing.ts`,
byte-for-byte the Rust `signing.rs`) with a real WebCrypto P-256 key, and the relay's
`require_admin` accepts them. Every other command falls through to the fake.

**Fake handler coverage is enforced:** every command in `$lib/ipc.ts` must have a handler in
`src/lib/harness/registry.ts` or `registry.test.ts` fails. Harness code lives in
`src/lib/harness/`, activated by `src/hooks.client.ts`.

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
  for the target pairing's device id), `unpair` (local-only forget — no relay call),
  `list_devices` (signed `GET /v1/admin/devices` for an id-addressed pairing; returns the
  relay's `AdminDeviceView` rows — active and revoked — as `AdminDevice`, a by-value copy
  of that wire shape pinned by a deserialization test), `revoke_device` (signed remote
  revoke of ANOTHER device on that pairing's relay; a self-target is refused with
  `SELF_REVOKE_NOT_ALLOWED` before signing — self-revoke is `revoke_self`, which also
  removes the local pairing), `get_subject_status`/`update_subject_status` (signed account
  takedown lookup/write against `com.atproto.admin.getSubjectStatus`/`updateSubjectStatus` for
  an id-addressed pairing; the GET signs the **bare path** and appends `?did=` to the URL only —
  the relay verifies `uri.path()`, query excluded — and the POST body is exactly
  `{subject: {$type, did}, takedown: {applied}}`, pinned because the relay's subject parse is
  deny-unknown-fields), `get_account_usage`/`get_account_storage` (signed GETs against
  `/v1/accounts/{did}/usage`/`…/storage` for an id-addressed pairing; the DID rides in the
  *path*, so it is inside the signed envelope — a metrics signature is bound to its account),
  `list_accounts` (signed `GET /v1/admin/accounts` for an id-addressed pairing: DID-cursor
  pagination + derived-status filter + handle/DID substring search; like the status lookup,
  the BARE path is signed and the paging/filter query params are appended after signing, so
  every page reuses the same envelope shape — `AccountList`/`AccountListEntry` are by-value
  copies of the wire shape pinned by a deserialization test),
  `get_server_health` (a signed `GET /v1/admin/health` for an id-addressed pairing — the
  Status screen's data source: version/uptime, account counts by lifecycle, blob/block
  totals, firehose state, and background-sweep last-runs as `ServerHealth`, a by-value
  copy of the wire shape pinned by a deserialization test; the relay reports literal
  facts only, so all staleness judgment is client-side),
  `list_claim_codes`/`revoke_claim_code` (the claim-code inventory: a signed
  `GET /v1/accounts/claim-codes` — bare path signed, pagination `cursor` appended to the URL
  only, like the moderation GET — and a signed `POST /v1/accounts/claim-codes/revoke` whose
  JSON body carries the code, so a revoke signature is bound to its code),
  `list_transfers`/`cancel_transfer` (in-flight device-transfer visibility/interrupt: a signed
  `GET /v1/admin/transfers` — bare path signed, pagination `cursor` appended to the URL only —
  and a signed `POST /v1/admin/transfers/{id}/cancel` whose transfer id rides in the *path*, so
  a cancel signature is bound to its transfer; the relay never reports the transfer code, and
  `TransferList`/`TransferEntry`/`CancelledTransfer` are by-value copies of the wire shape
  pinned by a deserialization test),
  `revoke_account_credentials` (the operator kill-switch for a compromised account: a signed
  `POST /v1/admin/accounts/{did}/revoke-credentials` — the DID rides in the *path*, so a sweep
  signature is bound to its account; the relay atomically revokes the account's sessions,
  app passwords, OAuth grants/pending codes, and promoted transfer-device tokens — never the
  main password — and reports literal per-family counts as `RevokedCredentials`, a by-value
  copy of the wire shape pinned by a deserialization test), plus
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
  `list_admin_devices(pairing_id)` (signed device list from that pairing's relay),
  `revoke_admin_device(pairing_id, device_id)` (signed remote revoke of another device;
  self-target → `SELF_REVOKE_NOT_ALLOWED`),
  `get_subject_status(pairing_id, did)` (signed takedown-status lookup; unknown DID →
  `RELAY_REJECTED` 404), `update_subject_status(pairing_id, did, applied)` (signed
  account takedown/restore; idempotent server-side, returns the resulting state),
  `get_account_usage(pairing_id, did)` / `get_account_storage(pairing_id, did)` (signed
  per-account usage/storage metrics reads; same error surface as the status lookup),
  `list_accounts(pairing_id, limit?, cursor?, status?, q?)` (signed account-list page read),
  `get_server_health(pairing_id)` (signed server-health readout; same error surface as the
  other signed reads),
  `list_claim_codes(pairing_id, cursor?)` (signed inventory page: every minted code with its
  derived status, newest first) / `revoke_claim_code(pairing_id, code)` (signed revoke of a
  live code; already-revoked is idempotent 200, redeemed → `RELAY_REJECTED` 409, unknown → 404),
  `list_transfers(pairing_id, cursor?)` (signed in-flight device-transfer page: every planned
  swap that can still advance, newest first, never the code) / `cancel_transfer(pairing_id,
  transfer_id)` (signed operator interrupt; repeat is idempotent 200, completed/expired →
  `RELAY_REJECTED` 409, unknown → 404),
  `revoke_account_credentials(pairing_id, did)` (signed account-wide credential sweep; repeat
  sweeps are idempotent 200s of zero counts, unknown DID → `RELAY_REJECTED` 404),
  `get_relay_status(pairing_id)` (signed federation-health read from `GET /v1/admin/relay-status`:
  whether the upstream relay is reachable/crawling us, its cursor, and the signed gap behind our
  head — verdict-free; the ok/warn/behind thresholds live in the pure, unit-tested
  `relay-status.ts`, not the endpoint) / `request_crawl(pairing_id)` (signed re-invite via
  `POST /v1/admin/request-crawl`, bypassing the auto-notify rate limit; reports each relay's outcome),
  `biometric_enabled`, `set_biometric_enabled` (plus Phase 6's `get_or_create_device_key`).
  `pairing_state` is gone — superseded by `list_pairings`.
- **Screens**: **Pair** (`src/routes/pair/` — QR/manual + required nickname, reachable while
  paired), **Home** (`src/routes/+page.svelte` — biometric-gated claim code for the *active*
  server, tappable identity block → inline switcher, explicit-pick state when no active pairing,
  plus a relay-status block — reachable / crawling / behind-by-N / not-seen as text + icon, never
  color alone, polling every 15s with a biometric-gated "Request crawl" action),
  **Settings** (`src/routes/settings/` — per-server list with per-entry rename / revoke-on-server /
  forget-locally / view-devices link, global admin key display, biometric toggle, all revokes
  biometric-gated), **Devices** (`src/routes/devices/` — the loss-response screen: every
  device registered on ONE relay, active and revoked, with a biometric-gated remote revoke for a
  lost device. Pinned to a single pairing at entry — `?server=<pairingId>` from Settings, else the
  active pairing — so a concurrent active switch on Home can't redirect what it shows or signs.
  The row whose relay id equals the pairing's `deviceId` is marked "this device" and its revoke
  defers to Settings), **Accounts** (`src/routes/accounts/` — the per-account hub:
  every account on ONE relay in DID order with search (handle/DID substring), derived-lifecycle
  filter chips, cursor-paged "Load more", and a per-row monospace blob-quota readout
  (`format.ts` `quotaBar`: `[▓▓░░░] 42.00%`, fill floors — a cell lights only when fully
  earned — with a ` !` glyph at ≥90%, never color alone) rendered by the `ui/AccountRow.svelte`
  primitive (DeviceRow's register + the quota line; lifecycle chip per row). Pinned to a single
  pairing at entry like Devices/Moderation; tapping a row hands the DID to **Account detail** via
  `?server=…&did=…` — replacing DID-pasting as the entry point for per-account work),
  **Account detail** (`src/routes/account/` — the read-only inspection home for one account:
  identity facts plus the **Usage & storage** readout panel — records/commits/blobs/stored
  bytes/last-active plus blob quota (used-of-total + %) and largest blob, byte figures via
  `format.ts` `formatBytes`/`formatPct` — moved here from the moderation screen so a read-only
  inspection task no longer lives on a destructively-framed screen. Pinned to a single pairing
  at entry (`?server=…&did=…`); nothing here signs — a "Take down or restore" entry point hands
  the same pin + DID to Moderation, which pre-fills the lookup field and runs the lookup
  immediately), **Moderation** (`src/routes/moderation/` — account takedown/restore:
  DID lookup → status panel → armed two-tap confirmation (the first tap swaps the destructive
  button for a Confirm/Cancel pair restating the relay-confirmed target) → biometric gate →
  signed write. Pinned to a single pairing at entry like Devices; the write always targets the
  DID from the last successful *lookup*, never the raw input field, and the action area goes
  stale — auto-disarming — the moment the input drifts from what was looked up. Below the
  status panel sits **Credential revocation**, the incident-response follow-up to a takedown:
  a second, independently-armed two-tap + biometric-gated destructive action that sweeps every
  credential of the looked-up account (sessions, app passwords, OAuth grants, transfer-device
  tokens — never the main password) and renders the relay's literal per-family counts as a
  fact sheet, no optimistic edit. The usage/storage readout that used to load here lives on
  **Account detail** now, restoring this screen to its destructive framing only),
  **Codes** (`src/routes/codes/` — the claim-code inventory:
  every code minted on ONE relay with its derived lifecycle status (`pending`/`redeemed`/
  `expired`/`revoked` — terminal events win over the clock), split by `src/lib/claim-codes.ts`
  (Functional Core: `partitionCodes`/`chipFor`/`timelineLine`, unit-tested) into an
  **Outstanding** panel (live credentials, expandable rows with a biometric-gated revoke) and a
  **History** panel (terminal codes, facts only). Pinned to a single pairing at entry like
  Devices (`?server=<pairingId>`, else active); pages older codes via the relay cursor with a
  "Load older codes" button; a revoke reloads the inventory so rows report the relay's
  post-revoke truth, never an optimistic edit. Reached from Home's Codes button),
  **Status** (`src/routes/status/` — ONE relay's server-health readout off
  `GET /v1/admin/health`: version/uptime, account counts by lifecycle, blob/block totals,
  firehose state, and background-sweep last-runs as literal fact sheets. Pinned to a single
  pairing at entry like Devices (`?server=<pairingId>`, else active); reads only, no
  biometric gate; Refresh uses the accounts screen's generation-counter guard. The relay
  reports raw facts with no verdicts, so all presentation judgment lives in
  `src/lib/health.ts` (Functional Core, unit-tested): `formatDuration` (uptime/ages),
  `formatBackfillWindow` (`null` → "empty log"), and `sweepLine` (`not yet run` vs
  `<age> ago · swept <n>`, with a trailing `!` staleness glyph at ≥24h — glyph, never color alone).
  Reached from Home's Status button),
  **Transfers** (`src/routes/transfers/` — in-flight planned device swaps on ONE relay: every
  transfer that can still advance, newest first, with `src/lib/transfers.ts` (Functional Core:
  `chipFor`/`timelineLine`/`accountLabel`, unit-tested) mapping each state-machine status to
  its chip — `accepted`/`completing` get the alarm tone, since the target device already holds
  a working credential. Expandable rows carry a fact sheet and a biometric-gated **Cancel this
  transfer** (the operator interrupt: the relay flips the transfer terminal and tombstones the
  accepted device credential; the account's sessions are untouched — the credential sweep on
  Moderation composes for a compromised account). Pinned to a single pairing at entry like
  Devices (`?server=<pairingId>`, else active); pages via the relay cursor; a cancel reloads
  the list so it reports the relay's post-cancel truth. The transfer code never appears —
  the relay does not return it. Reached from Home's Transfers button). The
  error-state matrix (not-paired / clock-skew / revoked / unreachable / not-found) is rendered by the shared
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

- `src/lib/ipc.ts` is the **only** file that calls `invoke()`; pages import from it. Pure
  parsers that carry no IPC (e.g. `parsePairingPayload`) live in their own modules, not `ipc.ts`.
- **Shared route helpers** factor out the three copy-paste patterns the per-server operator
  screens repeated. The security-relevant "pin the pairing at entry so a concurrent active
  switch can't redirect what a screen reads or signs" logic lives once:
  - `src/lib/pinned-pairing.ts` (Functional Core) — `resolvePinnedPairing(state, searchParams)`
    (pin from `?server=`, else the active pairing), `loadPinnedPairing(searchParams)` (the
    `onMount` load + resolve), and `pinnedHref(path, pairingId, extra?)` (uniform `?server=…`
    link construction). Rendered by `components/ui/PinnedPairingGate.svelte`, which shows the
    three pre-flight states (checking / check-failed / no-server) and hands the resolved,
    non-null pairing to its `children` snippet. Used by Devices, Codes, Accounts, Account
    detail, Moderation, Status, Transfers.
  - `src/lib/guarded-action.svelte.ts` — `createGuardedActions()`: a reactive controller owning
    the per-row busy/error maps + one gate-hint line for a biometric-gated relay action (busy
    flag claimed synchronously before the gate await; a denial is a quiet hint). Used by
    Devices/Codes/Transfers. (Settings keeps its own revoke logic — it shares one gate hint with
    the non-gated local-forget and reloads on error, a different shape.)
  - `src/lib/paged-list.svelte.ts` — `createPagedList(fetchPage)`: a reactive controller for a
    cursor-paged relay list (loading/error/ready-with-cursor + a separate paging-error slot so a
    failed page keeps the shown rows). Used by Codes/Transfers. (Accounts keeps its own
    generation-counter pagination — it layers search + filter re-fetches on top.)
  - `src/lib/armed-action.svelte.ts` — `createArmedAction()`: a reactive controller for an armed
    two-tap + biometric-gated destructive action (arm → confirm → gate → run, with an optional
    `commit` guard so a slow write can't land under a newer lookup). Moderation runs two
    independent instances (takedown + credential sweep), each treating the other's `writing` as a
    lock so two prompts never stack.
- SSR/prerender disabled globally (`src/routes/+layout.ts`); static SPA in `dist/`.
- **Pairing QR payload** is JSON `{"relayUrl","pairingCode"}` (parsed by
  `parsePairingPayload` in `src/lib/pairing-payload.ts`); the operator's code-minting tool encodes
  it. Manual entry fills the same two fields, so pairing works on the simulator (no camera).
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
  See the root `apps/identity-wallet/AGENTS.md` for the full explanation of every iOS
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
