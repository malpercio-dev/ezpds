# Browser Test Harness for the Mobile Apps Design

Tracking issue: [MM-324](https://linear.app/malpercio/issue/MM-324/browser-test-harness-for-the-mobile-apps-mock-ipc-fake-pds-proxy-mode)

Status: **landed** — the mock-IPC fake + PDS-proxy harness shipped in #283 (MM-324).

## Summary

Both mobile apps' frontends already run fine under a plain browser dev server — Svelte doesn't need Tauri to render. The only thing that breaks is the seam where each frontend calls into native Rust code. This design closes that gap by intercepting calls at that single seam, using Tauri's own `mockIPC` test utility, rather than by rewriting or aliasing any app code. A small activation file (`hooks.client.ts`) checks a dev-only environment flag and, only then, swaps in one of two handler sets: a stateful in-memory "fake" that models each app's domain objects (identities, pairings, claim codes, etc.) in plain TypeScript and is driven at runtime through a `window.__harness` console API (switch scenarios, force a specific command to fail, deliver an event) — or a "proxy" mode that forwards the subset of commands that are thin HTTP wrappers to a real, hermetically-spawned local PDS, using a real WebCrypto keypair for signatures. Commands that embed substantial Rust-side logic (repo migration, DID ceremony internals, OAuth) stay faked even in proxy mode, since re-implementing them in TypeScript would be its own maintenance burden with limited payoff.

The two apps share no frontend code today, so rather than introduce a shared package the harness is implemented twice, with a deliberately identical file layout and API shape per app. Work proceeds in seven phases: wallet fake mode, wallet scenarios/control API, admin-companion's equivalent, a shared hermetic-PDS spawn recipe plus a dev-server proxy route (keeping requests same-origin to sidestep CORS), each app's proxy mode, and finally a documented runbook (`.claude/launch.json` entries plus AGENTS.md sections) so an agent can start and drive either harness without re-deriving any of this. A build-output check guards against the harness ever leaking into a production build.

## Definition of Done

1. An agent (or a human) can boot each mobile app's frontend (identity-wallet and admin-companion) in a plain desktop browser with a single command and reach every screen, with no Tauri runtime present.
2. **Fake mode** is the default: a stateful in-memory fake stands in for the Rust backend. It is scriptable — named scenario presets plus per-command error injection, controllable at runtime from the browser console via a `window.__harness` API — so any UI state (including rare error states) can be produced on demand.
3. **Proxy mode** is available as an opt-in: commands that are thin HTTP wrappers over the PDS/relay API execute for real against a live Custos instance (a hermetic locally spawned PDS by default), with real P-256 signatures produced by WebCrypto. Commands that embed heavy Rust logic (repo migration legs, DID ceremony internals) remain faked in proxy mode and are documented as such.
4. Harness code is provably absent from production builds — the activation seam is dev-gated and a build-output check enforces it.
5. A runbook exists (per-app AGENTS.md sections + `.claude/launch.json` entries) so a fresh agent session can start either app's harness and drive it without re-deriving any of this.

Out of scope (deliberately): iOS-simulator automation (idb/XCUITest — separate effort), barcode-scan simulation (manual pairing entry already exists), and emulating ASWebAuthenticationSession for the wallet's OAuth flow (stays faked in both modes).

## Acceptance Criteria

### browser-harness.AC1: Apps boot and are fully navigable in a plain browser
- **browser-harness.AC1.1 Success:** `VITE_HARNESS=fake pnpm dev` in `apps/identity-wallet/` serves the wallet; the app loads with no uncaught errors and no failed `invoke` in the console.
- **browser-harness.AC1.2 Success:** Same for `apps/admin-companion/`.
- **browser-harness.AC1.3 Success:** Every registered Tauri command called by either frontend has a fake handler; a command added to `ipc.ts` without a corresponding handler fails `pnpm check` or `pnpm test` (coverage is enforced, not aspirational).
- **browser-harness.AC1.4 Success:** The wallet's `auth_ready` Tauri event path works in the browser: `listen()` does not throw, and the harness can deliver the event.
- **browser-harness.AC1.5 Success:** Plain `pnpm dev` (no `VITE_HARNESS`) behaves exactly as today — the harness never activates implicitly.

### browser-harness.AC2: Fake mode is stateful and scriptable
- **browser-harness.AC2.1 Success:** State persists across commands within a session: e.g. in the wallet, completing the create flow makes the new identity appear in `list_identities`; in admin, `pair_device` makes the pairing appear in `list_pairings` and `unpair` removes it.
- **browser-harness.AC2.2 Success:** `window.__harness.scenario(name)` switches to a named preset and the UI reflects it after reload/re-render (wallet: at minimum fresh-install, one-identity, migration-in-flight, agent-connected; admin: at minimum unpaired, single-relay, multi-relay, degraded-health).
- **browser-harness.AC2.3 Success:** `window.__harness.failNext(command, error)` causes the next call of that command to reject with the given typed error shape (e.g. `{ code: 'EXPIRED_CODE' }`), and the UI shows the corresponding error state.
- **browser-harness.AC2.4 Success:** `window.__harness.emit(event, payload)` delivers a Tauri event to live `listen()` subscribers (used for the wallet's OAuth-return simulation).
- **browser-harness.AC2.5 Success:** The fake store logic has vitest coverage following the existing co-located `*.test.ts` pattern.

### browser-harness.AC3: Proxy mode runs real flows against a real PDS
- **browser-harness.AC3.1 Success:** With `VITE_HARNESS=proxy` and a PDS base URL configured, the wallet's create-account flow (claim code → account → visible in `list_identities`) completes against a hermetic locally spawned PDS, with the account observable via the PDS admin API.
- **browser-harness.AC3.2 Success:** The device key in proxy mode is a real WebCrypto P-256 keypair; `sign_with_device_key` returns signatures that the PDS accepts where it verifies them.
- **browser-harness.AC3.3 Success:** The admin app in proxy mode completes a real pairing (claim code minted via the PDS admin API), and signed operator requests (e.g. `generate_claim_code`, `list_admin_devices`) succeed against the local PDS.
- **browser-harness.AC3.4 Success:** A `just` recipe spawns the hermetic PDS for harness use (reusing the `tools/mcp/test/harness.ts` approach: local binary, mock plc.directory, throwaway admin token) and prints the URL/token to configure the harness.
- **browser-harness.AC3.5 Edge:** Browser-origin issues (CORS) do not block proxy mode — requests are routed through the vite dev-server proxy, so no CORS changes land in the PDS itself.
- **browser-harness.AC3.6 Failure:** Commands documented as fake-only (migration transfer legs, DID ceremony internals, OAuth completion) behave identically in proxy mode as in fake mode, and the runbook lists them.

### browser-harness.AC4: Harness is absent from production builds
- **browser-harness.AC4.1 Success:** `pnpm build` output for each app contains no harness code (checked by a script that greps the build output for a harness marker; wired into each app's test or check flow).
- **browser-harness.AC4.2 Success:** The activation seam is statically dev-gated (`import.meta.env.DEV`) in addition to the env flag, so a production build cannot activate the harness even if `VITE_HARNESS` leaks into the build environment.

### browser-harness.AC5: Agent runbook
- **browser-harness.AC5.1 Success:** `.claude/launch.json` has named configurations to start each app's harness dev server.
- **browser-harness.AC5.2 Success:** Each app's AGENTS.md documents: how to start each mode, the `window.__harness` API, the scenario list, and the fake-only command list in proxy mode.

## Glossary

- **Tauri**: The framework both apps are built on — a native app shell (here, iOS) that hosts a web frontend and exposes native/Rust capabilities to it. The harness's whole job is to make a Tauri app run without the native shell.
- **Tauri command / `invoke`**: A Rust function exposed to the frontend via `#[tauri::command]`, called by name from JS through `invoke()`. Every native capability (crypto, keychain, biometrics) goes through one.
- **`mockIPC` / `__TAURI_INTERNALS__`**: Tauri's own test utility (`@tauri-apps/api/mocks`) for replacing `__TAURI_INTERNALS__`, the internal object `invoke`/`listen` calls actually hit, with JS handlers. This is the interception point the harness uses instead of touching app code.
- **Vite / vite dev server proxy**: The build tool/dev server both apps already run under. Its dev-server proxy feature lets the browser call a same-origin path (e.g. `/__pds/*`) that vite forwards server-side to the real PDS, avoiding browser CORS restrictions.
- **`import.meta.env` / `VITE_*` env vars**: Vite's mechanism for exposing environment variables to frontend code; `VITE_HARNESS` is the flag that activates the harness, and `import.meta.env.DEV` is the static guard that keeps it out of production builds.
- **Tree-shaking**: A bundler optimization that strips code no production import path reaches. Relied on here (via a dynamic import gated by `DEV`) to prove the harness is physically absent from shipped builds.
- **WebCrypto (P-256)**: The browser's built-in cryptography API. Proxy mode uses it to generate a real elliptic-curve (P-256) keypair and produce real signatures, standing in for the on-device key.
- **Secure Enclave**: Apple's hardware-isolated crypto coprocessor that normally holds the device's private signing key on a real iPhone. A browser can't emulate it, which is why proxy mode substitutes a software WebCrypto key instead.
- **CORS (Cross-Origin Resource Sharing)**: The browser security policy blocking a page from calling an API on a different origin directly. Proxy mode avoids it via the vite dev-server proxy rather than loosening the PDS's own CORS policy.
- **ASWebAuthenticationSession**: Apple's iOS API for presenting a system browser sheet during OAuth. It has no browser equivalent, so the wallet's OAuth completion stays faked in every harness mode.
- **XCUITest / idb**: Apple's UI-testing framework and Meta's iOS device bridge — the tooling that would drive an actual iOS Simulator. Explicitly out of scope for this harness (a separate future effort).
- **PDS (Personal Data Server) / Custos**: The ATProto-compatible backend server this repo builds (`crates/pds`); "Custos" is its product name. It owns accounts, repos, and blobs, and is what proxy mode talks to for real.
- **did:plc / plc.directory**: The ATProto DID method whose source of truth is a hosted directory service. "Mock plc.directory" means the hermetic PDS uses a local stand-in so the harness never touches the live network.
- **DID (Decentralized Identifier) / DID ceremony**: The cryptographic identity document at the core of the wallet, and the Rust-side process (genesis, key rotation) that creates/updates it. Called out as one of the "heavy logic" command groups that stay faked even in proxy mode.
- **Claim code**: A one-time code used to bootstrap a new wallet account, or to pair an admin device with a relay/PDS.
- **Admin token**: The credential used to authenticate against the PDS's administrative API; the hermetic PDS recipe mints a throwaway one for harness use.
- **Hermetic (PDS instance)**: A locally spawned, network-isolated PDS (with a mocked did:plc directory) so proxy-mode testing never depends on or reaches a live external service.
- **Identity wallet (Obsign)**: One of the two apps this harness covers — the end-user mobile app for holding and managing an ATProto identity.
- **Admin-companion (Brass Console)**: The other app — an operator console for pairing with and managing one or more relays/PDS instances.
- **Agent** (as in "agent-connected" scenario, "agent list/revoke/audit"): In this codebase, a third-party application granted delegated access to a user's account — not an AI agent.
- **Repo migration transfer legs**: The Rust-side steps (`transfer_repo`, `transfer_blobs`, etc.) that move a user's data during an account migration; named as logic-heavy commands that stay faked in proxy mode rather than reimplemented in TypeScript.

## Architecture

Both apps are SvelteKit 2 / Svelte 5 frontends that already run under plain `vite dev`; the only thing that breaks in a browser is the Tauri seam. Both apps route **all** native calls through one IPC surface per app — `apps/identity-wallet/src/lib/ipc/` (~45 commands split into per-domain modules re-exported from `index.ts`, plus a `listen('auth_ready')` event subscription in `src/routes/+page.svelte`) and `apps/admin-companion/src/lib/ipc.ts` (~28 commands; its header already documents it as the only file that calls `invoke()` directly). The mobile plugins (biometric, sharesheet, barcode scanner) are dynamically imported and already degrade gracefully off-device.

The harness intercepts at the `invoke` layer using Tauri's official mock (`mockIPC`/`mockWindows` from `@tauri-apps/api/mocks`), which replaces `__TAURI_INTERNALS__` — no app code changes its imports. Two modes share one activation seam and one command registry; only the handlers differ.

### Components (per app, mirrored structure)

Each app gets a `src/lib/harness/` directory. The apps share no frontend code today (there is no root pnpm workspace), so the harness is implemented per-app with a deliberately parallel layout:

- `install.ts` — installs `mockIPC`, dispatches command name → handler from the registry, and bridges the Tauri event plugin so `listen()`/`emit()` work (in Tauri v2, `listen` itself flows through `invoke('plugin:event|listen', …)`, so the mock must handle it rather than crash).
- `registry.ts` — the command table. Typed against a union of command names derived from the app's IPC surface, so adding a command to `ipc.ts` without a handler is a type/test failure (AC1.3).
- `state.ts` — the stateful in-memory fake: identities/DID docs/agents for the wallet; pairings/devices/accounts/claim codes/transfers/health for admin. Pure TS, vitest-tested.
- `scenarios.ts` — named presets that seed `state.ts`.
- `control.ts` — the `window.__harness` runtime API: `scenario(name)`, `failNext(command, error)`, `emit(event, payload)`, `state()` (read-only inspection). This is the surface an agent drives from the browser console.
- `proxy/` — proxy-mode handlers plus the WebCrypto P-256 device key. Handlers for thin-HTTP commands re-implement the Rust command's HTTP call in TS against the configured PDS; everything else falls through to the fake.

### Activation

A new `src/hooks.client.ts` in each app: if `import.meta.env.DEV && import.meta.env.VITE_HARNESS`, dynamically import the harness and install it before the app mounts. The double gate plus dynamic import means production builds tree-shake the entire harness (AC4.2), and a build-output grep enforces it (AC4.1). New package scripts: `dev:harness` (fake) and `dev:harness:proxy`. `vite.config.ts` already exposes `VITE_*` via `envPrefix`.

### Proxy-mode plumbing

- **Transport:** harness handlers fetch same-origin paths (e.g. `/__pds/*`) that the vite dev server proxies to the PDS base URL (`VITE_HARNESS_PDS_URL`), sidestepping CORS entirely (AC3.5).
- **PDS instance:** a `just` recipe spawns a hermetic local PDS following `tools/mcp/test/harness.ts` (binary from `target/{debug,release}`, mock plc.directory so no live-network traffic, throwaway admin token). Pointing `VITE_HARNESS_PDS_URL` at staging is possible but not the default.
- **Keys:** a real (extractable-false) WebCrypto P-256 keypair per browser session stands in for the Secure-Enclave/keychain key; signing is real, storage durability is not (that is a keychain concern the browser can't and shouldn't emulate).
- **Honest boundary:** commands whose Rust implementation is substantial local logic — the wallet's migration transfer legs (`transfer_repo`, `transfer_blobs`, …), DID ceremony internals, OAuth completion — stay faked in proxy mode v1 (AC3.6). Proxy mode's value is the account/claim/admin surfaces, which are thin HTTP.

### Event bridge

Fake mode maintains its own listener table; `window.__harness.emit('auth_ready')` simulates the OAuth deep-link return that iOS would deliver. This is the only event either app currently subscribes to, but the bridge is generic.

## Existing Patterns

- **Single IPC seam per app** — both `ipc.ts` files already funnel every `invoke`; the admin app documents this as a contract. The harness depends on and reinforces this pattern rather than introducing a new one.
- **Graceful plugin degradation** — `apps/admin-companion/src/lib/biometric.ts` and `share.ts` already dynamically import mobile-only plugins and resolve to `unavailable`/`false` off-device. The harness does not need to mock these plugins; scenarios that need a denied biometric drive it through the `biometric_enabled`/`set_biometric_enabled` commands instead.
- **Hermetic PDS spawning** — `tools/mcp/test/harness.ts` already solves local-PDS-with-mock-plc; the proxy-mode spawn recipe reuses that approach rather than inventing a second one.
- **Co-located vitest tests** — both apps test `src/lib/*.ts` modules with sibling `*.test.ts` files; `state.ts` and `registry.ts` coverage follows suit.
- **Divergence:** the harness duplicates its structure across the two apps instead of sharing a package. Justified: the apps share no frontend code today, introducing a workspace/shared package for this would be a bigger structural change than the feature warrants, and the two fakes model genuinely different domains.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Wallet harness core (fake mode)
**Goal:** The identity wallet boots and is fully navigable in a plain browser.

**Components:**
- `apps/identity-wallet/src/hooks.client.ts` — dev-gated activation seam
- `apps/identity-wallet/src/lib/harness/{install,registry,state}.ts` (+ `state.test.ts`, `registry.test.ts`) — mockIPC install, event bridge, full command registry, stateful fake
- `apps/identity-wallet/package.json` — `dev:harness` script
- Build-output harness-absence check wired into the app's check/test flow

**Dependencies:** None (first phase).

**Covers:** browser-harness.AC1.1, AC1.3 (wallet half), AC1.4, AC1.5, AC2.1 (wallet half), AC2.5 (wallet half), AC4.1, AC4.2.

**Done when:** `VITE_HARNESS=fake pnpm dev` serves a wallet where every screen is reachable without console errors; registry coverage is enforced; `pnpm check` + `pnpm test` pass; the build-output check proves harness absence.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Wallet scenarios + control API
**Goal:** Any wallet UI state — including rare error states — producible on demand from the browser console.

**Components:**
- `apps/identity-wallet/src/lib/harness/{scenarios,control}.ts` (+ tests) — presets (fresh-install, one-identity, migration-in-flight, agent-connected) and the `window.__harness` API (`scenario`, `failNext`, `emit`, `state`)

**Dependencies:** Phase 1.

**Covers:** browser-harness.AC2.2–AC2.4 (wallet half).

**Done when:** an agent can switch scenarios, inject typed command failures (e.g. `EXPIRED_CODE` on `create_account`), and deliver `auth_ready` from the console, and the UI visibly responds; tests pass.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Admin-companion harness (fake mode + scenarios)
**Goal:** The same capability for the Brass Console.

**Components:**
- `apps/admin-companion/src/hooks.client.ts`, `apps/admin-companion/src/lib/harness/{install,registry,state,scenarios,control}.ts` (+ tests) — mirrored structure; fake models pairings, admin devices, accounts, claim-code inventory, transfers, server health
- `apps/admin-companion/package.json` — `dev:harness` script; build-output check

**Dependencies:** Phase 1 (pattern established); independent of Phase 2.

**Covers:** browser-harness.AC1.2, AC1.3/AC2.1/AC2.2/AC2.3/AC2.5 (admin halves), AC4.1/AC4.2 (admin half).

**Done when:** same bar as Phases 1–2 but for admin-companion, including the unpaired / single-relay / multi-relay / degraded-health presets.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Hermetic PDS recipe + proxy transport
**Goal:** A one-command local PDS and the browser→PDS plumbing both apps' proxy modes share.

**Components:**
- `scripts/harness-pds.sh` + `just harness-pds` — spawn a local PDS with mock plc.directory and throwaway admin token (adapting `tools/mcp/test/harness.ts`), printing URL + token
- `vite.config.ts` in both apps — dev-server proxy route (`/__pds` → `VITE_HARNESS_PDS_URL`)

**Dependencies:** None on Phases 1–3 for the recipe; the vite wiring lands with it.

**Covers:** browser-harness.AC3.4, AC3.5.

**Done when:** `just harness-pds` yields a reachable PDS; a fetch to `/__pds/xrpc/…` from either dev server round-trips to it.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Wallet proxy mode
**Goal:** Real create-account/claim-surface flows in the browser against the local PDS.

**Components:**
- `apps/identity-wallet/src/lib/harness/proxy/` — WebCrypto P-256 device key; proxy handlers for the thin-HTTP command subset (account creation, handle/domain queries, identity resolution, agent list/revoke/audit); explicit fall-through-to-fake list for heavy commands
- `dev:harness:proxy` script

**Dependencies:** Phases 1, 4.

**Covers:** browser-harness.AC3.1, AC3.2, AC3.6 (wallet half).

**Done when:** the create-account flow completes in the browser against the hermetic PDS and the account is visible via the PDS admin API; fake-only commands are documented and behave as in fake mode.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Admin proxy mode
**Goal:** Real operator flows — pairing, claim codes, device management — against the local PDS.

**Components:**
- `apps/admin-companion/src/lib/harness/proxy/` — WebCrypto admin device key; real pairing bootstrap (claim code minted via the PDS admin API); signed-request proxy handlers for the operator command surface

**Dependencies:** Phases 3, 4.

**Covers:** browser-harness.AC3.3, AC3.6 (admin half).

**Done when:** a browser session pairs with the local PDS for real and `generate_claim_code`/`list_admin_devices` round-trip with accepted signatures.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Agent runbook + wiring
**Goal:** A fresh agent session can use all of this without spelunking.

**Components:**
- `.claude/launch.json` — named dev-server configurations for both apps' harness modes
- `apps/identity-wallet/AGENTS.md` + `apps/admin-companion/AGENTS.md` — harness sections (modes, `window.__harness` API, scenario list, proxy-mode fake-only list)
- `AGENTS.md` — one-paragraph pointer

**Dependencies:** Phases 1–6 (documents what shipped).

**Covers:** browser-harness.AC5.1, AC5.2.

**Done when:** the docs exist and a cold agent session can start either app's harness by name and drive a scenario end-to-end following only the runbook.
<!-- END_PHASE_7 -->

## Additional Considerations

**Fidelity boundary (what this harness cannot catch):** real keychain/Secure-Enclave behavior, the actual biometric prompt, ASWebAuthenticationSession, WKWebView-specific rendering, safe-area insets, camera/QR. Those remain simulator/device concerns; the runbook says so, so nobody mistakes a green harness run for device coverage.

**Error-shape drift:** fake handlers return the typed error shapes documented in each `ipc.ts`. If a Rust command's error serialization changes, the fake can silently drift. Mitigation is the existing discipline (error shapes are documented at the seam) plus proxy mode, which exercises the real thing for the HTTP-backed subset; full contract testing between fake and Rust is out of scope.

**Why mockIPC rather than aliasing `ipc.ts`:** intercepting `__TAURI_INTERNALS__` keeps the entire real frontend code path (including `ipc.ts` itself and its error-mapping logic) under test; a vite alias swap would exempt exactly the seam most worth exercising. It also transparently covers `listen()` and any plugin call that routes through `invoke`.

**Proxy-mode auth realism:** the wallet's OAuth completion and the migration legs are the two places proxy mode stays fake. If end-to-end OAuth-in-browser later becomes worth it, it is an additive follow-up (the PDS's OAuth surface is already exercised by `tools/interop` and `tools/mcp`), not a rework.
