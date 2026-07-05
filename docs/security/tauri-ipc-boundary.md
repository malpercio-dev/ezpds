# Tauri IPC boundary (least-privilege capability allowlist)

Last verified: 2026-07-05

Both iOS apps — **identity-wallet** (Obsign) and **admin-companion** — run a SvelteKit
frontend in a WKWebView over a Rust backend, talking through Tauri v2's IPC bridge. This
document is the security spec for that bridge: what the webview is allowed to call, why
each grant exists, and how the boundary is enforced.

The guard `scripts/capability-check.sh` (`just cap-check`, in `just ci` / `just ci-pds`)
is the automated half of this spec. If you widen an allowlist, update this doc **and** the
expected sets in that script together — the guard fails otherwise.

## Threat model in one paragraph

Tauri v2 gates every webview→Rust IPC call through **capability** files in each app's
`src-tauri/capabilities/`. A capability binds a set of **permissions** to one or more
windows (and, optionally, platforms). A window must be bound to a capability to reach the
IPC layer at all; once it is, the app's own `#[tauri::command]`s (registered via
`tauri::generate_handler!`) are callable **without a per-command permission entry** — that
is the intended surface. Everything else — Tauri **core** APIs (window, path, event, …) and
**plugin** commands — is denied unless a matching capability *permission* grants it. So the
only things worth listing (and minimizing) in a capability are the core and plugin
permissions; the app's commands are covered implicitly by the window binding. The attack we are minimizing: a compromised or malicious script running in the
webview (e.g. via a supply-chain'd frontend dep or an XSS-style injection) reaching for
`core:window`, `core:path`, or a plugin command to do more than the app's own commands
allow. Least privilege shrinks that reachable surface to the few grants each frontend
actually uses.

## The allowlists

Each permission below traces to a real frontend code path. App-defined commands
(`invoke('create_account', …)`, `invoke('generate_claim_code', …)`, etc.) are intentionally
absent — the window binding already covers them, so they need no per-command entry.

### identity-wallet — `capabilities/default.json`

| Permission | Why it's present |
| --- | --- |
| `core:event:default` | The frontend calls `listen()` for the `auth_ready` event (session restored on launch) and `plc_alert` event (`IdentityListHome` updates alert badges). The backend *emits* these from Rust, which is not ACL-gated; the webview *listening* is. |
| `auth-session:default` | The in-app OAuth flow calls `plugin:auth-session\|start` (the vendored `tauri-plugin-auth-session` / `ASWebAuthenticationSession`) for both the create and claim login flows. |

### admin-companion — `capabilities/default.json`

| Permission | Why it's present |
| --- | --- |
| `log:default` | The `tauri_plugin_log` plugin is registered on all platforms. The frontend does not currently call the log plugin, but the grant is a single low-risk plugin permission and keeps webview logging available; it is retained rather than chased to an empty allowlist. |

The admin frontend uses **no** core API — no events, no window control — so `core:*` is
absent entirely.

### admin-companion — `capabilities/mobile.json`

Platform-gated (`"platforms": ["iOS", "android"]`), so it is skipped on the macOS host
build. Unchanged by the lockdown — already minimal.

| Permission | Why it's present |
| --- | --- |
| `barcode-scanner:default` | Camera QR scan on the Pair screen (`scanQrCode()` dynamic import). |
| `biometric:default` | Face ID / Touch ID user-presence gate before every signing action (`requireUserPresence()`). |
| `sharesheet:default` | iOS Share Pane for a claim code (`shareText()`). |

## What we deliberately dropped, and why

- **`core:default`** — removed from both apps. It bundles nine core permission sets (app,
  event, image, menu, path, resources, tray, webview, and `window`'s 40+ commands). Only
  `core:event` is used (by the wallet); the rest was dead surface. Most importantly this
  removes all `core:window` control (position, sizing, decoration, dragging, close) from
  the reachable set.
- **`withGlobalTauri`** — kept **off** (the v2 default) in both `tauri.conf.json`s, so the
  global `window.__TAURI__` object is never injected. The frontends call commands via
  `@tauri-apps/api` imports, so they don't need it, and leaving it off keeps the IPC
  surface out of arbitrary in-page script.
- **A `"platforms"` gate on the base `default.json`** — intentionally *not* added. The base
  capability stays cross-platform (the repo pattern is `default.json` = base, `mobile.json`
  = the iOS/android plugin layer); gating the base to iOS would strip all IPC on any macOS
  host build.

## Schema note

Both apps are iOS-only, so their capability files reference `../gen/schemas/mobile-schema.json`
(the wallet previously referenced the desktop schema — corrected). The `$schema` is
editor-validation metadata only; the `gen/` schemas are build-generated and gitignored, so
it never affects the build or runtime. The guard fails on a `desktop-schema.json` reference
to prevent regression.

## Enforcement

Tauri v2 has **no runtime ACL-denial test harness** — a denied call surfaces only as a
console string (`"<command> not allowed"`) with no catchable exception type, and build-time
schema validation checks JSON *syntax*, not capability membership. So enforcement is two
halves:

1. **Static minimality lock (automated, CI).** `scripts/capability-check.sh` (`just
   cap-check`) asserts: no `core:default` in any capability; each file's permission set
   equals the audited-minimal set above (fails on any addition *or* removal); the mobile
   schema is referenced; `withGlobalTauri` is off. This runs on Linux in `just ci-pds`
   (pure JSON parsing, no Apple toolchain), so a re-widening can't merge silently.

2. **Manual denial check (on-device, when a simulator is available).** In a dev build, from
   the WKWebView dev tools, call a core command outside the allowlist through the
   `@tauri-apps/api` and confirm it is denied. For example, importing `getCurrentWindow`
   from `@tauri-apps/api/window` and calling `.setTitle('x')` (which needs
   `core:window:allow-set-title`, no longer granted) should reject with a
   `"…not allowed"` console error, while the app's own commands (e.g. `list_identities`,
   `pairing_state`) still resolve. This is the half the static guard cannot prove; run it
   after any capability change once Xcode/Simulator is at hand. (The exact denial-error
   string and internal invoke path vary by Tauri version — the signal is a *rejected*
   call, versus a resolving app command.)

## Changing an allowlist

1. Add the permission to the app's capability JSON, with a one-line rationale tracing it to
   the frontend code path.
2. Update the expected set in `scripts/capability-check.sh` and the table above.
3. Run `just cap-check` (must pass) and, when a simulator is available, the manual denial
   check.
