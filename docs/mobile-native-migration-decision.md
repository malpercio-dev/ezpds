# Decision record: native SwiftUI shell over the Rust core (DEFERRED)

Status: **Deferred — not scheduled.** Recorded 2026-06-20.

## Decision

If/when we leave Tauri for the iOS app, migrate to a **native SwiftUI shell over
the existing Rust core** (Rust exposed to Swift via UniFFI), NOT a full Swift
rewrite. Port the UI shell; never reimplement the crypto core in Swift.

## Trigger (the one signal that justifies starting)

**Background PLC monitoring becomes a hard requirement.** Today
`apps/identity-wallet/src-tauri/src/plc_monitor.rs` runs a foreground
`tokio::time::interval` (`run_monitoring_loop`, L225) that iOS suspends when the
app is backgrounded. True periodic checks against the 72h recovery window need
Apple's `BGTaskScheduler` / `BGAppRefreshTask`, reachable only from native Swift.
Note: even staying on Tauri, background tasks require a custom Swift plugin — so
the real migration signal is "we need background execution," not "the build annoys
me." (The build friction is addressed by the de-Nix work; see
docs/design-plans/2026-06-20-denix-ios-build.md.)

Secondary triggers: a Tauri iOS bug blocks *this app* specifically (e.g. a
WKWebView rendering defect we can't work around), or Android becomes a real
requirement (then reconsider Flutter/KMP vs SwiftUI).

## Why this shape (from the 2026 re-evaluation)

- The Rust core is the asset (did:plc genesis/rotation/recovery, P-256 + Secure
  Enclave, DAG-CBOR, Shamir). Reimplementing it in Swift is the highest-risk,
  highest-cost option and is explicitly ruled out.
- A SwiftUI shell deletes the remaining Tauri-specific glue (swift-rs patch, Run
  Script patches) and unlocks `BGTaskScheduler`, while the Rust core ports
  unchanged via UniFFI.
- Keep Secure Enclave/Keychain in Rust; use Swift only for LAContext/biometric UI.

## Why it's pre-de-risked (low switching cost when the trigger fires)

The monitoring logic is already cleanly separated: only `run_monitoring_loop`
(L225) and `emit_if_alerts` (L249) in `plc_monitor.rs` touch Tauri; `check_all`
(L58) and `check_for_changes` (L89) are framework-agnostic and port as-is behind a
`BGAppRefreshTask` handler. The rest of the Rust backend (device_key, keychain,
oauth_client, pds_client, claim, recovery) has no Tauri coupling in its core logic.

## Explicitly out of scope now

No SwiftUI project, no UniFFI bindings, no FFI layer, no removal of Tauri. This is
a decision record only. Revisit when the trigger above is met.
