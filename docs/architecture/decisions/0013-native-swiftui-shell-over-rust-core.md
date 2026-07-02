# ADR-0013: Native SwiftUI shell over the Rust core (Deferred)

- **Status:** Deferred — not scheduled
- **Date:** 2026-06-20 (recorded); migrated into the ADR log 2026-07-02
- **Deciders:** ezpds maintainers
- **Related:** [`apps/identity-wallet/src-tauri/src/plc_monitor.rs`](../../../apps/identity-wallet/src-tauri/src/plc_monitor.rs) · [ADR-0010](0010-toolchains-managed-outside-nix.md) · [`docs/design-plans/2026-06-20-denix-ios-build.md`](../../design-plans/2026-06-20-denix-ios-build.md)

> Migrated verbatim from `docs/mobile-native-migration-decision.md`, which now
> redirects here. Preserved as a Deferred decision record.

## Context

The iOS app is a Tauri v2 shell (SvelteKit frontend + Rust backend). If/when we
outgrow Tauri, the question is *what we replace it with* — and the expensive
wrong answer (a full Swift rewrite that reimplements the crypto core) should be
ruled out in advance so the trigger, when it comes, doesn't invite it.

The concrete forcing function is **background execution**: today
`plc_monitor.rs` runs a foreground `tokio::time::interval` (`run_monitoring_loop`)
that iOS suspends when the app is backgrounded. True periodic checks against the
72-hour PLC recovery window need Apple's `BGTaskScheduler` / `BGAppRefreshTask`,
reachable only from native Swift.

## Decision

If/when we leave Tauri for the iOS app, migrate to a **native SwiftUI shell over
the existing Rust core** (Rust exposed to Swift via UniFFI) — **not** a full
Swift rewrite. Port the UI shell; **never reimplement the crypto core in Swift.**
Keep Secure Enclave / Keychain in Rust; use Swift only for LAContext/biometric UI.

**Trigger (the one signal that justifies starting):** background PLC monitoring
becomes a hard requirement. Secondary triggers: a Tauri iOS bug blocks *this app*
specifically (e.g. an unworkable WKWebView defect), or Android becomes a real
requirement (then reconsider Flutter/KMP vs SwiftUI).

## Consequences

- **The Rust core is the asset** (did:plc genesis/rotation/recovery, P-256 +
  Secure Enclave, DAG-CBOR, Shamir). Reimplementing it in Swift is the
  highest-risk, highest-cost option and is explicitly ruled out.
- **Low switching cost when the trigger fires:** the monitoring logic is already
  cleanly separated — only `run_monitoring_loop` and `emit_if_alerts` touch
  Tauri; `check_all` / `check_for_changes` are framework-agnostic and port as-is
  behind a `BGAppRefreshTask` handler. The rest of the Rust backend
  (`device_key`, `keychain`, `oauth_client`, `pds_client`, `claim`, `recovery`)
  has no Tauri coupling in its core logic.
- A SwiftUI shell also deletes the remaining Tauri-specific glue (the swift-rs
  patch, the Run Script patches) and unlocks `BGTaskScheduler`.
- **Out of scope now:** no SwiftUI project, no UniFFI bindings, no FFI layer, no
  removal of Tauri. This is a decision record only.

## Alternatives considered

- **Full Swift rewrite (reimplement crypto in Swift).** Rejected: highest risk
  and cost; duplicates the security-critical core.
- **Stay on Tauri and add a custom Swift background-task plugin.** Possible, but
  once you're writing a Swift plugin for `BGTaskScheduler` the shell migration is
  the cleaner endpoint; the real migration signal is "we need background
  execution," not build friction (which ADR-0010 / the de-Nix work addresses).
- **Flutter / Kotlin Multiplatform.** Reconsider only if Android becomes a real
  requirement.
