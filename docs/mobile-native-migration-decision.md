# Decision record: native SwiftUI shell over the Rust core (DEFERRED)

> **Moved.** The full record now lives in the ADR log as
> [ADR-0013: Native SwiftUI shell over the Rust core (Deferred)](architecture/decisions/0013-native-swiftui-shell-over-rust-core.md).
> This page keeps a short summary so existing links stay self-contained; see the
> ADR for the complete context, consequences, and alternatives.

## Summary

**Status:** Deferred — not scheduled.

**Decision:** If/when we leave Tauri for the iOS app, migrate to a **native
SwiftUI shell over the existing Rust core** (Rust exposed to Swift via UniFFI) —
**never reimplement the crypto core in Swift**. Port the UI shell only.

**Trigger:** background PLC monitoring becomes a hard requirement. iOS suspends
the current foreground `tokio::time::interval`; true periodic checks against the
72h recovery window need Apple's `BGTaskScheduler` / `BGAppRefreshTask`,
reachable only from native Swift. (Secondary: a Tauri iOS bug that blocks this
app specifically, or Android becoming a real requirement.)

**Why this shape:** the Rust core (did:plc genesis/rotation/recovery, P-256 +
Secure Enclave, DAG-CBOR, Shamir) is the asset; reimplementing it in Swift is the
highest-risk option and is ruled out. The monitoring logic is already cleanly
separated, so switching cost is low when the trigger fires.
