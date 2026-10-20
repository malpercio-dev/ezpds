# ADR-0013: A native shell over the bound Rust core (Deferred)

- **Status:** Deferred — not scheduled; waits on a trigger below
- **Date:** 2026-06-20 (recorded); migrated into the ADR log 2026-07-02; revised 2026-10-20
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0039](0039-obsign-core-bound-rust-core.md) (the bound core, split out of this record and Accepted) · [`apps/identity-wallet/src-tauri/src/bg_backup.rs`](../../../apps/identity-wallet/src-tauri/src/bg_backup.rs) · [`apps/identity-wallet/src-tauri/src/plc_monitor.rs`](../../../apps/identity-wallet/src-tauri/src/plc_monitor.rs) · [ADR-0010](0010-toolchains-managed-outside-nix.md) · [`docs/design-plans/2026-09-06-v2-in-place.md`](../../design-plans/2026-09-06-v2-in-place.md) §4

> **Revised 2026-10-20.** This record used to hold two decisions. "The Rust core
> is the asset; never reimplement it in Swift" now lives in
> [ADR-0039](0039-obsign-core-bound-rust-core.md), Accepted. This record keeps
> only the shell question, with its trigger rewritten. The original trigger is
> recorded under "Why background execution is not a trigger".

## Context

The wallet is a Tauri v2 shell (SvelteKit frontend) over Rust that ADR-0039
makes a platform-free core. A native shell (SwiftUI on iOS, Kotlin/Compose on
Android) is a UI port over that same core, bound through UniFFI. It is never a
rewrite. The open question is when a port is worth its cost: two UI codebases
for the wallet, and the browser harness and docs screenshots re-proved against
each.

## Decision

Stay on Tauri. Start a native shell only when one of these fires:

1. **Android demand.** Android becomes a real requirement. The shell is
   Kotlin/Compose over the core's UniFFI AAR. The iOS app may stay on Tauri;
   each platform's shell is its own decision.
2. **A WKWebView defect blocks this app.** Not general friction, but a defect
   with no workaround that stops a wallet flow from shipping.
3. **Assurance needs native fidelity.** A product decision that the wallet's
   assurance story (biometric prompts, secure-entry fields, system-integrated
   identity surfaces) can't be told credibly from a web view.

Whichever trigger fires, the port covers the shell only. ADR-0039 rules out
reimplementing the core or `crypto` in Swift or Kotlin.

### Why background execution is not a trigger

The original trigger was "background PLC monitoring becomes a hard
requirement", because `BGTaskScheduler` was taken to be "reachable only from
native Swift". That premise is false. `bg_backup.rs` schedules a
`BGProcessingTask` from Rust through `objc2-background-tasks` today, inside the
Tauri app. `plc_monitor`'s foreground `run_monitoring_loop` can move onto that
bridge, behind ADR-0039's `Scheduler` trait, without changing shells. A trigger
that can never fire leaves the decision with no way to start, so it is replaced
rather than kept as a secondary signal.

## Consequences

- No native shell, no Swift package, and no UniFFI bindings get built until a
  trigger fires. ADR-0039's extraction proceeds anyway, so a port, when it
  comes, is UI work only.
- A native iOS shell would also delete the remaining Tauri-specific glue (the
  swift-rs patch, the XcodeGen template workarounds).
- The Brass Console stays on Tauri as long as the wallet does.

## Alternatives considered

- **Full Swift rewrite, crypto included.** Rejected: highest risk and cost, and
  it duplicates the security-critical core. ADR-0039 makes this permanent.
- **Keep background monitoring as the trigger.** Rejected: already satisfiable
  from Rust under Tauri, so it can never fire.
- **Flutter for Android.** Not recommended: Flutter's UI fidelity is the wrong
  fit for the wallet's brief, and Kotlin/Compose binds the same core with no
  extra runtime.
- **Kotlin Multiplatform for shared UI.** Would share UI code, but the shared
  layer that matters (the core) is already Rust. Two thin native shells cost
  less than a third language.
