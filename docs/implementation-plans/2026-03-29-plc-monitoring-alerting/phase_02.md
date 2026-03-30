# PLC Monitoring & Alerting Implementation Plan — Phase 2: Monitor Lifecycle

**Goal:** Wire the PlcMonitor into the app lifecycle: a 15-minute polling timer while the app is open, an immediate check when the app returns to foreground, and event emission so the frontend can react to alerts.

**Architecture:** A background `tokio::time::interval` spawned in the Tauri `.setup()` closure runs `PlcMonitor::check_all()` every 15 minutes. On each cycle, if unauthorized changes are detected, a `"plc_alert"` Tauri event is emitted to the frontend. App foreground detection uses the browser's `visibilitychange` event in the WKWebView (no native plugin needed) — the frontend calls `check_identity_status` IPC command when the app becomes visible. iOS background fetch (BGTaskScheduler) is deferred as best-effort future work.

**Tech Stack:** Rust (tokio::time, tauri::async_runtime), Svelte 5 (frontend visibility listener)

**Scope:** 3 phases from design Phase 6. This is phase 2 of 3.

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC6: PLC monitoring and alerting
- **plc-key-management.AC6.6 Success:** Monitor runs on app foreground and on a 15-minute timer while app is open

---

## Codebase Verification Findings

- ✓ `lib.rs:754-818` — `run()` function with `.setup()` closure; existing background task pattern at lines 787-790 (`tauri::async_runtime::spawn` with `app.handle().clone()`)
- ✓ `AppState::new()` at `oauth.rs` — manages `PdsClient` (eager), accessed via `state.pds_client()`
- ✓ `AppState` is registered via `.manage(oauth::AppState::new())` at line 757
- ✓ Existing `handle.emit()` pattern for Tauri events (e.g., `"auth_ready"`, `"pds_auth_ready"`)
- ✓ No existing lifecycle plugin — `tauri-plugin-deep-link` and `tauri-plugin-opener` only
- ✓ `tokio` available with `macros` and `rt` features in dev-dependencies; runtime features available via Tauri
- ✓ `visibilitychange` browser event fires reliably in WKWebView for iOS foreground/background transitions

## External Dependency Findings

- ✓ `tokio::time::interval` with `MissedTickBehavior::Delay` prevents burst of catch-up ticks after iOS app suspension — timer pauses while suspended, resumes normally
- ✓ No `tauri-plugin-app-events` needed — browser `visibilitychange` event handles foreground detection from the frontend side
- ✓ iOS `BGTaskScheduler` for background fetch requires custom Swift plugin — deferred to future work (design marks this as "best-effort, OS-throttled")

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Spawn 15-minute monitoring timer in Tauri setup

**Verifies:** plc-key-management.AC6.6

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (add `run_monitoring_loop` function)
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (spawn timer in `.setup()` closure)

**Implementation:**

Add a public function to `plc_monitor.rs` that runs the monitoring loop. This function is spawned once during app setup and runs for the lifetime of the app.

```rust
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

const MONITOR_INTERVAL_SECS: u64 = 15 * 60; // 15 minutes

/// Run a single monitoring cycle. Extracted from the loop for testability.
/// Returns the list of identity statuses with any alerts.
pub async fn run_monitoring_cycle(monitor: &PlcMonitor) -> Vec<IdentityStatus> {
    match monitor.check_all().await {
        Ok(statuses) => statuses,
        Err(e) => {
            tracing::warn!(error = %e, "Monitoring cycle check_all failed");
            vec![]
        }
    }
}

/// Run the PLC monitoring loop. Spawned once during app setup.
/// Checks all managed identities every 15 minutes and emits "plc_alert"
/// events to the frontend when unauthorized changes are detected.
pub async fn run_monitoring_loop(app_handle: tauri::AppHandle) {
    let mut interval = interval(Duration::from_secs(MONITOR_INTERVAL_SECS));
    // Don't burst-fire missed ticks after iOS suspension
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Skip the first immediate tick — let the app finish initializing
    interval.tick().await;

    loop {
        interval.tick().await;

        let state = app_handle.state::<crate::oauth::AppState>();
        let monitor = PlcMonitor::new(state.pds_client().clone());
        let statuses = run_monitoring_cycle(&monitor).await;

        let has_alerts = statuses.iter().any(|s| s.alert_count > 0);
        if has_alerts {
            if let Err(e) = app_handle.emit("plc_alert", &statuses) {
                tracing::warn!(error = %e, "Failed to emit plc_alert event");
            }
        }
    }
}
```

Note: `run_monitoring_cycle` is independently testable — it takes a `&PlcMonitor` (which can be constructed with `PdsClient::new_for_test()`) and returns `Vec<IdentityStatus>` without requiring a Tauri app handle. Tests for the cycle logic can use the same `httpmock` patterns as Phase 1.

In `lib.rs`, after the existing session restore spawn (around line 791), add:

```rust
// Start PLC monitoring timer (15-minute interval)
let monitor_handle = app.handle().clone();
tauri::async_runtime::spawn(plc_monitor::run_monitoring_loop(monitor_handle));
```

**Verification:**

Run: `cd apps/identity-wallet/src-tauri && cargo check`
Expected: Compiles without errors

Run: `cd apps/identity-wallet/src-tauri && cargo test plc_monitor`
Expected: Existing Phase 1 tests still pass

**Commit:** `feat(identity-wallet): spawn 15-minute PLC monitoring timer`

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Add frontend visibility-change handler for app foreground check

**Verifies:** plc-key-management.AC6.6

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte` (add visibility-change listener)
- Modify: `apps/identity-wallet/src/lib/ipc.ts` (add `checkIdentityStatus` IPC wrapper)

**Implementation:**

First, add the IPC wrapper to `ipc.ts`. Follow the existing pattern of typed wrappers (e.g., `listIdentities`, `getStoredDidDoc`):

```typescript
import { invoke } from '@tauri-apps/api/core';

// Add alongside existing type exports:
export interface UnauthorizedChange {
  cid: string;
  createdAt: string;
  signingKey: string | null;
  operation: unknown;
}

export interface IdentityStatus {
  did: string;
  alertCount: number;
  unauthorizedChanges: UnauthorizedChange[];
}

// Add alongside existing function exports:
export async function checkIdentityStatus(): Promise<IdentityStatus[]> {
  return invoke<IdentityStatus[]>('check_identity_status');
}
```

In `+page.svelte`, add a visibility-change listener. This should be added in the root page component since it needs to run regardless of which screen is active. Add it alongside the existing `onMount` logic:

```svelte
<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { checkIdentityStatus } from '$lib/ipc';

  // ... existing state and logic ...

  // PLC monitoring: check on app foreground
  function handleVisibilityChange() {
    if (document.visibilityState === 'visible' && step === 'home') {
      checkIdentityStatus().catch((e) => {
        console.warn('PLC status check failed:', e);
      });
    }
  }

  onMount(() => {
    document.addEventListener('visibilitychange', handleVisibilityChange);
    // ... existing onMount logic ...
  });

  onDestroy(() => {
    document.removeEventListener('visibilitychange', handleVisibilityChange);
  });
</script>
```

The `step === 'home'` guard ensures we only check when the user is on the home screen (not mid-onboarding or mid-import flow).

**Testing:**

This task tests the IPC type contract and visibility-change wiring. The behavior verification is:
- plc-key-management.AC6.6: Monitor runs on app foreground — `visibilitychange` triggers `checkIdentityStatus()` when app becomes visible and user is on home screen.

Testing approach: This is primarily infrastructure/wiring code. The IPC command was compile-time verified in Phase 1. The frontend listener is a thin wrapper over `visibilitychange` → `invoke()`. No dedicated unit test needed — verified by the Phase 3 frontend integration.

**Verification:**

Run: `cd apps/identity-wallet && pnpm check`
Expected: Svelte type checking passes (confirms IPC types match)

**Commit:** `feat(identity-wallet): add foreground PLC check via visibility-change`

<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->
