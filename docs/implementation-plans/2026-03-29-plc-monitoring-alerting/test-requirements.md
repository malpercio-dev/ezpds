# Test Requirements: PLC Monitoring & Alerting (AC6)

**Design plan:** `docs/design-plans/2026-03-28-plc-key-management.md` (AC6, lines 73-81)
**Implementation plans:** `docs/implementation-plans/2026-03-29-plc-monitoring-alerting/` (phases 1-3)
**Date:** 2026-03-29

---

## AC6.1: Authorized operation detection

**Criterion:** Monitor detects a new PLC operation signed by the device key and updates cached log without alerting.

| Field | Value |
|-------|-------|
| Verification | Automated test |
| Test type | Integration |
| Test file | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Implementation phase | Phase 1, Task 2 |

**Test approach:** Construct a valid PLC genesis operation signed by the device key using `crypto::build_did_plc_genesis_op`. Mock plc.directory via `httpmock::MockServer` to return an audit log containing this operation. Call `PlcMonitor::check_for_changes(did)`. Assert: (1) return value is `Ok(vec![])` (no unauthorized changes), (2) `IdentityStore::get_plc_log(did)` now contains the fetched log (cache updated).

**Additional coverage (multi-identity):** Phase 1, Task 3 tests `check_all` with two DIDs, both having only authorized operations. Asserts both `IdentityStatus` entries have `alert_count: 0`.

---

## AC6.2: Unauthorized operation detection

**Criterion:** Monitor detects a new PLC operation signed by a different key and creates an `UnauthorizedChange` alert.

| Field | Value |
|-------|-------|
| Verification | Automated test |
| Test type | Integration |
| Test file | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Implementation phase | Phase 1, Task 2 |

**Test approach:** Generate two PLC operations: a genesis operation signed by the device key (cached), and a subsequent rotation operation signed by a different P-256 key (returned by mock plc.directory). Call `PlcMonitor::check_for_changes(did)`. Assert: (1) return value contains exactly one `UnauthorizedChange`, (2) `signing_key` matches the `did:key` URI of the non-device key, (3) `cid` matches the unauthorized operation's CID, (4) `operation` field contains the raw operation JSON.

**Additional coverage (multi-identity):** Phase 1, Task 3 tests `check_all` with two DIDs, one with an unauthorized operation. Asserts the affected identity has `alert_count: 1` while the clean identity has `alert_count: 0`.

---

## AC6.3: Recovery deadline correctness

**Criterion:** Alert includes correct recovery deadline (operation timestamp + 72 hours).

| Field | Value |
|-------|-------|
| Verification | Automated test |
| Test type | Unit + Integration |
| Test file (backend) | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Test file (frontend) | `apps/identity-wallet/src/lib/utils/deadline.test.ts` |
| Implementation phase | Phase 1, Task 2 (backend); Phase 3, Task 4 (frontend) |

**Test approach (backend):** In the AC6.2 test above, additionally assert that `UnauthorizedChange.created_at` matches the `createdAt` value from the mock audit log entry. The `created_at` field is the raw ISO 8601 string from plc.directory; the 72-hour deadline is computed by the frontend from this value.

**Test approach (frontend):** Unit tests in `deadline.test.ts` for the extracted utility functions:
- `getDeadline('2026-03-29T12:00:00.000Z')` returns a `Date` exactly 72 hours later (`2026-04-01T12:00:00.000Z`).
- `getUrgency(deadline, now)` returns correct urgency levels at threshold boundaries: `'safe'` (>24h), `'warning'` (4-24h), `'critical'` (<4h), `'expired'` (<=0).
- `formatCountdown(deadline, now)` edge cases: exactly 72h remaining produces `'72h 0m remaining'`, 0 remaining produces `'Expired'`, 23h 59m remaining produces `'23h 59m remaining'`.

---

## AC6.4: Alert badge on home screen

**Criterion:** Home screen shows red alert badge on identity cards with `alertCount > 0`.

| Field | Value |
|-------|-------|
| Verification | **Human verification required** |
| Test type | Visual / manual |
| Test file | N/A (frontend UI rendering) |
| Implementation phase | Phase 3, Task 1 and Task 3 |

**Why automation is insufficient:** This criterion specifies visual rendering of a red alert badge on identity cards. The badge involves CSS styling (`.badge--alert` with `#fef2f2` background, `#ef4444` dot, `#991b1b` text), layout position relative to existing rotation key badges, and correct conditional rendering based on alert data. Svelte component rendering with scoped CSS and Tauri IPC data flow cannot be meaningfully verified by unit tests alone.

**Automated verification (partial):**
- `pnpm check` (Svelte type checking) verifies that `checkIdentityStatus` IPC types, `alertData` state, and `onalert` callback types are correct at compile time.
- The backend `check_all` integration tests (Phase 1, Task 3) verify that `IdentityStatus.alert_count` is computed correctly, so the data driving the badge is trustworthy.

**Human verification approach:**
1. Set up a test identity in the wallet with a known DID.
2. Use `httpmock` or a staging plc.directory to inject an unauthorized operation for that DID.
3. Open the app and navigate to the home screen.
4. Verify: (a) a red badge appears on the affected identity card showing the correct count, (b) identity cards with no alerts show no red badge, (c) tapping the alert badge navigates to the alert detail screen.

---

## AC6.5: Alert detail screen content

**Criterion:** Alert detail screen shows signing key, timestamp, and recovery deadline countdown.

| Field | Value |
|-------|-------|
| Verification | **Human verification required** (with automated support for deadline logic) |
| Test type | Visual / manual (UI); Unit (deadline computation) |
| Test file (partial) | `apps/identity-wallet/src/lib/utils/deadline.test.ts` |
| Implementation phase | Phase 3, Task 2 and Task 4 |

**Why full automation is insufficient:** The criterion requires verifying visual rendering of the `AlertDetailScreen` component: layout of signing key (truncated `did:key` URI or "Unknown key"), human-readable timestamp, a live countdown timer that updates every 60 seconds, and color-coded urgency indicators (green >24h, amber 4-24h, red <4h, red expired). These are visual and temporal behaviors that require a running app context.

**Automated verification (partial):**
- `deadline.test.ts` unit tests cover the pure computation: `getDeadline`, `getUrgency` thresholds, and `formatCountdown` formatting (see AC6.3 above).
- `pnpm check` verifies that the component's `$props` types (`did`, `changes`, `onback`) match the data passed from the page state machine.

**Human verification approach:**
1. Navigate to alert detail from an identity card with alerts (depends on AC6.4 verification).
2. Verify: (a) signing key displays as a `did:key:z...` URI (or "Unknown key" if null), (b) timestamp shows a human-readable date/time, (c) recovery deadline countdown is present and updates over time, (d) urgency color matches the remaining time (green/amber/red), (e) "Review & Override" button is visible but disabled, (f) back button returns to the home screen.

---

## AC6.6: Monitor lifecycle (foreground + timer)

**Criterion:** Monitor runs on app foreground and on a 15-minute timer while app is open.

| Field | Value |
|-------|-------|
| Verification | **Human verification required** (with automated support for cycle logic) |
| Test type | Integration (cycle logic); Manual (lifecycle wiring) |
| Test file (partial) | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Implementation phase | Phase 2, Task 1 (timer) and Task 2 (foreground) |

**Why full automation is insufficient:** This criterion has two parts:

1. **15-minute timer:** The `run_monitoring_loop` function spawns a `tokio::time::interval` in the Tauri `.setup()` closure. Testing the actual timer integration requires a running Tauri app runtime, which is not available in `cargo test`. The `run_monitoring_cycle` helper (extracted for testability) can be unit-tested with mocks.
2. **App foreground:** The `visibilitychange` event listener in `+page.svelte` calls `checkIdentityStatus()` when the document becomes visible and the user is on the home screen. This requires a WKWebView context on an iOS device or simulator.

**Automated verification (partial):**
- `run_monitoring_cycle(&monitor)` is tested via the same `httpmock` integration tests as Phase 1 (it delegates to `check_all`). Tests verify that a single cycle produces correct `Vec<IdentityStatus>` results.
- `cargo check` verifies that `run_monitoring_loop` compiles with correct Tauri types and the timer is wired into `.setup()`.
- `pnpm check` verifies that the `visibilitychange` listener and `checkIdentityStatus` IPC call type-check.

**Human verification approach:**
1. **Timer:** Launch the app and observe logs. After 15 minutes, verify that a monitoring cycle executes (look for `tracing` output from `run_monitoring_cycle` or `check_for_changes`). Inject a mock unauthorized operation between cycles and verify the `plc_alert` event fires on the next tick.
2. **Foreground:** Suspend the app (press Home), wait, then return to the app. Verify that `checkIdentityStatus` is called on resume (observable via network traffic to plc.directory or backend logs).

---

## AC6.7: Graceful handling of unreachable plc.directory

**Criterion:** Monitor handles plc.directory being unreachable gracefully (logs error, retries next cycle, does not alert).

| Field | Value |
|-------|-------|
| Verification | Automated test |
| Test type | Integration |
| Test file | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Implementation phase | Phase 1, Task 2 |

**Test approach:** Configure `httpmock::MockServer` to return a network error (connection refused or 500 status) for the audit log endpoint. Call `PlcMonitor::check_for_changes(did)`. Assert: (1) return value is `Ok(vec![])` (no error propagated, no unauthorized changes), (2) no `UnauthorizedChange` alerts are created, (3) cached log is NOT updated (failure should not overwrite good cached data).

---

## AC6.8: Empty audit log handling

**Criterion:** Monitor handles empty audit log (newly created identity, no operations yet).

| Field | Value |
|-------|-------|
| Verification | Automated test |
| Test type | Integration |
| Test file | `apps/identity-wallet/src-tauri/src/plc_monitor.rs` (`#[cfg(test)]` module) |
| Implementation phase | Phase 1, Task 2 |

**Test approach:** Configure mock plc.directory to return an empty JSON array (`[]`) for the audit log. Ensure no cached log exists in `IdentityStore` (first check scenario). Call `PlcMonitor::check_for_changes(did)`. Assert: (1) return value is `Ok(vec![])`, (2) no errors, no alerts. This covers both the "no cached log" and "empty remote log" paths.

---

## Coverage Matrix

| AC | Automated Test | Human Verification | Phase.Task |
|----|:-:|:-:|---|
| AC6.1 | Yes | -- | P1.T2, P1.T3 |
| AC6.2 | Yes | -- | P1.T2, P1.T3 |
| AC6.3 | Yes (backend + frontend unit) | -- | P1.T2, P3.T4 |
| AC6.4 | Partial (type check) | **Yes** | P3.T1, P3.T3 |
| AC6.5 | Partial (deadline unit) | **Yes** | P3.T2, P3.T4 |
| AC6.6 | Partial (cycle logic) | **Yes** | P2.T1, P2.T2 |
| AC6.7 | Yes | -- | P1.T2 |
| AC6.8 | Yes | -- | P1.T2 |

**Summary:** 5 of 8 acceptance criteria (AC6.1, AC6.2, AC6.3, AC6.7, AC6.8) are fully verifiable by automated tests. 3 criteria (AC6.4, AC6.5, AC6.6) require human verification due to visual rendering, real-time countdown behavior, or app lifecycle integration that cannot be exercised in headless test environments. All 3 have partial automated coverage (type checking, pure function unit tests, or backend integration tests) that reduces the surface area of manual verification.
