import { invoke } from '@tauri-apps/api/core';

// ── Notification tap routing (Phase C: push-to-approve) ─────────────────────
//
// A tapped push can launch the app cold or foreground it warm. The iOS tap handler parks the
// route (extracted from the NSE's verified `ezpdsRoute` block) in a single Rust-side slot and
// emits a `notification_route` Tauri event; the frontend drains the slot on mount and on the
// event. `takePendingNotificationRoute` clears the slot, so the two paths never double-navigate.

/** Where a tapped, NSE-verified notification wants the app to go. */
export type PendingNotificationRoute = {
  /** The payload type, e.g. `login-approval`. Unknown kinds are ignored by the router. */
  kind: string;
  /** A pending OAuth consent request id (`login-approval`). */
  requestId: string | null;
  /** The account DID the notification concerns; must match a managed identity to navigate. */
  did: string | null;
};

/** The Tauri event the warm-foreground tap emits; payload is the same route shape. */
export const NOTIFICATION_ROUTE_EVENT = 'notification_route';

/** Take (and clear) the pending notification route, if a tap parked one. */
export const takePendingNotificationRoute = (): Promise<PendingNotificationRoute | null> =>
  invoke('take_pending_notification_route');
