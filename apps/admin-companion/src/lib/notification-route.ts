// pattern: Functional Core
//
// Where a tapped operator alert lands. The iOS tap handler parks a route (extracted from
// the NSE's verified `ezpdsRoute` block) and the root layout drains it; this module turns
// that route into a pinned per-server href, or `null` when there is nowhere safe to go.
//
// The route is a pointer, never a claim. `server` names the sealing instance by public
// URL, and it only ever selects among the pairings this device already holds — an alert
// from a server the operator is not paired with routes nowhere, and the selected pairing
// is pinned into the href (`?server=<pairingId>`) exactly as a Home tap would pin it, so
// the destination screen signs against that relay and no other. `screen` is matched
// against the allowlist below rather than spliced into a path.

import type { Pairing, PendingNotificationRoute } from './ipc';
import { pinnedHref } from './pinned-pairing';

/** The screens an alert may point at, and the path each one lives at. */
const SCREENS: Record<string, string> = { accounts: '/accounts' };

/**
 * Normalize a relay URL for comparison — the same rule the Rust pin store applies
 * (`notifications.rs` `host_key`): trimmed, no trailing slash, lower-cased. A pairing
 * saved as `https://pds.example/` must match a server advertised as `https://pds.example`.
 */
export function serverKey(url: string): string {
  return url.trim().replace(/\/+$/, '').toLowerCase();
}

/**
 * The href a tapped alert should open, or `null` when it names a server this device is
 * not paired with or a screen this build does not route to. A route carrying a `did`
 * opens that account's detail; otherwise the screen itself.
 */
export function notificationHref(
  route: PendingNotificationRoute,
  pairings: readonly Pairing[],
): string | null {
  const wanted = serverKey(route.server);
  if (wanted === '') return null;
  const pairing = pairings.find((p) => serverKey(p.relayUrl) === wanted);
  if (!pairing) return null;
  const path = route.screen ? SCREENS[route.screen] : undefined;
  if (!path) return null;
  const did = route.did?.trim();
  return did ? pinnedHref('/account', pairing.id, { did }) : pinnedHref(path, pairing.id);
}
