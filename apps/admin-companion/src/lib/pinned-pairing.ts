// pattern: Functional Core (+ one IPC loader)
//
// Pinned-pairing resolution — the shared entry ritual for every per-server operator
// screen (Devices, Codes, Accounts, Account detail, Moderation, Status, Transfers).
//
// Each of those screens acts on ONE relay, resolved ONCE when the screen mounts:
// `?server=<pairingId>` if the caller pinned one (Home/Settings pass it explicitly),
// else the active pairing. The resolved id is address-stable for the life of the
// screen — so a concurrent active-pointer switch on Home can never redirect what a
// pinned screen reads or signs. This is the security property; it lives here, once,
// instead of being re-derived in seven onMount blocks.
//
// The gate that renders the three pre-flight states (checking / check-failed /
// no-server) is `components/ui/PinnedPairingGate.svelte`, which hands the resolved,
// non-null pairing to its children.

import { listPairings, type Pairing, type PairingsState } from './ipc';

/**
 * The pairing a per-server screen is pinned to: the `?server=` pin when present, else
 * the active pairing. `null` when nothing matches (unpaired, no active pick and no pin,
 * or a stale id that no longer exists) — the caller renders the "no server" gate.
 */
export function resolvePinnedPairing(
  state: PairingsState,
  searchParams: URLSearchParams,
): Pairing | null {
  const requested = searchParams.get('server');
  const targetId = requested ?? state.active;
  return state.pairings.find((p) => p.id === targetId) ?? null;
}

/**
 * Load the pairing document and resolve the pinned pairing in one step — the async
 * half of the entry ritual, shared by every pinned screen's `onMount`. A failed read
 * surfaces as `view: 'error'` (the gate's check-failed state) rather than throwing.
 */
export async function loadPinnedPairing(
  searchParams: URLSearchParams,
): Promise<{ view: PairingsState | 'error'; pairing: Pairing | null }> {
  let state: PairingsState;
  try {
    state = await listPairings();
  } catch {
    return { view: 'error', pairing: null };
  }
  return { view: state, pairing: resolvePinnedPairing(state, searchParams) };
}

/**
 * Build a pinned per-server link: `<path>?server=<pairingId>` plus any extra query
 * params (e.g. `did`). One place for the `?server=` construction so encoding is
 * consistent everywhere a screen hands a pin to the next (Home, Accounts, Account
 * detail, Settings) — `URLSearchParams` percent-encodes every value uniformly.
 */
export function pinnedHref(
  path: string,
  pairingId: string,
  extra?: Record<string, string>,
): string {
  const params = new URLSearchParams({ server: pairingId, ...extra });
  return `${path}?${params.toString()}`;
}
