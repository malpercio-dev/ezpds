// pattern: Imperative Shell (reactive controller)
//
// The biometric-gated per-row relay action, shared by Devices (revoke a device),
// Codes (revoke a code), and Transfers (cancel a transfer). Every one of these is the
// same shape:
//
//   1. claim a per-id busy flag SYNCHRONOUSLY, before the biometric prompt's await, so
//      rapid taps can't open multiple gates and fire concurrent signed requests;
//   2. run the user-presence gate — a denial is a quiet hint, not an error;
//   3. run the signing action (the relay call, then a reload so the row reports the
//      relay's post-action truth rather than an optimistic local edit);
//   4. classify any failure into the per-id error slot.
//
// The controller owns the three reactive pieces every one of those screens declared by
// hand: the per-id busy map, the per-id error map, and the single gate-hint line.

import { SvelteMap } from 'svelte/reactivity';
import { classifyRelayError, type ErrorView } from './errors';
import { presenceAllows, requireUserPresence } from './biometric';

export interface GuardedActionOptions {
  /** The row key — the busy flag and any error are stored under it. */
  id: string;
  /** Shown in the system biometric prompt (e.g. "Revoke a device on this server"). */
  reason: string;
  /** The quiet hint shown when the operator cancels the gate. */
  deniedHint: string;
  /** The signing action itself: the relay call plus the reload-for-relay-truth. */
  action: () => Promise<void>;
}

export interface GuardedActions {
  /** The one gate-hint line for the screen (a cancelled prompt, not an alarm). */
  readonly gateHint: string | undefined;
  /** Whether the row keyed by `id` has an action in flight. */
  isBusy(id: string): boolean;
  /** The classified failure for the row keyed by `id`, if any. */
  errorFor(id: string): ErrorView | undefined;
  /** Run a biometric-gated signing action for one row. */
  run(options: GuardedActionOptions): Promise<void>;
}

export function createGuardedActions(): GuardedActions {
  // SvelteMap is reactive per-key, so a single map drives every row's spinner/error
  // without a re-render of the whole list.
  const busy = new SvelteMap<string, boolean>();
  const errors = new SvelteMap<string, ErrorView | undefined>();
  let gateHint = $state<string | undefined>(undefined);

  async function run({ id, reason, deniedHint, action }: GuardedActionOptions): Promise<void> {
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent signed requests.
    if (busy.get(id)) return;
    busy.set(id, true);
    gateHint = undefined;
    errors.set(id, undefined);

    try {
      const presence = await requireUserPresence(reason);
      if (!presenceAllows(presence)) {
        gateHint = deniedHint;
        return;
      }
      await action();
    } catch (e) {
      errors.set(id, classifyRelayError(e));
    } finally {
      busy.set(id, false);
    }
  }

  return {
    get gateHint() {
      return gateHint;
    },
    isBusy: (id) => busy.get(id) ?? false,
    errorFor: (id) => errors.get(id),
    run,
  };
}
