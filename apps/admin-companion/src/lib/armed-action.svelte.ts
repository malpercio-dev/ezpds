// pattern: Imperative Shell (reactive controller)
//
// An armed two-tap + biometric-gated destructive action. The Moderation screen carries
// two of these — account takedown/restore and the credential sweep — as independent
// state machines that must never leave the other half-armed. Each is:
//
//   • arm()  — tap 1 swaps the destructive button for an explicit Confirm/Cancel pair;
//   • confirm() — tap 2 claims a busy flag before the biometric await (so rapid taps
//     can't stack prompts), gates on user presence (a denial is a quiet hint), then
//     runs the signed write; on success it disarms, on failure it classifies the error;
//   • disarm() — clears the armed state, the gate hint, and any error.
//
// The controller owns armed / writing / error / gateHint; the caller supplies the
// per-confirm reason, denial hint, a `precondition` (pairing present, lookup fresh, the
// sibling action idle), the `run` closure, and an optional `commit` guard for the case
// where a slower write must not land its result under a newer lookup.

import { classifyRelayError, type ErrorView } from './errors';
import { presenceAllows, requireUserPresence } from './biometric';

export interface ArmedConfirmOptions {
  /** Shown in the system biometric prompt. */
  reason: string;
  /** The quiet hint shown when the operator cancels the gate. */
  deniedHint: string;
  /** Guard checked before anything runs: pairing present, lookup fresh, sibling idle. */
  precondition: () => boolean;
  /** The signed write itself. */
  run: () => Promise<void>;
  /**
   * Whether to land the outcome (disarm on success / show the error on failure).
   * Defaults to always. A screen returns `false` here when the lookup has drifted since
   * the write started, so a stale result never lands under a newer lookup.
   */
  commit?: () => boolean;
}

export interface ArmedAction {
  /** Tap 1 happened — the Confirm/Cancel pair is showing. */
  readonly armed: boolean;
  /** The signed write is in flight. */
  readonly writing: boolean;
  /** The classified failure of the last write, if any. */
  readonly error: ErrorView | undefined;
  /** The quiet hint shown when the operator cancels the gate. */
  readonly gateHint: string | undefined;
  /** Tap 1: show the Confirm/Cancel pair. */
  arm(): void;
  /** Cancel: clear the armed state, gate hint, and error. */
  disarm(): void;
  /** Tap 2: gate on user presence, then run the signed write. */
  confirm(options: ArmedConfirmOptions): Promise<void>;
}

export function createArmedAction(): ArmedAction {
  let armed = $state(false);
  let writing = $state(false);
  let error = $state<ErrorView | undefined>(undefined);
  let gateHint = $state<string | undefined>(undefined);

  function arm(): void {
    error = undefined;
    gateHint = undefined;
    armed = true;
  }

  function disarm(): void {
    armed = false;
    error = undefined;
    gateHint = undefined;
  }

  async function confirm({
    reason,
    deniedHint,
    precondition,
    run,
    commit,
  }: ArmedConfirmOptions): Promise<void> {
    if (!precondition()) return;
    // Claim the busy flag synchronously, before the biometric prompt's await, so rapid
    // taps can't open multiple gates and fire concurrent writes.
    if (writing) return;
    writing = true;
    gateHint = undefined;
    error = undefined;
    try {
      const presence = await requireUserPresence(reason);
      if (!presenceAllows(presence)) {
        gateHint = deniedHint;
        return;
      }
      await run();
      if (commit === undefined || commit()) armed = false;
    } catch (e) {
      if (commit === undefined || commit()) error = classifyRelayError(e);
    } finally {
      writing = false;
    }
  }

  return {
    get armed() {
      return armed;
    },
    get writing() {
      return writing;
    },
    get error() {
      return error;
    },
    get gateHint() {
      return gateHint;
    },
    arm,
    disarm,
    confirm,
  };
}
