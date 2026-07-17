<script lang="ts">
  import { onMount } from 'svelte';
  import {
    requestIdentityRemoval,
    confirmIdentityRemoval,
    tombstoneIdentity,
    listPendingRemovals,
    forgetIdentityLocally,
    sovereignLogin,
    isCodedError,
    type RemovalError,
    type RemovalOutcome,
  } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { truncateDid } from '$lib/did-doc-utils';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import { useHoldGesture } from '$lib/components/ui/use-hold-gesture.svelte';

  let {
    did,
    handle,
    onback,
    oncomplete,
  }: {
    did: string;
    /** The identity's handle (for context in the warning); may be empty. */
    handle?: string;
    onback: () => void;
    /** Called on success. `wasLast` routes back to onboarding vs. the identity list. */
    oncomplete: (wasLast: boolean) => void;
  } = $props();

  // warn → confirm (code + password) → (on partial failure) tombstone_retry.
  // forget_confirm is the local-only escape hatch, reachable whenever the server-side
  // deletion can't proceed (the account no longer exists on its PDS).
  type Phase =
    | 'warn'
    | 'requesting'
    | 'confirm'
    | 'working'
    | 'tombstone_retry'
    | 'forget_confirm';
  let phase = $state<Phase>('warn');
  let error = $state<string | null>(null);

  let code = $state('');
  let password = $state('');

  let canConfirm = $derived(code.trim().length > 0 && password.length > 0);

  // If a prior attempt already deleted the PDS account but was interrupted before the
  // tombstone + wipe finished (the app was killed mid-flow), the account is gone and the
  // single-use email code is spent — the request flow would fail. Resume straight to the
  // tombstone-only retry instead. Checked on every mount so this self-corrects no matter
  // how the screen was reached (launch reconciliation or manual navigation).
  onMount(async () => {
    try {
      const pending = await listPendingRemovals();
      if (pending.includes(did) && phase === 'warn') {
        phase = 'tombstone_retry';
      }
    } catch (e) {
      console.warn('listPendingRemovals failed:', e);
    }
  });

  // Hold-to-remove: a deliberate, irreversible confirmation gesture (matches the
  // recovery-override screen), gated by biometrics before anything is sent.
  const HOLD_MS = 1500;
  const hold = useHoldGesture({
    durationMs: HOLD_MS,
    oncomplete: () => {
      hold.state.progress = 1;
      confirm();
    },
    canStart: () => phase === 'confirm' && canConfirm,
  });
  let holdFill = $derived(hold.state.progress);

  // A separate hold gesture for the local-only "forget" confirmation, so its own progress
  // and canStart guard stay independent of the delete-and-tombstone hold above.
  const forgetHold = useHoldGesture({
    durationMs: HOLD_MS,
    oncomplete: () => {
      forgetHold.state.progress = 1;
      forgetLocally();
    },
    canStart: () => phase === 'forget_confirm',
  });
  let forgetHoldFill = $derived(forgetHold.state.progress);

  /** Enter the local-only escape hatch from any stuck state. */
  function startForget() {
    error = null;
    phase = 'forget_confirm';
  }

  /** Translate a typed RemovalError (or any throwable) into a display string. */
  function messageFor(raw: unknown): string {
    if (isCodedError(raw)) {
      const err = raw as RemovalError;
      switch (err.code) {
        case 'SESSION_REQUIRED':
          return 'This identity needs to be unlocked first.';
        case 'REQUEST_DELETE_FAILED':
          return `Could not start deletion: ${err.message || 'unknown error'}`;
        case 'INVALID_TOKEN':
          return 'That password or confirmation code was not accepted. Check your email and try again.';
        case 'ACCOUNT_DELETE_FAILED':
          return `Account deletion failed: ${err.message || 'unknown error'}`;
        case 'INVALID_AUDIT_LOG':
          return `Could not read the identity's PLC log: ${err.message || 'unknown error'}`;
        case 'TOMBSTONE_SIGNING_FAILED':
          return `Could not sign the tombstone: ${err.message || 'unknown error'}`;
        case 'PLC_DIRECTORY_ERROR':
          return `The PLC directory rejected the tombstone: ${err.message || 'unknown error'}`;
        case 'IDENTITY_NOT_FOUND':
          return `Identity not found: ${err.message || 'unknown error'}`;
        case 'LOCAL_WIPE_FAILED':
          return `The account was removed, but local cleanup failed: ${err.message || 'unknown error'}`;
        case 'RATE_LIMITED':
          return 'Rate limited by the server. Please wait a moment and try again.';
        case 'NETWORK_ERROR':
          return `Network error: ${err.message || 'unknown error'}`;
        default:
          return (err as { message?: string }).message || 'An unexpected error occurred.';
      }
    }
    return 'An unexpected error occurred. Please try again.';
  }

  /** Step 1: ask the PDS to email a confirmation code (unlocking the session if needed). */
  async function startRequest() {
    phase = 'requesting';
    error = null;
    try {
      await requestIdentityRemoval(did);
      phase = 'confirm';
    } catch (raw: unknown) {
      // A locked identity: run the passwordless unlock (biometric-gated) once, then retry.
      if (isCodedError(raw) && (raw as RemovalError).code === 'SESSION_REQUIRED') {
        try {
          await sovereignLogin(did);
          await requestIdentityRemoval(did);
          phase = 'confirm';
          return;
        } catch (retryRaw: unknown) {
          console.error('Unlock-then-request failed:', retryRaw);
          error = messageFor(retryRaw);
          phase = 'warn';
          return;
        }
      }
      console.error('requestIdentityRemoval failed:', raw);
      error = messageFor(raw);
      phase = 'warn';
    }
  }

  /** Step 2: delete on the PDS, tombstone the DID, wipe locally. Biometric-gated. */
  async function confirm() {
    error = null;
    try {
      await authenticateBiometric('Confirm permanent removal of this identity');
    } catch {
      hold.state.progress = 0;
      return; // gate declined — nothing sent.
    }

    phase = 'working';
    try {
      const outcome: RemovalOutcome = await confirmIdentityRemoval(did, password, code.trim());
      oncomplete(outcome.wasLastIdentity);
    } catch (raw: unknown) {
      console.error('confirmIdentityRemoval failed:', raw);
      hold.state.progress = 0;
      if (isPostDeleteFailure(raw)) {
        // The PDS account is already gone; only the tombstone + wipe remain. The
        // single-use code is spent, so resume via tombstoneIdentity (no re-delete).
        error = messageFor(raw);
        phase = 'tombstone_retry';
      } else {
        error = messageFor(raw);
        phase = 'confirm';
      }
    }
  }

  /** Resume path: retry only the tombstone + local wipe. Biometric-gated. */
  async function retryTombstone() {
    error = null;
    try {
      await authenticateBiometric('Finish removing this identity');
    } catch {
      return;
    }
    phase = 'working';
    try {
      const outcome: RemovalOutcome = await tombstoneIdentity(did);
      oncomplete(outcome.wasLastIdentity);
    } catch (raw: unknown) {
      console.error('tombstoneIdentity failed:', raw);
      error = messageFor(raw);
      phase = 'tombstone_retry';
    }
  }

  /**
   * Escape hatch: forget the identity from this device only, no network step. For an
   * account that no longer exists on its PDS (deleted elsewhere / migrated away), the
   * server-side delete can never succeed — the PDS answers an absent account with the same
   * opaque 401 as a wrong password, so it can't be auto-treated as done. This wipes local
   * material without deleting a server account or retiring the DID. Biometric-gated.
   */
  async function forgetLocally() {
    error = null;
    try {
      await authenticateBiometric('Remove this identity from this device');
    } catch {
      forgetHold.state.progress = 0;
      return; // gate declined — nothing wiped.
    }
    phase = 'working';
    try {
      const wasLast = await forgetIdentityLocally(did);
      oncomplete(wasLast);
    } catch (raw: unknown) {
      console.error('forgetIdentityLocally failed:', raw);
      forgetHold.state.progress = 0;
      error = messageFor(raw);
      phase = 'forget_confirm';
    }
  }

  /**
   * Errors that mean deleteAccount already succeeded — only the tombstone/wipe is left, so the
   * UI offers the tombstone-only retry. Deliberately excludes RATE_LIMITED and NETWORK_ERROR:
   * those are the *deletion* stage's codes (a transport failure there leaves the outcome
   * unknown, not confirmed-deleted), so they must re-prompt rather than enter the retry path.
   * The backend folds every post-delete PLC transport failure into PLC_DIRECTORY_ERROR, so the
   * two stages' codes are disjoint.
   */
  function isPostDeleteFailure(raw: unknown): boolean {
    if (!isCodedError(raw)) return false;
    const code = (raw as RemovalError).code;
    return (
      code === 'PLC_DIRECTORY_ERROR' ||
      code === 'TOMBSTONE_SIGNING_FAILED' ||
      code === 'INVALID_AUDIT_LOG' ||
      code === 'LOCAL_WIPE_FAILED' ||
      code === 'IDENTITY_NOT_FOUND'
    );
  }
</script>

<div class="screen">
  <div class="appbar">
    <button
      class="back"
      onclick={onback}
      disabled={phase === 'requesting' || phase === 'working'}
      aria-label="Back"
    >
      <ChevronLeftIcon />
      Back
    </button>
    <h2 class="appbar-title">Remove identity</h2>
    <span class="appbar-spacer" aria-hidden="true"></span>
  </div>

  <div class="content">
    <div class="identity">
      <span class="id-label">Identity</span>
      {#if handle}
        <span class="id-handle">{handle}</span>
      {/if}
      <span class="id-did">{truncateDid(did)}</span>
    </div>

    {#if phase === 'warn'}
      <div class="hero">
        <h1 class="hero-title">Permanently remove this identity</h1>
        <p class="hero-sub">This cannot be undone. Removing this identity will:</p>
      </div>
      <ul class="consequences">
        <li><strong>Delete your account</strong> and all its data on your PDS.</li>
        <li><strong>Retire the identity on the network</strong> by tombstoning its DID — it can never be reactivated or migrated.</li>
        <li><strong>Erase its keys</strong> from this device.</li>
      </ul>
      <p class="note">
        We'll email a confirmation code to the account address. You'll enter that code and your
        password to confirm.
      </p>
    {:else if phase === 'requesting'}
      <div class="loading">
        <Spinner size={32} label="Sending confirmation code" />
        <p class="loading-text">Sending a confirmation code to your email…</p>
      </div>
    {:else if phase === 'confirm'}
      <div class="hero">
        <h1 class="hero-title">Confirm removal</h1>
        <p class="hero-sub">
          Enter the code we emailed you and your account password, then hold to remove.
        </p>
      </div>
      <div class="form">
        <label class="field-label" for="removal-code">Confirmation code</label>
        <TextField
          id="removal-code"
          bind:value={code}
          mono
          autocapitalize="off"
          autocorrect="off"
          placeholder="Code from your email"
        />
        <label class="field-label" for="removal-password">Account password</label>
        <TextField
          id="removal-password"
          type="password"
          bind:value={password}
          placeholder="Your password"
        />
      </div>
    {:else if phase === 'working'}
      <div class="loading">
        <Spinner size={32} label="Removing identity" />
        <p class="loading-text">Deleting your account and retiring the identity…</p>
      </div>
    {:else if phase === 'tombstone_retry'}
      <div class="hero">
        <h1 class="hero-title">Almost done</h1>
        <p class="hero-sub">
          Your account was deleted, but retiring the identity on the network didn't finish. Your
          keys are still on this device — retry to complete removal.
        </p>
      </div>
    {:else if phase === 'forget_confirm'}
      <div class="hero">
        <h1 class="hero-title">Remove from this device only</h1>
        <p class="hero-sub">
          Use this if this identity's account no longer exists on its server — for example it was
          already deleted, or you migrated it elsewhere.
        </p>
      </div>
      <ul class="consequences">
        <li><strong>Erases this identity's keys</strong> from this device.</li>
        <li><strong>Does not delete a server account</strong> or retire the identity on the network.</li>
      </ul>
      <p class="note danger-note">
        If this identity is still active anywhere, removing its keys here may permanently end your
        ability to control it. This can't be undone.
      </p>
    {/if}

    {#if error}
      <div class="error-box" role="alert">
        <p class="error-text">{error}</p>
      </div>
    {/if}
  </div>

  <div class="actions">
    {#if phase === 'warn'}
      <Button variant="secondary" onclick={startRequest}>Continue</Button>
      <Button variant="secondary" onclick={onback}>Cancel</Button>
      <button class="link-action" onclick={startForget}>
        This account no longer exists on its server
      </button>
    {:else if phase === 'confirm'}
      <button
        class="hold"
        disabled={!canConfirm}
        onpointerdown={hold.start}
        onpointerup={hold.end}
        onpointerleave={hold.end}
        onpointercancel={hold.end}
        onkeydown={hold.keydown}
        onkeyup={hold.keyup}
        aria-label="Press and hold to permanently remove"
      >
        <span class="hold-fill" style="transform: scaleX({holdFill})"></span>
        <span class="hold-label">Hold to remove</span>
      </button>
      <p class="hint">Press and hold — this can't be undone</p>
      <Button variant="secondary" onclick={onback}>Cancel</Button>
      <button class="link-action" onclick={startForget}>
        This account no longer exists on its server
      </button>
    {:else if phase === 'tombstone_retry'}
      <Button onclick={retryTombstone}>Retry</Button>
      <button class="link-action" onclick={startForget}>Remove from this device instead</button>
      <Button variant="secondary" onclick={onback}>Close</Button>
    {:else if phase === 'forget_confirm'}
      <button
        class="hold"
        onpointerdown={forgetHold.start}
        onpointerup={forgetHold.end}
        onpointerleave={forgetHold.end}
        onpointercancel={forgetHold.end}
        onkeydown={forgetHold.keydown}
        onkeyup={forgetHold.keyup}
        aria-label="Press and hold to remove this identity from this device"
      >
        <span class="hold-fill" style="transform: scaleX({forgetHoldFill})"></span>
        <span class="hold-label">Hold to remove from device</span>
      </button>
      <p class="hint">Press and hold — this can't be undone</p>
      <Button variant="secondary" onclick={() => { error = null; phase = 'warn'; }}>Back</Button>
    {/if}
  </div>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .appbar {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-md) var(--space-md) var(--space-sm);
  }
  .back {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs);
    min-height: 44px;
  }
  .back:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .appbar-title {
    flex: 1;
    text-align: center;
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .appbar-spacer {
    width: 44px;
    flex-shrink: 0;
  }

  .content {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-sm) var(--space-md) var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .identity {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .id-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .id-handle {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    word-break: break-all;
  }
  .id-did {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    word-break: break-all;
  }

  .hero-title {
    font-family: var(--font-display);
    font-weight: var(--weight-regular);
    font-size: 1.75rem;
    line-height: 1.15;
    color: var(--color-ink);
    margin: 0 0 var(--space-sm);
  }
  .hero-sub {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
    margin: 0;
  }

  .consequences {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    margin: 0;
    padding-left: var(--space-lg);
  }
  .consequences li {
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }

  .note {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .field-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }

  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    padding: var(--space-xl) 0;
  }
  .loading-text {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: 12px var(--space-md);
  }
  .error-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }

  .actions {
    flex-shrink: 0;
    border-top: 1px solid var(--color-line);
    background: var(--color-surface);
    padding: var(--space-md) var(--space-md) var(--space-xl);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .hold {
    position: relative;
    width: 100%;
    height: 54px;
    border-radius: var(--radius-md);
    border: none;
    cursor: pointer;
    overflow: hidden;
    background: var(--color-critical-solid);
    touch-action: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .hold:disabled {
    background: var(--color-surface-sunk);
    cursor: not-allowed;
  }
  .hold-fill {
    position: absolute;
    inset: 0;
    background: var(--color-critical-solid-deep);
    transform: scaleX(0);
    transform-origin: left;
    transition: transform 0.1s linear;
  }
  .hold-label {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--color-on-color);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
  }
  .hold:disabled .hold-label {
    color: var(--color-muted);
  }
  .hint {
    text-align: center;
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }

  /* Low-emphasis escape hatch into the local-only "forget" flow. */
  .link-action {
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    text-align: center;
    cursor: pointer;
    padding: var(--space-xs);
    min-height: 44px;
  }

  .danger-note {
    color: var(--color-critical);
  }
</style>
