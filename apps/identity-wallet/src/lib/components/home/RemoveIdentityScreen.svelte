<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getIdentityRemovalRoute,
    requestIdentityRemoval,
    confirmIdentityRemoval,
    tombstoneIdentity,
    listPendingRemovals,
    forgetIdentityLocally,
    isCodedError,
    type RemovalError,
    type RemovalOutcome,
  } from '$lib/ipc';
  import { unlockIdentity, isUnlockCancelled } from '$lib/unlock';
  import { authenticateBiometric } from '$lib/biometric';
  import { truncateDid } from '$lib/did-doc-utils';
  import { didWebDocumentUrl } from '$lib/did-web';
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
  // web_epilogue is the did:web terminal state: the removal succeeded, but the last step
  // — taking the DID's document off the domain — belongs to the user, not the wallet.
  type Phase =
    | 'warn'
    | 'requesting'
    | 'confirm'
    | 'working'
    | 'tombstone_retry'
    | 'forget_confirm'
    | 'web_epilogue';
  let phase = $state<Phase>('warn');
  let error = $state<string | null>(null);

  // A did:web has no PLC tombstone: it is retired by removing its document from the
  // domain, which the wallet has no control over. That single fact drives every copy
  // branch on this screen — what the warning promises, whether the "also retire on the
  // network" advanced option exists at all, and how a removal ends.
  let isDidWeb = $derived(did.startsWith('did:web:'));
  // The document's authoritative URL, for a concrete instruction rather than a vague one.
  // `didWebDocumentUrl` throws on a malformed identifier — fall back to naming no URL
  // rather than blocking the epilogue over cosmetics.
  let didWebDocUrl = $derived.by(() => {
    if (!isDidWeb) return null;
    try {
      return didWebDocumentUrl(did);
    } catch {
      return null;
    }
  });

  // Carried from the successful removal into `web_epilogue`, so the Done button routes
  // exactly where an immediate `oncomplete` would have.
  let epilogueWasLast = $state(false);

  let code = $state('');
  let password = $state('');

  // Whether this identity's host wants the account password at all. An identity created
  // without one has nothing to type here — the wallet signs a device-key removal proof
  // instead — so asking would be asking for something that does not exist.
  //
  // `routeLoaded` distinguishes "we know a password is needed" from "we have not asked
  // yet", so the warning copy never promises a password step it may be about to drop.
  // A failed lookup leaves `requiresPassword` true, matching the backend's own fallback.
  let requiresPassword = $state(true);
  let routeLoaded = $state(false);

  let canConfirm = $derived(
    code.trim().length > 0 && (!requiresPassword || password.length > 0),
  );

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
    try {
      requiresPassword = (await getIdentityRemovalRoute(did)).requiresPassword;
      routeLoaded = true;
    } catch (e) {
      // Leave `requiresPassword` true and `routeLoaded` false: the warning stays silent
      // about the credential rather than promising the wrong one, and the confirm step
      // offers the field. The confirm call re-resolves this and reports the real failure.
      console.warn('getIdentityRemovalRoute failed:', e);
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

  // A separate hold gesture for the "forget" confirmation, so its own progress and canStart
  // guard stay independent of the delete-and-tombstone hold above.
  const forgetHold = useHoldGesture({
    durationMs: HOLD_MS,
    oncomplete: () => {
      forgetHold.state.progress = 1;
      confirmForget();
    },
    canStart: () => phase === 'forget_confirm',
  });
  let forgetHoldFill = $derived(forgetHold.state.progress);

  // Advanced escape-hatch options, revealed behind a disclosure. `alsoTombstone` upgrades the
  // local-only wipe into a full network retirement (sign + publish a did:plc tombstone) for an
  // advanced user who is certain they want to torch the identity everywhere, not just here.
  // Offered for a did:plc only: there is no did:web tombstone to publish, so the option would
  // promise a network-wide retirement the wallet cannot perform.
  let showAdvanced = $state(false);
  let alsoTombstone = $state(false);

  // The message shown during the `working` step — set by each path so it tells the literal truth
  // (a local-only forget must not claim it is "deleting your account").
  let workingMessage = $state('Removing identity…');

  /** Enter the escape hatch from any stuck state, resetting its advanced options. */
  function startForget() {
    error = null;
    showAdvanced = false;
    alsoTombstone = false;
    phase = 'forget_confirm';
  }

  /**
   * The screen-owned sentence for a typed RemovalError (or any throwable), keyed on `code` —
   * the diagnostic `message` stays in the console log, never in the sentence. The tombstone-leg
   * sentences don't claim the account was deleted: the same codes surface from the
   * forget-with-retirement path, where no `deleteAccount` ran.
   */
  function messageFor(raw: unknown): string | null {
    // A dismissed unlock prompt is the user's decision, not a failure: say nothing.
    if (isUnlockCancelled(raw)) return null;
    if (isCodedError(raw)) {
      const err = raw as RemovalError;
      switch (err.code) {
        case 'SESSION_REQUIRED':
          return 'This identity needs to be unlocked first.';
        case 'REQUEST_DELETE_FAILED':
          return 'Your server couldn’t start the deletion. Nothing was removed — try again in a moment.';
        case 'INVALID_TOKEN':
          return 'That password or confirmation code was not accepted. Check your email and try again.';
        case 'INVALID_CONFIRMATION_CODE':
          return 'That confirmation code was not accepted. Check your email and try again.';
        case 'PASSWORD_REQUIRED':
          return 'This server needs your account password to remove an identity.';
        case 'PROOF_SIGNING_FAILED':
          return 'This device couldn’t sign the removal authorization. Nothing was removed — try again.';
        case 'ACCOUNT_DELETE_FAILED':
          return 'Your server couldn’t complete the deletion. The account is still there — try again.';
        case 'INVALID_AUDIT_LOG':
          return 'Couldn’t read this identity’s public history. Try again in a moment.';
        case 'TOMBSTONE_SIGNING_FAILED':
          return 'This device couldn’t sign the identity’s retirement. Nothing was retired — try again.';
        case 'PLC_DIRECTORY_ERROR':
          return 'The public record refused the identity’s retirement. Try again in a moment.';
        case 'IDENTITY_NOT_FOUND':
          return 'This identity isn’t registered in this wallet.';
        case 'LOCAL_WIPE_FAILED':
          return 'The account was removed, but this device couldn’t finish cleaning up. Try again to clear the leftover data.';
        case 'RATE_LIMITED':
          return 'The server is busy. Wait a moment and try again.';
        case 'NETWORK_ERROR':
          return 'Couldn’t reach the server. Check your connection and try again.';
        default:
          return 'Something went wrong. Please try again.';
      }
    }
    return 'Something went wrong. Please try again.';
  }

  /** Step 1: ask the PDS to email a confirmation code (unlocking the session if needed). */
  async function startRequest() {
    phase = 'requesting';
    error = null;
    try {
      await requestIdentityRemoval(did);
      phase = 'confirm';
    } catch (raw: unknown) {
      // A locked identity: run the host's unlock (biometric sovereign login on Custos, a
      // password prompt on any other host) once, then retry.
      if (isCodedError(raw) && (raw as RemovalError).code === 'SESSION_REQUIRED') {
        try {
          await unlockIdentity(did);
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

    workingMessage = isDidWeb
      ? 'Deleting your account and removing this identity…'
      : 'Deleting your account and retiring the identity…';
    phase = 'working';
    try {
      const outcome: RemovalOutcome = await confirmIdentityRemoval(
        did,
        requiresPassword ? password : null,
        code.trim(),
      );
      finishRemoval(outcome);
    } catch (raw: unknown) {
      console.error('confirmIdentityRemoval failed:', raw);
      hold.state.progress = 0;
      // The host wants a password after all — the route probe reads a per-host cache while
      // the confirm re-describes the server live, so the two can disagree if the identity's
      // host changed underneath us. Correct the flag, or the screen would show the "needs
      // your password" message with no field to type it in and a hold gesture still armed
      // to retry the identical, still-failing request.
      if (isCodedError(raw) && (raw as RemovalError).code === 'PASSWORD_REQUIRED') {
        requiresPassword = true;
      }
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

  /**
   * End a successful removal.
   *
   * A tombstone-less outcome (`tombstoneCid: null` — a did:web) is NOT finished from the
   * user's point of view: the DID keeps resolving until its document leaves the domain, so
   * the screen says so instead of silently returning to the identity list as if the
   * identity had been retired network-wide.
   */
  function finishRemoval(outcome: RemovalOutcome) {
    if (outcome.tombstoneCid === null) {
      epilogueWasLast = outcome.wasLastIdentity;
      phase = 'web_epilogue';
      return;
    }
    oncomplete(outcome.wasLastIdentity);
  }

  /**
   * Resume path: retry the remaining work — the tombstone + local wipe for a did:plc, the
   * local wipe alone for a did:web (which has no tombstone to retry). Biometric-gated.
   */
  async function retryTombstone() {
    error = null;
    try {
      await authenticateBiometric('Finish removing this identity');
    } catch {
      return;
    }
    workingMessage = isDidWeb
      ? 'Finishing local cleanup…'
      : 'Retiring the identity on the network…';
    phase = 'working';
    try {
      const outcome: RemovalOutcome = await tombstoneIdentity(did);
      finishRemoval(outcome);
    } catch (raw: unknown) {
      console.error('tombstoneIdentity failed:', raw);
      error = messageFor(raw);
      phase = 'tombstone_retry';
    }
  }

  /**
   * Escape hatch: remove an identity whose PDS account no longer exists (deleted elsewhere /
   * migrated away), where the server-side delete can never succeed — the PDS answers an absent
   * account with the same opaque 401 as a wrong password, so it can't be auto-treated as done.
   *
   * Two variants, chosen by the advanced `alsoTombstone` toggle:
   * - default: wipe local material only, no network step (`forgetIdentityLocally`).
   * - advanced: also sign + publish a did:plc tombstone to retire the identity network-wide
   *   (`tombstoneIdentity`, which tombstones then wipes; idempotent if already tombstoned, and
   *   it fails cleanly if this device no longer holds a rotation key — e.g. after migrating away).
   *
   * Biometric-gated either way.
   */
  async function confirmForget() {
    error = null;
    try {
      await authenticateBiometric(
        alsoTombstone
          ? 'Retire this identity on the network and remove it'
          : 'Remove this identity from this device',
      );
    } catch {
      forgetHold.state.progress = 0;
      return; // gate declined — nothing wiped.
    }
    workingMessage = alsoTombstone
      ? 'Retiring the identity on the network…'
      : 'Removing this identity from this device…';
    phase = 'working';
    try {
      if (alsoTombstone) {
        const outcome: RemovalOutcome = await tombstoneIdentity(did);
        oncomplete(outcome.wasLastIdentity);
      } else {
        const wasLast = await forgetIdentityLocally(did);
        oncomplete(wasLast);
      }
    } catch (raw: unknown) {
      console.error('confirmForget failed:', raw);
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
    <!--
      In `web_epilogue` the identity is already gone, so returning to its detail screen would
      show a stale surface. Back there means the same thing Done does: leave the removed
      identity behind.
    -->
    <button
      class="back"
      onclick={() => (phase === 'web_epilogue' ? oncomplete(epilogueWasLast) : onback())}
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
    <div class="identity u-stack-xs">
      <span class="id-label u-label-muted">Identity</span>
      {#if handle}
        <span class="id-handle">{handle}</span>
      {/if}
      <span class="id-did u-id-mono">{truncateDid(did)}</span>
    </div>

    {#if phase === 'warn'}
      <div class="hero">
        <h1 class="hero-title">Permanently remove this identity</h1>
        <p class="hero-sub u-body-soft">This cannot be undone. Removing this identity will:</p>
      </div>
      <ul class="consequences">
        <li><strong>Delete your account</strong> and all its data on your server.</li>
        {#if !isDidWeb}
          <li><strong>Retire the identity across the network</strong> — it can never be reactivated or migrated.</li>
        {/if}
        <li><strong>Erase its keys</strong> from this device.</li>
      </ul>
      {#if isDidWeb}
        <p class="note u-fine">
          This identity lives at your own domain, so there is nothing to retire on the network.
          It keeps working until you take its document down — we'll show you what to remove
          once the account is deleted.
        </p>
      {/if}
      <p class="note u-fine">
        We'll email a confirmation code to the account address.
        {#if routeLoaded && requiresPassword}
          You'll enter that code and your account password to confirm.
        {:else if routeLoaded}
          You'll enter that code to confirm — this identity is held by its key on this device,
          not by a password.
        {/if}
      </p>
    {:else if phase === 'requesting'}
      <div class="loading">
        <Spinner size={32} label="Sending confirmation code" />
        <p class="loading-text u-status-text">Sending a confirmation code to your email…</p>
      </div>
    {:else if phase === 'confirm'}
      <div class="hero">
        <h1 class="hero-title">Confirm removal</h1>
        <p class="hero-sub u-body-soft">
          {#if requiresPassword}
            Enter the code we emailed you and your account password, then hold to remove.
          {:else}
            Enter the code we emailed you, then hold to remove. This device's key signs the rest.
          {/if}
        </p>
      </div>
      <div class="form u-stack-sm">
        <label class="field-label u-label-muted" for="removal-code">Confirmation code</label>
        <TextField
          id="removal-code"
          bind:value={code}
          mono
          autocapitalize="off"
          autocorrect="off"
          placeholder="Code from your email"
        />
        {#if requiresPassword}
          <label class="field-label u-label-muted" for="removal-password">Account password</label>
          <TextField
            id="removal-password"
            type="password"
            bind:value={password}
            placeholder="Your password"
          />
        {/if}
      </div>
    {:else if phase === 'working'}
      <div class="loading">
        <Spinner size={32} label="Removing identity" />
        <p class="loading-text u-status-text">{workingMessage}</p>
      </div>
    {:else if phase === 'tombstone_retry'}
      <div class="hero">
        <h1 class="hero-title">Almost done</h1>
        <p class="hero-sub u-body-soft">
          {#if isDidWeb}
            Your account was deleted, but erasing this identity's keys from this device didn't
            finish. Retry to complete removal.
          {:else}
            Your account was deleted, but retiring the identity on the network didn't finish. Your
            keys are still on this device — retry to complete removal.
          {/if}
        </p>
      </div>
    {:else if phase === 'web_epilogue'}
      <div class="hero">
        <h1 class="hero-title">One step is yours</h1>
        <p class="hero-sub u-body-soft">
          Your account is deleted and this identity's keys are erased from this device. The
          identity itself keeps resolving for as long as its document stays published.
        </p>
      </div>
      <ul class="consequences">
        <li>
          <strong>Take down the DID document</strong>
          {#if didWebDocUrl}
            at <span class="mono">{didWebDocUrl}</span>
          {/if}
          — delete it, blank it, or serve <span class="mono">410 Gone</span> — to retire this
          identity network-wide.
        </li>
        <li>
          <strong>If your server published it for you</strong>, deleting the account already
          stopped it being served, and there is nothing left for you to do.
        </li>
      </ul>
      <p class="note u-fine">
        The wallet can't do this part for you — it never had control of the domain. Until the
        document is gone, anyone can still resolve this DID to its last published state.
      </p>
    {:else if phase === 'forget_confirm'}
      <div class="hero">
        <h1 class="hero-title">
          {alsoTombstone ? 'Retire and remove this identity' : 'Remove from this device only'}
        </h1>
        <p class="hero-sub u-body-soft">
          Use this if this identity's account no longer exists on its server — for example it was
          already deleted, or you migrated it elsewhere.
        </p>
      </div>
      <ul class="consequences">
        <li><strong>Erases this identity's keys</strong> from this device.</li>
        {#if alsoTombstone}
          <li>
            <strong>Retires the identity on the network</strong> by tombstoning its DID — it can
            never be reactivated or migrated.
          </li>
        {:else}
          <li>
            <strong>Does not delete a server account</strong> or retire the identity on the network.
          </li>
        {/if}
      </ul>
      <p class="note danger-note u-fine">
        {#if alsoTombstone}
          Tombstoning is permanent and network-wide. Only continue if you are certain you want to
          destroy this identity everywhere — it cannot be undone.
        {:else}
          If this identity is still active anywhere, removing its keys here may permanently end your
          ability to control it. This can't be undone.
        {/if}
      </p>

      {#if isDidWeb}
        <p class="note u-fine">
          There is no network-wide retirement the wallet can perform for a domain
          identity: it is retired by taking its document
          {#if didWebDocUrl}
            at <span class="mono">{didWebDocUrl}</span>
          {/if}
          off the domain, which only whoever controls that domain can do.
        </p>
      {:else}
        <button class="toggle" onclick={() => { showAdvanced = !showAdvanced; }}>
          {showAdvanced ? 'Hide advanced options' : 'Advanced options'}
        </button>
        {#if showAdvanced}
          <label class="advanced-check">
            <input type="checkbox" bind:checked={alsoTombstone} />
            <span class="check-body u-stack-xs">
              <span class="check-title u-title-strong">Also retire this identity on the network</span>
              <span class="check-desc">
                Sign and publish a did:plc tombstone so the identity is permanently retired
                everywhere, not just on this device. Requires this device to still hold one of the
                identity's rotation keys.
              </span>
            </span>
          </label>
        {/if}
      {/if}
    {/if}

    {#if error}
      <div class="error-box" role="alert">
        <p class="error-text u-error-text">{error}</p>
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
      {#if !isDidWeb}
        <button class="link-action" onclick={startForget}>Remove from this device instead</button>
      {/if}
      <Button variant="secondary" onclick={onback}>Close</Button>
    {:else if phase === 'web_epilogue'}
      <Button onclick={() => oncomplete(epilogueWasLast)}>Done</Button>
    {:else if phase === 'forget_confirm'}
      <button
        class="hold"
        onpointerdown={forgetHold.start}
        onpointerup={forgetHold.end}
        onpointerleave={forgetHold.end}
        onpointercancel={forgetHold.end}
        onkeydown={forgetHold.keydown}
        onkeyup={forgetHold.keyup}
        aria-label={alsoTombstone
          ? 'Press and hold to retire this identity on the network and remove it'
          : 'Press and hold to remove this identity from this device'}
      >
        <span class="hold-fill" style="transform: scaleX({forgetHoldFill})"></span>
        <span class="hold-label">
          {alsoTombstone ? 'Hold to retire & remove' : 'Hold to remove from device'}
        </span>
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
    gap: var(--space-2xs);
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs);
    min-height: var(--size-tap-target);
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
    width: var(--size-tap-target);
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

  .id-handle {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
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

  /* Literal machine strings inline in prose — a DID method, a document URL, an HTTP status.
     Wraps anywhere because a did:web document URL is long and must never widen the screen. */
  .mono {
    font-family: var(--font-mono);
    font-size: 0.95em;
    word-break: break-all;
  }

  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    padding: var(--space-xl) 0;
  }

  .error-box {
    background: var(--color-critical-surface);
    border-radius: var(--radius-md);
    padding: 12px var(--space-md);
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
    min-height: var(--size-tap-target);
  }

  .danger-note {
    color: var(--color-critical);
  }

  /* Advanced disclosure — the "reveal the machinery" toggle, matching DIDDocumentScreen. */
  .toggle {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: 10px var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    cursor: pointer;
    text-align: center;
  }

  .advanced-check {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    padding: var(--space-md);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    background: var(--color-surface-sunk);
    cursor: pointer;
  }
  .advanced-check input[type='checkbox'] {
    margin-top: var(--space-3xs);
    width: 20px;
    height: 20px;
    flex-shrink: 0;
    accent-color: var(--color-critical-solid);
    cursor: pointer;
  }
  .check-desc {
    font-size: var(--text-label);
    line-height: 1.5;
    color: var(--color-ink-soft);
  }
</style>
