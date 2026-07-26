<script lang="ts">
  import { onMount, tick } from 'svelte';

  import { isCodedError, unlockIdentityWithPassword, type UnlockError } from '$lib/ipc';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import {
    registerPasswordUnlockPrompt,
    UNLOCK_CANCELLED,
    type PasswordUnlockRequest,
  } from '$lib/unlock';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';

  // The app-level password unlock prompt: mounted once at the root, driven by `$lib/unlock`.
  //
  // A Custos-hosted identity reopens with a device-key signature and no dialog at all. On any
  // other spec-compliant host there is no such proof, so the account's password opens the
  // session (ADR-0021 — the operations behind it need a full session, which no OAuth
  // `transition:generic` token can grant). The password is submitted once and never stored:
  // only the JWT pair the server returns is persisted, into the same record `sovereignLogin`
  // writes.
  //
  // It lives at the root rather than inside each screen because `unlockIdentity` is called from
  // the middle of async operations (`catch SESSION_LOCKED → unlock → retry`), which cannot
  // render a form of their own. The dialog resolves the promise those callers are awaiting.

  type Pending = {
    request: PasswordUnlockRequest;
    resolve: () => void;
    reject: (reason: unknown) => void;
  };

  let pending = $state<Pending | null>(null);
  let identifier = $state('');
  let password = $state('');
  // Once the host asks for an emailed code we keep the typed password in memory and resubmit it
  // alongside the code — `createSession` takes all three at once.
  let needsTwoFactor = $state(false);
  let twoFactorToken = $state('');
  let submitting = $state(false);
  let error = $state<string | null>(null);
  let passwordField = $state<HTMLElement | null>(null);

  onMount(() =>
    registerPasswordUnlockPrompt(
      (request) =>
        new Promise<void>((resolve, reject) => {
          identifier = request.handle ?? request.did;
          password = '';
          needsTwoFactor = false;
          twoFactorToken = '';
          submitting = false;
          error = null;
          pending = { request, resolve, reject };
          void tick().then(() => passwordField?.querySelector('input')?.focus());
        }),
    ),
  );

  /** Clear every credential this dialog held before it goes away. */
  function reset() {
    password = '';
    twoFactorToken = '';
    identifier = '';
    needsTwoFactor = false;
    error = null;
    submitting = false;
    pending = null;
  }

  function cancel() {
    const current = pending;
    reset();
    current?.reject({ code: UNLOCK_CANCELLED });
  }

  const canSubmit = $derived(
    !submitting &&
      identifier.trim().length > 0 &&
      password.length > 0 &&
      (!needsTwoFactor || twoFactorToken.trim().length > 0),
  );

  async function submit() {
    if (!pending || !canSubmit) return;
    const { request, resolve } = pending;
    submitting = true;
    error = null;

    try {
      await unlockIdentityWithPassword(
        request.did,
        identifier.trim(),
        password,
        needsTwoFactor ? twoFactorToken.trim() : undefined,
      );
      reset();
      resolve();
    } catch (raw: unknown) {
      submitting = false;
      console.error('[PasswordUnlockDialog] unlock failed:', raw);
      error = messageFor(raw, request);
    }
  }

  function messageFor(raw: unknown, request: PasswordUnlockRequest): string | null {
    if (!isCodedError(raw)) return 'Sign-in failed. Please try again.';
    const err = raw as UnlockError;
    const who = request.handle ?? request.did;

    switch (err.code) {
      case 'TWO_FACTOR_REQUIRED':
        if (needsTwoFactor) return "That code wasn't accepted. Check the latest code emailed to you.";
        // First time: not a failure — the host emailed a code and wants it. Advance the form.
        needsTwoFactor = true;
        return null;
      case 'INVALID_CREDENTIALS':
        return needsTwoFactor
          ? "That code wasn't accepted. Check the latest code emailed to you."
          : `${request.pdsUrl} did not accept that password. Use your account password — an app password can't unlock an identity.`;
      case 'ACCOUNT_MISMATCH':
        return `Those credentials signed in to a different account than ${who}. Sign in as ${who}.`;
      case 'INSECURE_HOST_URL':
        return `Can't sign in securely: ${request.pdsUrl} isn't served over HTTPS. Your password won't be sent over an unencrypted connection.`;
      case 'UNSUPPORTED_HOST':
        return `Couldn't reach the server hosting ${who}. Check your connection and try again.`;
      case 'RATE_LIMITED':
        return formatRateLimitMessage(err.retryAfter ?? null);
      case 'SERVER_ERROR':
        return formatServerErrorMessage(err.message ?? '');
      case 'NETWORK_ERROR':
        return 'Network error. Check your connection and try again.';
      case 'IDENTITY_NOT_FOUND':
        return "This identity isn't registered in the wallet.";
      default:
        return `Sign-in failed (${err.code}). Please try again.`;
    }
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape' && !submitting) {
      event.preventDefault();
      cancel();
    }
  }
</script>

<svelte:window on:keydown={pending ? onkeydown : undefined} />

{#if pending}
  <div class="scrim">
    <div
      class="sheet"
      role="dialog"
      aria-modal="true"
      aria-labelledby="unlock-title"
      aria-describedby="unlock-why"
    >
      {#if submitting}
        <div class="working">
          <Spinner size={44} label="Signing in" />
          <p class="status">Opening a session on {pending.request.pdsUrl}…</p>
        </div>
      {:else}
        <h2 id="unlock-title">
          {needsTwoFactor ? 'Enter your two-factor code' : 'Unlock this identity'}
        </h2>
        <span class="pds-chip">{pending.request.pdsUrl}</span>

        <p id="unlock-why">
          {#if needsTwoFactor}
            {pending.request.pdsUrl} emailed a one-time code to the address on
            <strong>{identifier}</strong>. Enter it to finish signing in.
          {:else}
            This server doesn't support passwordless sign-in, so it needs your account password
            to open a session. It's sent once, to {pending.request.pdsUrl}, and never stored.
          {/if}
        </p>

        {#if needsTwoFactor}
          <TextField
            bind:value={twoFactorToken}
            type="text"
            inputmode="text"
            autocomplete="one-time-code"
            autocapitalize="none"
            autocorrect="off"
            spellcheck={false}
            aria-label="Two-factor code"
            placeholder="Two-factor code"
            error={error ?? undefined}
          />
        {:else}
          <TextField
            bind:value={identifier}
            type="text"
            autocomplete="username"
            autocapitalize="none"
            autocorrect="off"
            spellcheck={false}
            aria-label="Handle, DID, or email"
            placeholder="Handle, DID, or email"
          />
          <div bind:this={passwordField}>
            <TextField
              bind:value={password}
              type="password"
              autocomplete="current-password"
              aria-label="Account password"
              placeholder="Account password"
              error={error ?? undefined}
            />
          </div>
        {/if}

        <Button disabled={!canSubmit} onclick={submit}>
          {#if needsTwoFactor}
            Verify code
          {:else}
            {error ? 'Try again' : 'Unlock'}
          {/if}
        </Button>
        <Button variant="secondary" onclick={cancel}>Cancel</Button>
      {/if}
    </div>
  </div>
{/if}

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    display: flex;
    align-items: flex-end;
    justify-content: center;
    /* Dim the screen behind the sheet without hiding it — the user should still see which
       surface they were on when the unlock interrupted them. */
    background: color-mix(in oklab, var(--color-bg) 78%, transparent);
    padding: var(--space-md);
    padding-bottom: max(var(--space-md), env(safe-area-inset-bottom));
  }
  .sheet {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    width: 100%;
    max-width: 32rem;
    max-height: 90vh;
    overflow-y: auto;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
  }
  h2 {
    font-family: var(--font-display);
    font-size: var(--text-title);
    color: var(--color-ink);
    margin: 0;
  }
  #unlock-why {
    font-size: var(--text-label);
    line-height: 1.5;
    color: var(--color-muted);
    margin: 0;
  }
  .pds-chip {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    word-break: break-all;
    max-width: 100%;
  }
  .working {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-lg);
    padding: var(--space-xl) var(--space-md);
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }
</style>
