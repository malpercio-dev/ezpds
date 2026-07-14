<script lang="ts">
  import { authenticateSourcePds, isCodedError, type ClaimError } from '$lib/ipc';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    did,
    handle,
    pdsUrl,
    onnext,
    onback,
  }: {
    did: string;
    handle: string;
    pdsUrl: string;
    onnext: () => void;
    onback: () => void;
  } = $props();

  // Prefill the login identifier with the resolved handle, then let the user edit it to a DID or
  // email if that is how they sign in to their PDS. Capturing the initial value is intentional —
  // this screen's `handle` prop is fixed for its lifetime, so it never needs to re-sync.
  // svelte-ignore state_referenced_locally
  let identifier = $state(handle);
  let password = $state('');
  // For accounts with email 2FA: once the PDS asks for a code, we keep the password in memory and
  // re-submit it alongside the code the user enters here.
  let needsTwoFactor = $state(false);
  let twoFactorToken = $state('');
  let authenticating = $state(false);
  let error = $state<string | null>(null);

  async function authenticate() {
    if (!identifier.trim() || !password) return;
    if (needsTwoFactor && !twoFactorToken.trim()) return;
    authenticating = true;
    error = null;

    try {
      await authenticateSourcePds(
        did,
        identifier.trim(),
        password,
        needsTwoFactor ? twoFactorToken.trim() : undefined,
      );
      // Credentials are not retained after this call resolves.
      password = '';
      twoFactorToken = '';
      onnext();
    } catch (raw: unknown) {
      authenticating = false;
      console.error('Source PDS sign-in failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'TWO_FACTOR_REQUIRED':
            if (needsTwoFactor) {
              // We already submitted a code and it wasn't accepted.
              error = "That code wasn't accepted. Check the latest code emailed to you.";
            } else {
              // First time: the account has 2FA. Advance to the code step — not an error.
              needsTwoFactor = true;
            }
            break;
          case 'SOURCE_AUTH_FAILED':
            error = needsTwoFactor
              ? "That code wasn't accepted. Check the latest code emailed to you."
              : `${pdsUrl} did not accept that password. Use your account password — an app password can't authorize identity changes.`;
            break;
          case 'ACCOUNT_MISMATCH':
            error = `Those credentials signed in to a different account than ${handle}. Sign in as ${handle}.`;
            break;
          case 'INSECURE_SOURCE_URL':
            error = `Can't sign in securely: ${pdsUrl} isn't served over HTTPS. Your password won't be sent over an unencrypted connection.`;
            break;
          case 'INSUFFICIENT_SCOPE':
            error = `${pdsUrl} refused to authorize the identity change for this session. This shouldn't happen with a full sign-in — please try again.`;
            break;
          case 'UNAUTHORIZED':
            error = 'This claim is no longer active. Go back and start again.';
            break;
          case 'RATE_LIMITED':
            error = formatRateLimitMessage(err.retryAfter);
            break;
          case 'SERVER_ERROR':
            error = formatServerErrorMessage(err.message);
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = `Sign-in failed (${err.code}). Please try again.`;
        }
      } else {
        error = 'Sign-in failed. Please try again.';
      }
    }
  }

  // Return from the 2FA step to the password form (e.g. wrong account, or to restart).
  function backToPassword() {
    needsTwoFactor = false;
    twoFactorToken = '';
    error = null;
  }
</script>

{#if authenticating}
  <div class="centered">
    <Spinner size={44} label="Signing in" />
    <p class="status">Opening a session with your PDS…</p>
  </div>
{:else if needsTwoFactor}
  <OnboardingShell
    title="Enter your two-factor code"
    subtitle="Your account has email two-factor authentication turned on."
  >
    <span class="pds-chip">{pdsUrl}</span>

    <div class="why" role="note">
      <p>{pdsUrl} emailed a one-time code to the address on <strong>{identifier}</strong>. Enter it to finish signing in.</p>
    </div>

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

    <Button disabled={!twoFactorToken.trim()} onclick={authenticate}>Verify code</Button>
    <Button variant="secondary" onclick={backToPassword}>Back</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell
    title="Sign in to your PDS"
    subtitle="Adding this device as a recovery key is an identity change, and the AT Protocol lets only a full sign-in authorize one."
  >
    <span class="pds-chip">{pdsUrl}</span>

    <div class="why" role="note">
      <p>
        Your PDS only permits identity changes with your <strong>account password</strong> — the
        protocol has no way to delegate this one action, which is why migration tools ask for it too.
      </p>
      <p class="reassure">
        Your password is sent only to {pdsUrl}, used once to open a session, and never stored on this
        device or seen by Obsign. An app password won't work here.
      </p>
    </div>

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
    <TextField
      bind:value={password}
      type="password"
      autocomplete="current-password"
      aria-label="Account password"
      placeholder="Account password"
      error={error ?? undefined}
    />

    <Button disabled={!identifier.trim() || !password} onclick={authenticate}>
      {error ? 'Try again' : 'Sign in'}
    </Button>
    <Button variant="secondary" onclick={onback}>Back</Button>
  </OnboardingShell>
{/if}

<style>
  .centered {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: var(--space-lg);
    padding: var(--space-xl);
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }
  .pds-chip {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    word-break: break-all;
    max-width: 100%;
  }
  .why {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    font-size: var(--text-label);
    line-height: 1.5;
    color: var(--color-ink);
  }
  .why p {
    margin: 0;
  }
  .why .reassure {
    color: var(--color-muted);
  }
</style>
