<script lang="ts">
  import {
    initiateEscrowRelease,
    requestEscrowRelease,
    isCodedError,
    type CollectedShare,
    type ShareRecoveryError,
  } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    onreleased,
    onback,
  }: {
    /** Share 2 collected — return to the shares screen. */
    onreleased: (share: CollectedShare) => void;
    onback: () => void;
  } = $props();

  // intro → otp → pending → (released via onreleased) | cancelled
  type Phase = 'intro' | 'otp' | 'pending' | 'cancelled';
  let phase = $state<Phase>('intro');
  let otp = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let availableAt = $state<string | null>(null);

  function describeError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch ((raw as ShareRecoveryError).code) {
        case 'RELEASE_UNAUTHORIZED':
          return 'The server declined this code. It may be wrong, expired, or already used — request a new one.';
        case 'RATE_LIMITED':
          return 'Too many attempts. Wait a moment and try again.';
        case 'SHARE_SET_MISMATCH':
          return 'The escrowed share is from a different backup generation than the one on this device. Contact your server operator.';
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        default:
          return `An unexpected error occurred (${(raw as ShareRecoveryError).code}). Please try again.`;
      }
    }
    return 'An unexpected error occurred. Please try again.';
  }

  async function sendCode() {
    busy = true;
    error = null;
    try {
      await initiateEscrowRelease();
      phase = 'otp';
    } catch (raw: unknown) {
      console.error('Escrow initiate failed:', raw);
      error = describeError(raw);
    } finally {
      busy = false;
    }
  }

  async function submitCode() {
    if (!otp.trim()) return;
    busy = true;
    error = null;
    try {
      const status = await requestEscrowRelease(otp.trim());
      if (status.status === 'released' && status.share) {
        onreleased(status.share);
      } else {
        availableAt = status.availableAt;
        phase = 'pending';
      }
    } catch (raw: unknown) {
      console.error('Escrow release failed:', raw);
      error = describeError(raw);
    } finally {
      busy = false;
    }
  }

  async function poll() {
    busy = true;
    error = null;
    try {
      const status = await requestEscrowRelease();
      if (status.status === 'released' && status.share) {
        onreleased(status.share);
      } else {
        availableAt = status.availableAt ?? availableAt;
      }
    } catch (raw: unknown) {
      console.error('Escrow poll failed:', raw);
      // During the wait, a uniform refusal usually means the release was
      // cancelled (by you, or by someone signed in to your account).
      if (isCodedError(raw) && (raw as ShareRecoveryError).code === 'RELEASE_UNAUTHORIZED') {
        phase = 'cancelled';
      } else {
        error = describeError(raw);
      }
    } finally {
      busy = false;
    }
  }
</script>

{#if phase === 'intro'}
  <OnboardingShell
    title="Request the escrow share"
    subtitle="Your server will email a one-time code to your account address. The code unlocks the release — not the share itself."
    {onback}
  >
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button disabled={busy} onclick={sendCode}>{busy ? 'Sending…' : 'Email me a code'}</Button>
  </OnboardingShell>
{:else if phase === 'otp'}
  <OnboardingShell
    title="Enter the emailed code"
    subtitle="Check the inbox for your account email. The code works once and expires after an hour."
    onback={() => (phase = 'intro')}
  >
    <TextField
      bind:value={otp}
      type="text"
      placeholder="Code from the email"
      autocomplete="one-time-code"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Escrow release code"
      mono
      error={error ?? undefined}
    />
    <Button disabled={busy || !otp.trim()} onclick={submitCode}>
      {busy ? 'Unlocking…' : 'Unlock the share'}
    </Button>
  </OnboardingShell>
{:else if phase === 'pending'}
  <OnboardingShell
    title="Release opened"
    subtitle="Your server holds the share for a waiting period before handing it over. This delay is a protection: it gives you time to stop a release you didn't ask for."
  >
    <div class="pending-box">
      <p class="pending-label">Share available after</p>
      <p class="pending-time">{availableAt ?? 'the configured waiting period'}</p>
      <p class="pending-note">
        The server has notified your account email. Anyone still signed in to your account can
        cancel this release — if that happens, you'll see it here. You can close the app and come
        back; the wait continues on the server.
      </p>
    </div>
    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}
    <Button disabled={busy} onclick={poll}>{busy ? 'Checking…' : 'Check again'}</Button>
    <Button variant="secondary" onclick={onback}>Back to shares</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell
    title="Release no longer available"
    subtitle="The server declined to hand over the share. The release was cancelled from a signed-in device, or it expired."
  >
    <p class="cancel-note">
      If you cancelled it yourself, nothing more to do. If you didn't, someone with access to your
      account stopped it — your other backup shares still work, and no share was disclosed.
    </p>
    <Button onclick={() => (phase = 'intro')}>Start a new request</Button>
    <Button variant="secondary" onclick={onback}>Back to shares</Button>
  </OnboardingShell>
{/if}

<style>
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
    line-height: 1.4;
  }
  .pending-box {
    width: 100%;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    text-align: left;
  }
  .pending-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .pending-time {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    margin: 0;
  }
  .pending-note,
  .cancel-note {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.5;
  }
</style>
