<script lang="ts">
  import { onMount } from 'svelte';
  import {
    requestClaimVerification,
    signAndVerifyClaim,
    type VerifiedClaimOp,
    type ClaimError,
  } from '$lib/ipc';
  import { isCodedError } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    did,
    onnext,
    onback,
  }: {
    did: string;
    onnext: (result: VerifiedClaimOp) => void;
    onback: () => void;
  } = $props();

  let token = $state('');
  let sending = $state(true); // true while sending verification email
  let sendError = $state<string | null>(null);
  let verifying = $state(false); // true while verifying token
  let verifyError = $state<string | null>(null);

  // ── Send verification email on mount ─────────────────────────────────────
  async function sendVerificationEmail() {
    sending = true;
    sendError = null;

    try {
      await requestClaimVerification(did);
      sending = false;
    } catch (e) {
      sending = false;
      console.error('Failed to send verification email:', e);
      if (isCodedError(e) && e.code === 'UNAUTHORIZED') {
        sendError = 'Authorization expired. Please go back and re-authenticate with your PDS.';
      } else {
        sendError = 'Failed to send verification email. Please try again.';
      }
    }
  }

  // ── Verify token and sign claim ──────────────────────────────────────────
  async function verifyToken() {
    verifying = true;
    verifyError = null;

    try {
      const result = await signAndVerifyClaim(did, token.trim());
      onnext(result);
    } catch (raw: unknown) {
      verifying = false;
      console.error('Claim verification failed:', raw);

      if (isCodedError(raw)) {
        const err = raw as ClaimError;
        switch (err.code) {
          case 'INVALID_TOKEN':
            verifyError = 'Invalid or expired verification code. Check your email and try again.';
            break;
          case 'VERIFICATION_FAILED':
            verifyError = `Verification failed: ${err.message ?? 'Please try again.'}`;
            break;
          case 'NETWORK_ERROR':
            verifyError = 'Network error. Check your connection and try again.';
            break;
          default:
            verifyError = `An error occurred (${err.code}). Please try again.`;
        }
      } else {
        verifyError = 'An error occurred. Please try again.';
      }
    }
  }

  onMount(() => {
    sendVerificationEmail();
  });
</script>

{#if sending}
  <div class="centered">
    <Spinner size={44} label="Sending verification email" />
    <p class="status">Sending verification email…</p>
  </div>
{:else if sendError}
  <OnboardingShell title="Email verification" subtitle="We couldn't send the verification email.">
    <p class="error" role="alert">{sendError}</p>
    <Button onclick={sendVerificationEmail}>Retry</Button>
    <Button variant="secondary" onclick={onback}>Back</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell title="Email verification" subtitle="A verification code has been sent to your email. Enter it below.">
    <TextField
      bind:value={token}
      type="text"
      placeholder="Enter verification code"
      autocomplete="off"
      aria-label="Verification code"
      disabled={verifying}
      error={verifyError ?? undefined}
    />
    <Button disabled={!token.trim() || verifying} onclick={verifyToken}>
      {verifying ? 'Verifying…' : 'Verify'}
    </Button>
    <Button variant="secondary" onclick={onback} disabled={verifying}>Back</Button>
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
  .error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
</style>
