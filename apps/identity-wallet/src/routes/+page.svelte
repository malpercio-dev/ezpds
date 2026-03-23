<script lang="ts">
  import WelcomeScreen from '$lib/components/onboarding/WelcomeScreen.svelte';
  import ClaimCodeScreen from '$lib/components/onboarding/ClaimCodeScreen.svelte';
  import EmailScreen from '$lib/components/onboarding/EmailScreen.svelte';
  import HandleScreen from '$lib/components/onboarding/HandleScreen.svelte';
  import PasswordScreen from '$lib/components/onboarding/PasswordScreen.svelte';
  import LoadingScreen from '$lib/components/onboarding/LoadingScreen.svelte';
  import DIDCeremonyScreen from '$lib/components/onboarding/DIDCeremonyScreen.svelte';
  import DIDSuccessScreen from '$lib/components/onboarding/DIDSuccessScreen.svelte';
  import ShamirBackupScreen from '$lib/components/onboarding/ShamirBackupScreen.svelte';
  import { createAccount, type CreateAccountError } from '$lib/ipc';

  // ── Onboarding step type ─────────────────────────────────────────────────
  //
  // Design plan originally specified an 'error' state for displaying errors,
  // but the implementation uses per-screen error rewinding instead.
  // When an error occurs (e.g., EXPIRED_CODE, EMAIL_TAKEN), the app rewinds
  // to the relevant screen and displays an inline error message below the
  // input field, rather than showing a separate error screen. This is a better
  // UX pattern — users can immediately correct the issue on the same screen
  // instead of navigating through an extra modal. No 'error' step is needed.

  type OnboardingStep =
    | 'welcome'
    | 'claim_code'
    | 'email'
    | 'handle'
    | 'password'
    | 'loading'
    | 'did_ceremony'
    | 'did_success'
    | 'shamir_backup'
    | 'complete';

  // ── State ────────────────────────────────────────────────────────────────

  let step = $state<OnboardingStep>('welcome');
  let form = $state({ claimCode: '', email: '', handle: '', password: '', did: '', share3: '' });

  /**
   * Per-field error messages displayed by each screen.
   * Cleared when the user navigates forward to the next step.
   */
  let errors = $state<{ claimCode?: string; email?: string; handle?: string }>(
    {}
  );

  // ── Navigation helpers ───────────────────────────────────────────────────

  function goTo(next: OnboardingStep) {
    errors = {};
    step = next;
  }

  // ── Account creation ─────────────────────────────────────────────────────

  async function submitAccount() {
    step = 'loading';
    errors = {};

    try {
      const result = await createAccount({
        claimCode: form.claimCode,
        email: form.email,
        handle: form.handle,
      });

      // Rust guarantees nextStep is 'did_creation' on success; unrecognized
      // relay values fail deserialization and surface as CreateAccountError::Unknown.
      step = 'did_ceremony';
    } catch (raw: unknown) {
      // Guard against non-CreateAccountError shapes (e.g. JS runtime errors).
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as CreateAccountError).code === 'string'
      ) {
        handleError(raw as CreateAccountError);
      } else {
        errors.handle = "Couldn't reach the server. Check your connection.";
        step = 'handle';
      }
    }
  }

  function handleError(err: CreateAccountError) {
    switch (err.code) {
      case 'EXPIRED_CODE':
        errors.claimCode = 'This claim code has expired. Please request a new one.';
        step = 'claim_code';
        break;
      case 'REDEEMED_CODE':
        errors.claimCode = 'This claim code has already been used.';
        step = 'claim_code';
        break;
      case 'EMAIL_TAKEN':
        errors.email = 'An account with that email already exists.';
        step = 'email';
        break;
      case 'HANDLE_TAKEN':
        errors.handle = 'That handle is taken. Please choose another.';
        step = 'handle';
        break;
      case 'KEYCHAIN_ERROR':
        errors.handle = "Couldn't save credentials to your device. Try again.";
        step = 'handle';
        break;
      case 'NETWORK_ERROR':
        errors.handle = "Couldn't reach the server. Check your connection.";
        step = 'handle';
        break;
      case 'UNKNOWN':
      default:
        errors.handle = 'Something went wrong. Please try again.';
        step = 'handle';
        break;
    }
  }
</script>

<div class="app">
  {#if step === 'welcome'}
    <WelcomeScreen onstart={() => goTo('claim_code')} />
  {:else if step === 'claim_code'}
    <ClaimCodeScreen
      bind:value={form.claimCode}
      error={errors.claimCode}
      onnext={() => goTo('email')}
    />
  {:else if step === 'email'}
    <EmailScreen
      bind:value={form.email}
      error={errors.email}
      onnext={() => goTo('handle')}
    />
  {:else if step === 'handle'}
    <HandleScreen
      bind:value={form.handle}
      error={errors.handle}
      onnext={() => goTo('password')}
    />
  {:else if step === 'password'}
    <PasswordScreen
      bind:value={form.password}
      onnext={submitAccount}
    />
  {:else if step === 'loading'}
    <LoadingScreen statusText="Creating your account…" />
  {:else if step === 'did_ceremony'}
    <DIDCeremonyScreen
      handle={form.handle}
      password={form.password}
      onsuccess={(result) => { form.did = result.did; form.share3 = result.share3; step = 'did_success'; }}
    />
  {:else if step === 'did_success'}
    <DIDSuccessScreen
      did={form.did}
      oncontinue={() => { step = 'shamir_backup'; }}
    />
  {:else if step === 'shamir_backup'}
    <ShamirBackupScreen
      share3={form.share3}
      oncomplete={() => { step = 'complete'; }}
    />
  {:else if step === 'complete'}
    <div class="complete">
      <div class="complete-icon" aria-hidden="true">✓</div>
      <h2>You're All Set!</h2>
      <p>Your identity is ready. Your recovery key has been safely backed up.</p>
    </div>
  {/if}
</div>

<style>
  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .complete {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 1.25rem;
    text-align: center;
    padding: 2rem;
  }

  .complete-icon {
    width: 64px;
    height: 64px;
    background: #007aff;
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: 700;
  }

  .complete h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .complete p {
    font-size: 0.95rem;
    color: #6b7280;
    margin: 0;
  }
</style>
