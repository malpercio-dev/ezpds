<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import WelcomeScreen from '$lib/components/onboarding/WelcomeScreen.svelte';
  import ClaimCodeScreen from '$lib/components/onboarding/ClaimCodeScreen.svelte';
  import EmailScreen from '$lib/components/onboarding/EmailScreen.svelte';
  import HandleScreen from '$lib/components/onboarding/HandleScreen.svelte';
  import PasswordScreen from '$lib/components/onboarding/PasswordScreen.svelte';
  import LoadingScreen from '$lib/components/onboarding/LoadingScreen.svelte';
  import DIDCeremonyScreen from '$lib/components/onboarding/DIDCeremonyScreen.svelte';
  import DIDSuccessScreen from '$lib/components/onboarding/DIDSuccessScreen.svelte';
  import ShamirBackupScreen from '$lib/components/onboarding/ShamirBackupScreen.svelte';
  import HandleRegistrationScreen from '$lib/components/onboarding/HandleRegistrationScreen.svelte';
  import AuthenticatingScreen from '$lib/components/onboarding/AuthenticatingScreen.svelte';
  import HomeScreen from '$lib/components/home/HomeScreen.svelte';
  import DIDDocumentScreen from '$lib/components/home/DIDDocumentScreen.svelte';
  import RecoveryInfoScreen from '$lib/components/home/RecoveryInfoScreen.svelte';
  import { createAccount, type CreateAccountError, type OAuthError, type HomeData } from '$lib/ipc';

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
    | 'handle_registration'
    | 'complete'
    | 'authenticating'
    | 'home'
    | 'did_document'
    | 'recovery_info'
    | 'auth_failed';

  // ── State ────────────────────────────────────────────────────────────────

  let step = $state<OnboardingStep>('welcome');
  let form = $state({ claimCode: '', email: '', handle: '', password: '', did: '', share3: '', registeredHandle: '' });

  /**
   * Per-field error messages displayed by each screen.
   * Cleared when the user navigates forward to the next step.
   */
  let errors = $state<{ claimCode?: string; email?: string; handle?: string; password?: string }>(
    {}
  );

  let authError = $state<OAuthError | null>(null);

  let homeData = $state<HomeData | null>(null);

  // ── Navigation helpers ───────────────────────────────────────────────────

  function goTo(next: OnboardingStep) {
    errors = {};
    step = next;
  }

  // ── OAuth event listener ──────────────────────────────────────────────────

  onMount(() => {
    listen('auth_ready', () => {
      goTo('home');
    });
    // Note: We intentionally don't await listen() or return a cleanup function here.
    // Svelte 5's onMount does not await async cleanup return values (it would receive a
    // Promise, not the unlisten function). Since +page.svelte is the root page and never
    // unmounts during the app lifecycle, the listener persists for the app's lifetime,
    // which is the correct behavior.
  });

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
        errors.password = "Couldn't save credentials to your device. Try again.";
        step = 'password';
        break;
      case 'NETWORK_ERROR':
        errors.password = "Couldn't reach the server. Check your connection.";
        step = 'password';
        break;
      case 'UNKNOWN':
      default:
        errors.password = 'Something went wrong. Please try again.';
        step = 'password';
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
      error={errors.password}
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
      oncomplete={() => { step = 'handle_registration'; }}
    />
  {:else if step === 'handle_registration'}
    <HandleRegistrationScreen
      handleLabel={form.handle}
      did={form.did}
      onsuccess={(handle) => { form.registeredHandle = handle; step = 'complete'; }}
      ontimeout={(handle) => { form.registeredHandle = handle; step = 'complete'; }}
    />

  {:else if step === 'complete'}
    <div class="complete">
      <div class="complete-icon" aria-hidden="true">✓</div>
      <h2>You're All Set!</h2>
      <p>Your identity is ready. Your recovery key has been safely backed up.</p>
      <button class="cta" onclick={() => goTo('authenticating')}>
        Continue
      </button>
    </div>

  {:else if step === 'authenticating'}
    <AuthenticatingScreen
      onresolved={() => goTo('home')}
      onfailed={(err) => {
        authError = err;
        goTo('auth_failed');
      }}
    />

  {:else if step === 'home'}
    <HomeScreen
      onnavdiddoc={(data) => { homeData = data; goTo('did_document'); }}
      onnavrecovery={(data) => { homeData = data; goTo('recovery_info'); }}
      onlogout={() => goTo('welcome')}
    />

  {:else if step === 'did_document'}
    <DIDDocumentScreen
      didDoc={homeData?.session?.didDoc ?? {}}
      onback={() => goTo('home')}
    />

  {:else if step === 'recovery_info'}
    <RecoveryInfoScreen
      share1InKeychain={homeData?.share1InKeychain ?? false}
      onback={() => goTo('home')}
    />

  {:else if step === 'auth_failed'}
    <div class="oauth-screen">
      <div class="oauth-icon" aria-hidden="true">✗</div>
      <h2 class="oauth-title">Authentication Failed</h2>
      {#if authError}
        <p class="oauth-error-code">{authError.code}</p>
      {/if}
      <div class="oauth-actions">
        <button
          class="cta"
          onclick={() => {
            authError = null;
            goTo('authenticating');
          }}
        >
          Try again
        </button>
        <button
          class="cta cta--secondary"
          onclick={() => {
            authError = null;
            goTo('welcome');
          }}
        >
          Start over
        </button>
      </div>
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

  .oauth-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 24px;
    padding: 32px;
    text-align: center;
  }

  .oauth-icon {
    font-size: 3rem;
  }

  .oauth-title {
    font-size: 1.5rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .oauth-error-code {
    font-family: monospace;
    font-size: 0.875rem;
    color: #6b7280;
    margin: 0;
  }

  .oauth-actions {
    display: flex;
    flex-direction: column;
    gap: 12px;
    width: 100%;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
  }

  .cta--secondary {
    background: #f3f4f6;
    color: #374151;
  }
</style>
