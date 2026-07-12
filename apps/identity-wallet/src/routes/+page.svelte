<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import { onMount, onDestroy } from 'svelte';
  import ModeSelectScreen from '$lib/components/onboarding/ModeSelectScreen.svelte';
  import PdsConfigScreen from '$lib/components/onboarding/PdsConfigScreen.svelte';
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
  import IdentityInputScreen from '$lib/components/onboarding/IdentityInputScreen.svelte';
  import PdsAuthScreen from '$lib/components/onboarding/PdsAuthScreen.svelte';
  import EmailVerificationScreen from '$lib/components/onboarding/EmailVerificationScreen.svelte';
  import ReviewOperationScreen from '$lib/components/onboarding/ReviewOperationScreen.svelte';
  import ClaimSuccessScreen from '$lib/components/onboarding/ClaimSuccessScreen.svelte';
  import MigrationStartScreen from '$lib/components/onboarding/MigrationStartScreen.svelte';
  import MigrationSourceAuthScreen from '$lib/components/onboarding/MigrationSourceAuthScreen.svelte';
  import MigrationProgressScreen from '$lib/components/onboarding/MigrationProgressScreen.svelte';
  import MigrationReviewScreen from '$lib/components/onboarding/MigrationReviewScreen.svelte';
  import MigrationSuccessScreen from '$lib/components/onboarding/MigrationSuccessScreen.svelte';
  import DIDDocumentScreen from '$lib/components/home/DIDDocumentScreen.svelte';
  import RecoveryInfoScreen from '$lib/components/home/RecoveryInfoScreen.svelte';
  import AlertDetailScreen from '$lib/components/home/AlertDetailScreen.svelte';
  import RecoveryOverrideScreen from '$lib/components/home/RecoveryOverrideScreen.svelte';
  import MyAgentsScreen from '$lib/components/home/MyAgentsScreen.svelte';
  import AgentClaimApprovalScreen from '$lib/components/home/AgentClaimApprovalScreen.svelte';
  import SettingsScreen from '$lib/components/home/SettingsScreen.svelte';
  import { createAccount, registerCreatedIdentity, listIdentities, checkIdentityStatus, type CreateAccountError, type OAuthError, type HomeData, type IdentityInfo, type VerifiedClaimOp, type ClaimResult, type UnauthorizedChange } from '$lib/ipc';
  import { normalizePlcDocToW3c } from '$lib/did-doc-utils';
  import IdentityListHome from '$lib/components/home/IdentityListHome.svelte';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

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
    | 'mode_select'
    | 'pds_config'
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
    | 'identity_detail'
    | 'did_document'
    | 'recovery_info'
    | 'alert_detail'
    | 'recovery_override'
    | 'my_agents'
    | 'agent_approval'
    | 'settings'
    | 'auth_failed'
    | 'identity_input'
    | 'pds_auth'
    | 'email_verification'
    | 'review_operation'
    | 'claim_success'
    | 'migration_start'
    | 'migration_source_auth'
    | 'migration_progress'
    | 'migration_review'
    | 'migration_success';

  // ── State ────────────────────────────────────────────────────────────────

  let step = $state<OnboardingStep>('mode_select');
  let form = $state({ claimCode: '', email: '', handle: '', password: '', did: '', share3: '', registeredHandle: '', handleOrDid: '' });

  // ── Import flow state ────────────────────────────────────────────────────────
  let identityInfo = $state<IdentityInfo | null>(null);
  let verifiedClaim = $state<VerifiedClaimOp | null>(null);
  let claimResult = $state<ClaimResult | null>(null);

  /**
   * Per-field error messages displayed by each screen.
   * Cleared when the user navigates forward to the next step.
   */
  let errors = $state<{ claimCode?: string; email?: string; handle?: string; password?: string }>(
    {}
  );

  let authError = $state<OAuthError | null>(null);

  let homeData = $state<HomeData | null>(null);

  let selectedDid = $state<string | null>(null);
  let selectedDidDoc = $state<Record<string, unknown> | null>(null);
  let selectedDeviceKeyIsRoot = $state<boolean | null>(null);

  let selectedAlertDid = $state<string | null>(null);
  let selectedAlertChanges = $state<UnauthorizedChange[]>([]);

  let selectedRecoveryCid = $state<string | null>(null);
  let selectedRecoveryCreatedAt = $state<string | null>(null);

  // ── Migration flow state ──────────────────────────────────────────────────
  // Each migration screen owns its own transient error/progress display; the page only threads
  // the values a later screen consumes (destination + email for the flow, the result for success).
  let migrationDid = $state('');
  let migrationEmail = $state('');
  let migrationInviteCode = $state<string | undefined>(undefined);
  let migrationDestPds = $state('');
  let migrationResult = $state<ClaimResult | null>(null);

  // ── Navigation helpers ───────────────────────────────────────────────────

  function goTo(next: OnboardingStep) {
    errors = {};
    step = next;
  }

  // ── PDS configuration and OAuth event listener ──────────────────────

  function handleVisibilityChange() {
    if (document.visibilityState === 'visible' && step === 'home') {
      checkIdentityStatus().catch((e) => {
        console.warn('PLC status check failed:', e);
      });
    }
  }

  onMount(async () => {
    // If the user has claimed identities, skip to home.
    try {
      const identities = await listIdentities();
      if (identities.length > 0) {
        step = 'home';
      }
    } catch (e) {
      console.error('listIdentities failed on mount:', e);
      // First launch (empty Keychain) or Keychain error — continue to mode_select
    }

    // Legacy users (PDS URL configured but no managed-dids) stay at mode_select.
    // PdsConfigScreen internally checks for saved PDS URL, so the "Create new
    // identity" path handles them correctly without additional logic here.

    // Listen for auth_ready from PDS OAuth (existing onboarding flow).
    listen('auth_ready', () => {
      goTo('home');
    });
    // Note: We intentionally don't await listen() or return a cleanup function here.
    // Svelte 5's onMount does not await async cleanup return values (it would receive a
    // Promise, not the unlisten function). Since +page.svelte is the root page and never
    // unmounts during the app lifecycle, the listener persists for the app's lifetime,
    // which is the correct behavior.

    // PLC monitoring: check on app foreground
    document.addEventListener('visibilitychange', handleVisibilityChange);
  });

  onDestroy(() => {
    document.removeEventListener('visibilitychange', handleVisibilityChange);
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
      // PDS values fail deserialization and surface as CreateAccountError::Unknown.
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

  // ── Finish the create flow ────────────────────────────────────────────────
  //
  // Called once the new identity's DID (form.did) and full handle both exist.
  // Registering here is what makes the identity appear on the home screen:
  // IdentityListHome lists identities from IdentityStore alone, and the PDS
  // OAuth flow never writes to it — so without this call the home screen shows
  // "No identities yet" after login. This is the fix for that bug.
  //
  // Error-handling strategy: best-effort, matching this app's "always reach
  // home" pattern (loadHomeData / logOut never block the UI). If registration
  // fails we log and continue — the user keeps their identity and can refresh
  // the card later. (Strict alternative: surface the error and let the user
  // retry before advancing — see the accompanying notes.)
  async function finishCreateFlow(handle: string) {
    form.registeredHandle = handle;
    try {
      await registerCreatedIdentity(form.did, handle);
    } catch (e) {
      console.error('Failed to register created identity in IdentityStore:', e);
    }
    step = 'complete';
  }
</script>

<div class="app">
  {#if step === 'mode_select'}
    <ModeSelectScreen
      oncreate={() => goTo('pds_config')}
      onimport={() => goTo('identity_input')}
    />
  {:else if step === 'identity_input'}
    <IdentityInputScreen
      bind:value={form.handleOrDid}
      onnext={(info) => {
        identityInfo = info;
        goTo('pds_auth');
      }}
      onback={() => goTo('mode_select')}
    />
  {:else if step === 'pds_auth'}
    <PdsAuthScreen
      pdsUrl={identityInfo!.pdsUrl}
      onnext={() => goTo('email_verification')}
      onback={() => goTo('identity_input')}
    />
  {:else if step === 'email_verification'}
    <EmailVerificationScreen
      did={identityInfo!.did}
      onnext={(result) => {
        verifiedClaim = result;
        goTo('review_operation');
      }}
      onback={() => goTo('pds_auth')}
    />
  {:else if step === 'review_operation'}
    <ReviewOperationScreen
      did={identityInfo!.did}
      verifiedClaim={verifiedClaim!}
      onnext={(result) => {
        claimResult = result;
        goTo('claim_success');
      }}
      oncancel={() => goTo('identity_input')}
    />
  {:else if step === 'claim_success'}
    <ClaimSuccessScreen
      claimResult={claimResult!}
      ondone={() => goTo('home')}
    />
  {:else if step === 'pds_config'}
    <PdsConfigScreen onnext={() => goTo('claim_code')} onback={() => goTo('mode_select')} />
  {:else if step === 'claim_code'}
    <ClaimCodeScreen
      bind:value={form.claimCode}
      error={errors.claimCode}
      onnext={() => goTo('email')}
      onback={() => goTo('pds_config')}
    />
  {:else if step === 'email'}
    <EmailScreen
      bind:value={form.email}
      error={errors.email}
      onnext={() => goTo('handle')}
      onback={() => goTo('claim_code')}
    />
  {:else if step === 'handle'}
    <HandleScreen
      bind:value={form.handle}
      error={errors.handle}
      onnext={() => goTo('password')}
      onback={() => goTo('email')}
    />
  {:else if step === 'password'}
    <PasswordScreen
      bind:value={form.password}
      error={errors.password}
      onnext={submitAccount}
      onback={() => goTo('handle')}
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
      handle={form.handle}
      did={form.did}
      onsuccess={(handle) => finishCreateFlow(handle)}
      ontimeout={(handle) => finishCreateFlow(handle)}
    />

  {:else if step === 'complete'}
    <OnboardingShell
      tone="signet"
      title="You're all set"
      subtitle="Your identity is ready. Your recovery key has been safely backed up."
    >
      {#snippet icon()}
        <SealEmblem>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
        </SealEmblem>
      {/snippet}
      <Button onclick={() => goTo('authenticating')}>Continue</Button>
    </OnboardingShell>

  {:else if step === 'authenticating'}
    <AuthenticatingScreen
      onresolved={() => goTo('home')}
      onfailed={(err) => {
        authError = err;
        goTo('auth_failed');
      }}
    />

  {:else if step === 'home'}
    <IdentityListHome
      onadd={() => goTo('mode_select')}
      onselect={(did, didDoc, deviceKeyIsRoot) => {
        selectedDid = did;
        selectedDidDoc = didDoc;
        selectedDeviceKeyIsRoot = deviceKeyIsRoot;
        goTo('identity_detail');
      }}
      onalert={(did, changes) => {
        selectedAlertDid = did;
        selectedAlertChanges = changes;
        goTo('alert_detail');
      }}
      onagents={() => goTo('my_agents')}
      onsettings={() => goTo('settings')}
    />

  {:else if step === 'settings'}
    <SettingsScreen onback={() => goTo('home')} />

  {:else if step === 'my_agents'}
    <MyAgentsScreen onback={() => goTo('home')} onapprove={() => goTo('agent_approval')} />

  {:else if step === 'agent_approval'}
    <AgentClaimApprovalScreen onback={() => goTo('my_agents')} ondone={() => goTo('my_agents')} />

  {:else if step === 'identity_detail'}
    <DIDDocumentScreen
      didDoc={selectedDidDoc ? normalizePlcDocToW3c(selectedDidDoc) : {}}
      onback={() => goTo('home')}
      onmigrate={selectedDeviceKeyIsRoot === true
        ? () => {
            migrationDid = selectedDid ?? '';
            goTo('migration_start');
          }
        : undefined}
    />

  {:else if step === 'migration_start'}
    <MigrationStartScreen
      did={migrationDid}
      onnext={({ destPdsUrl, email, inviteCode }) => {
        migrationDestPds = destPdsUrl;
        migrationEmail = email;
        migrationInviteCode = inviteCode;
        goTo('migration_source_auth');
      }}
      onback={() => goTo('identity_detail')}
    />

  {:else if step === 'migration_source_auth'}
    <MigrationSourceAuthScreen
      did={migrationDid}
      onnext={() => goTo('migration_progress')}
      onback={() => goTo('migration_start')}
    />

  {:else if step === 'migration_progress'}
    <MigrationProgressScreen
      did={migrationDid}
      email={migrationEmail}
      inviteCode={migrationInviteCode}
      onnext={() => goTo('migration_review')}
      onerror={() => {
        // Stay on the progress screen — it surfaces the error inline and offers Retry itself,
        // rather than rewinding. The parent has nothing to do on a per-leg failure.
      }}
    />

  {:else if step === 'migration_review'}
    <MigrationReviewScreen
      did={migrationDid}
      onnext={(result) => {
        migrationResult = result;
        goTo('migration_success');
      }}
      oncancel={() => goTo('identity_detail')}
    />

  {:else if step === 'migration_success'}
    <MigrationSuccessScreen
      result={migrationResult!}
      destPdsLabel={migrationDestPds}
      ondone={() => goTo('home')}
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

  {:else if step === 'alert_detail'}
    <AlertDetailScreen
      did={selectedAlertDid ?? ''}
      changes={selectedAlertChanges}
      onback={() => goTo('home')}
      onoverride={(cid, createdAt) => {
        selectedRecoveryCid = cid;
        selectedRecoveryCreatedAt = createdAt;
        goTo('recovery_override');
      }}
    />

  {:else if step === 'recovery_override'}
    <RecoveryOverrideScreen
      did={selectedAlertDid ?? ''}
      operationCid={selectedRecoveryCid ?? ''}
      createdAt={selectedRecoveryCreatedAt ?? ''}
      onback={() => goTo('alert_detail')}
      onsuccess={() => goTo('home')}
    />

  {:else if step === 'auth_failed'}
    <OnboardingShell title="Authentication failed" subtitle="We couldn't complete authentication. Please try again.">
      {#if authError}
        <span class="code">Error code: {authError.code}</span>
      {/if}
      <Button onclick={() => { authError = null; goTo('authenticating'); }}>Try again</Button>
      <Button variant="secondary" onclick={() => { authError = null; goTo('mode_select'); }}>Start over</Button>
    </OnboardingShell>
  {/if}
</div>

<style>
  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .code {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
  }
</style>
