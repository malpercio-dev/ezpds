<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import { onMount, onDestroy } from 'svelte';
  import ModeSelectScreen from '$lib/components/onboarding/ModeSelectScreen.svelte';
  import IdentityMethodScreen from '$lib/components/onboarding/IdentityMethodScreen.svelte';
  import DidWebPathScreen from '$lib/components/onboarding/DidWebPathScreen.svelte';
  import DidWebDomainScreen from '$lib/components/onboarding/DidWebDomainScreen.svelte';
  import DidWebCeremonyScreen from '$lib/components/onboarding/DidWebCeremonyScreen.svelte';
  import DidWebMigrationReviewScreen from '$lib/components/onboarding/DidWebMigrationReviewScreen.svelte';
  import DidWebHostingScreen from '$lib/components/onboarding/DidWebHostingScreen.svelte';
  import { didWebFromDomain, type DidWebHosting } from '$lib/did-web';
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
  import RecoverStartScreen from '$lib/components/onboarding/RecoverStartScreen.svelte';
  import RecoverSharesScreen from '$lib/components/onboarding/RecoverSharesScreen.svelte';
  import RecoverEscrowScreen from '$lib/components/onboarding/RecoverEscrowScreen.svelte';
  import RecoverVerifyScreen from '$lib/components/onboarding/RecoverVerifyScreen.svelte';
  import RecoverEpilogueScreen from '$lib/components/onboarding/RecoverEpilogueScreen.svelte';
  import MigrationStartScreen from '$lib/components/onboarding/MigrationStartScreen.svelte';
  import MigrationSourceAuthScreen from '$lib/components/onboarding/MigrationSourceAuthScreen.svelte';
  import MigrationProgressScreen from '$lib/components/onboarding/MigrationProgressScreen.svelte';
  import MigrationReviewScreen from '$lib/components/onboarding/MigrationReviewScreen.svelte';
  import MigrationSuccessScreen from '$lib/components/onboarding/MigrationSuccessScreen.svelte';
  import DIDDocumentScreen from '$lib/components/home/DIDDocumentScreen.svelte';
  import ChangeHandleScreen from '$lib/components/home/ChangeHandleScreen.svelte';
  import RotateRepoKeyScreen from '$lib/components/home/RotateRepoKeyScreen.svelte';
  import RekeyReviewScreen from '$lib/components/home/RekeyReviewScreen.svelte';
  import AppPasswordsScreen from '$lib/components/home/AppPasswordsScreen.svelte';
  import AlertDetailScreen from '$lib/components/home/AlertDetailScreen.svelte';
  import RecoveryOverrideScreen from '$lib/components/home/RecoveryOverrideScreen.svelte';
  import MyAgentsScreen from '$lib/components/home/MyAgentsScreen.svelte';
  import AgentClaimApprovalScreen from '$lib/components/home/AgentClaimApprovalScreen.svelte';
  import SettingsScreen from '$lib/components/home/SettingsScreen.svelte';
  import RemoveIdentityScreen from '$lib/components/home/RemoveIdentityScreen.svelte';
  import { createAccount, confirmShareBackup, confirmRekey, confirmRecoveryBackup, getPendingRecoveryEpilogue, registerCreatedIdentity, listIdentities, listPendingRemovals, getStoredDidDoc, checkIdentityStatus, isCodedError, type CreateAccountError, type OAuthError, type IdentityInfo, type VerifiedClaimOp, type ClaimResult, type RekeyResult, type UnauthorizedChange, type CollectedShare } from '$lib/ipc';
  import { authenticateBiometric } from '$lib/biometric';
  import { normalizePlcDocToW3c, extractHandle } from '$lib/did-doc-utils';
  import IdentityListHome from '$lib/components/home/IdentityListHome.svelte';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  // ── Onboarding step type ─────────────────────────────────────────────────
  //
  // There is no dedicated 'error' step: when an error occurs (e.g. EXPIRED_CODE,
  // EMAIL_TAKEN), the app rewinds to the relevant screen and shows an inline error
  // below the input field, so the user can correct it without an extra modal.

  type OnboardingStep =
    | 'mode_select'
    | 'identity_method'
    | 'did_web_path'
    | 'did_web_domain'
    | 'did_web_existing'
    | 'did_web_ceremony'
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
    | 'change_handle'
    | 'rotate_repo_key'
    | 'rekey_review'
    | 'rekey_backup'
    | 'rekey_success'
    | 'app_passwords'
    | 'remove_identity'
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
    | 'migration_hosting'
    | 'migration_review'
    | 'migration_success'
    | 'recover_start'
    | 'recover_shares'
    | 'recover_escrow'
    | 'recover_verify'
    | 'recover_epilogue'
    | 'recover_backup'
    | 'recover_success';

  // ── State ────────────────────────────────────────────────────────────────

  let step = $state<OnboardingStep>('mode_select');
  // True once the user has reached `mode_select` from an existing wallet (via the
  // home screen's "add" action), so the entry screen can offer a Back-to-home
  // affordance. Stays false on first launch, where there is no home to return to.
  let cameFromHome = $state(false);
  let form = $state({ claimCode: '', email: '', handle: '', password: '', did: '', share3: '', share3Words: '', registeredHandle: '', handleOrDid: '' });
  let didWebHosting = $state<DidWebHosting>('self');
  let migrationHostingChosen = $state(false);
  let identityMethod = $state<'plc' | 'web'>('plc');
  let didWebDomain = $state('');

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

  let selectedDid = $state<string | null>(null);
  let selectedDidDoc = $state<Record<string, unknown> | null>(null);
  let selectedDeviceKeyIsRoot = $state<boolean | null>(null);

  let selectedAlertDid = $state<string | null>(null);
  let selectedAlertChanges = $state<UnauthorizedChange[]>([]);

  // ── Re-key (old-model upgrade) flow state ─────────────────────────────────
  // The re-key runs against an existing identity; the review screen produces the new Share 3,
  // which the backup screen then walks the user through saving before the staging teardown.
  let rekeyDid = $state<string | null>(null);
  let rekeyShare3 = $state('');
  let rekeyShare3Words = $state('');
  let rekeyBackupError = $state<string | null>(null);

  let selectedRecoveryCid = $state<string | null>(null);
  let selectedRecoveryCreatedAt = $state<string | null>(null);

  // ── Recovery flow state ──────────────────────────────────────────────────
  let recoveryCollected = $state<CollectedShare[]>([]);
  // The NEW Share 3 produced by the rotation epilogue, for the backup walkthrough.
  let recoveryShare3 = $state('');
  let recoveryShare3Words = $state('');
  // True when the epilogue screen was entered from launch-time resume (an app
  // restart interrupted a prior recovery's share rotation).
  let recoveryResuming = $state(false);
  let recoveryBackupConfirmError = $state<string | null>(null);

  // ── Migration flow state ──────────────────────────────────────────────────
  // Each migration screen owns its own transient error/progress display; the page only threads
  // the values a later screen consumes (destination + email for the flow, the result for success).
  let migrationDid = $state('');
  let migrationEmail = $state('');
  let migrationInviteCode = $state<string | undefined>(undefined);
  let migrationDestPds = $state('');
  // Resolved source identity (from prepareMigration) for the source-auth screen's prefill + copy.
  let migrationSourceHandle = $state('');
  let migrationSourcePds = $state('');
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
    // Resume a stranded removal first. If a prior removal deleted the PDS account but was
    // interrupted before the tombstone + local wipe finished (e.g. iOS killed the app
    // mid-flow), the identity still exists locally but its account is gone. Route straight
    // to the removal screen, which resumes the tombstone-only retry rather than the request
    // flow — the latter would fail against the already-deleted account.
    let resumingRemoval = false;
    try {
      const pending = await listPendingRemovals();
      if (pending.length > 0) {
        const did = pending[0];
        selectedDid = did;
        try {
          selectedDidDoc = await getStoredDidDoc(did);
        } catch {
          // The DID doc may already be gone (a wipe that outran its marker clear); the
          // removal screen still resumes correctly from the marker alone.
          selectedDidDoc = null;
        }
        selectedDeviceKeyIsRoot = null;
        step = 'remove_identity';
        resumingRemoval = true;
      }
    } catch (e) {
      console.warn('listPendingRemovals failed on mount:', e);
    }

    // Resume an interrupted recovery share-rotation epilogue next. The epilogue is
    // mandatory — the lost device's share world must be voided — so a restart lands
    // back on the epilogue screen, which re-runs only the incomplete steps.
    let resumingRecovery = false;
    if (!resumingRemoval) {
      try {
        const pendingEpilogue = await getPendingRecoveryEpilogue();
        if (pendingEpilogue) {
          recoveryResuming = true;
          step = 'recover_epilogue';
          resumingRecovery = true;
        }
      } catch (e) {
        console.warn('getPendingRecoveryEpilogue failed on mount:', e);
      }
    }

    // If the user has claimed identities, skip to home (unless we're resuming a removal
    // or a recovery epilogue).
    if (!resumingRemoval && !resumingRecovery) {
      try {
        const identities = await listIdentities();
        if (identities.length > 0) {
          step = 'home';
        }
      } catch (e) {
        console.error('listIdentities failed on mount:', e);
        // First launch (empty Keychain) or Keychain error — continue to mode_select
      }
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
      step = identityMethod === 'web' ? 'did_web_ceremony' : 'did_ceremony';
    } catch (raw: unknown) {
      // Guard against non-CreateAccountError shapes (e.g. JS runtime errors).
      if (isCodedError(raw)) {
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
  // OAuth flow never writes to it — so without this call the home screen would show
  // "No identities yet" after login.
  //
  // Error-handling strategy: best-effort. If registration fails we log and
  // continue — the user keeps their identity and can refresh the card later.
  // (Strict alternative: surface the error and let the user retry before
  // advancing — see the accompanying notes.)
  let backupConfirmError = $state<string | null>(null);

  async function confirmBackupAndContinue() {
    backupConfirmError = null;
    // The teardown destroys the last local copy of the recovery seed material, so it
    // is gated on user presence like every other irreversible operation.
    try {
      await authenticateBiometric('Confirm you have saved your recovery share');
    } catch (e) {
      console.warn('Backup confirmation biometric gate rejected:', e);
      backupConfirmError = 'Authentication was cancelled. Try again to finish your backup.';
      return;
    }
    // Fail closed: advancing without a successful teardown would either violate the
    // backup invariant (SHARE_NOT_STORED — Share 1 never reached its durable slot) or
    // report completion while sensitive staging material is still retained.
    try {
      await confirmShareBackup(form.did);
    } catch (e) {
      console.error('Ceremony staging teardown failed:', e);
      backupConfirmError =
        isCodedError(e) && e.code === 'SHARE_NOT_STORED'
          ? 'Your automatic iCloud share is not saved yet. Try again — if this keeps happening, reopen the app before continuing.'
          : 'Could not finalize the backup. Check device storage and try again.';
      return;
    }
    step = 'handle_registration';
  }

  // Mirror of confirmBackupAndContinue for the re-key epilogue: the biometric-gated teardown of
  // the per-DID re-key staging slot, fail-closed on a non-durable Share 1 (SHARE_NOT_STORED).
  async function confirmRekeyBackup() {
    rekeyBackupError = null;
    try {
      await authenticateBiometric('Confirm you have saved your recovery share');
    } catch (e) {
      console.warn('Re-key backup confirmation biometric gate rejected:', e);
      rekeyBackupError = 'Authentication was cancelled. Try again to finish your backup.';
      return;
    }
    try {
      await confirmRekey(rekeyDid ?? '');
    } catch (e) {
      console.error('Re-key staging teardown failed:', e);
      rekeyBackupError =
        isCodedError(e) && e.code === 'SHARE_NOT_STORED'
          ? 'Your automatic iCloud share is not saved yet. Try again — if this keeps happening, reopen the app before continuing.'
          : 'Could not finalize the backup. Check device storage and try again.';
      return;
    }
    step = 'rekey_success';
  }

  // ── Finish the recovery flow ──────────────────────────────────────────────
  //
  // Mirrors confirmBackupAndContinue: the teardown destroys the last transient home
  // of the NEW recovery seed material, so it is biometric-gated and fails closed.
  async function confirmRecoveryBackupAndFinish() {
    recoveryBackupConfirmError = null;
    try {
      await authenticateBiometric('Confirm you have saved your new recovery share');
    } catch (e) {
      console.warn('Recovery backup biometric gate rejected:', e);
      recoveryBackupConfirmError = 'Authentication was cancelled. Try again to finish your backup.';
      return;
    }
    try {
      await confirmRecoveryBackup();
    } catch (e) {
      console.error('Recovery epilogue teardown failed:', e);
      recoveryBackupConfirmError =
        isCodedError(e) && e.code === 'SHARE_NOT_STORED'
          ? 'Your automatic iCloud share is not saved yet. Try again — if this keeps happening, reopen the app before continuing.'
          : 'Could not finalize the backup. Check device storage and try again.';
      return;
    }
    step = 'recover_success';
  }

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
      oncreate={() => goTo('identity_method')}
      onimport={() => goTo('identity_input')}
      onrecover={() => goTo('recover_start')}
      onback={cameFromHome ? () => goTo('home') : undefined}
    />
  {:else if step === 'identity_method'}
    <IdentityMethodScreen
      onplc={() => { identityMethod = 'plc'; goTo('pds_config'); }}
      onweb={() => { identityMethod = 'web'; goTo('did_web_path'); }}
      onback={() => goTo('mode_select')}
    />
  {:else if step === 'did_web_path'}
    <DidWebPathScreen
      onselect={(origin, hosting) => {
        didWebHosting = hosting;
        migrationHostingChosen = origin === 'existing';
        // Existing did:web identities enter the method-agnostic migration flow. New identities
        // continue through account provisioning; the ceremony uses these levers after the PDS
        // has issued its reserved repo key.
        goTo(origin === 'existing' ? 'did_web_existing' : 'did_web_domain');
      }}
      onback={() => goTo('identity_method')}
    />
  {:else if step === 'did_web_domain'}
    <DidWebDomainScreen
      bind:value={didWebDomain}
      onnext={() => goTo('pds_config')}
      onback={() => goTo('did_web_path')}
    />
  {:else if step === 'did_web_existing'}
    <DidWebDomainScreen
      bind:value={didWebDomain}
      onnext={() => {
        migrationDid = didWebFromDomain(didWebDomain);
        goTo('migration_start');
      }}
      onback={() => goTo('did_web_path')}
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
      did={identityInfo!.did}
      handle={identityInfo!.handle}
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
      onsuccess={(result) => { form.did = result.did; form.share3 = result.share3; form.share3Words = result.share3Words; step = 'did_success'; }}
    />
  {:else if step === 'did_web_ceremony'}
    <DidWebCeremonyScreen
      domain={didWebDomain}
      handle={form.handle}
      password={form.password}
      hosting={didWebHosting}
      onsuccess={(result) => { form.did = result.did; form.share3 = result.share3; form.share3Words = result.share3Words; step = 'did_success'; }}
      onback={() => goTo('password')}
    />
  {:else if step === 'did_success'}
    <DIDSuccessScreen
      did={form.did}
      oncontinue={() => { step = identityMethod === 'web' ? 'handle_registration' : 'shamir_backup'; }}
    />
  {:else if step === 'shamir_backup'}
    <ShamirBackupScreen
      share3={form.share3}
      share3Words={form.share3Words}
      confirmError={backupConfirmError}
      oncomplete={confirmBackupAndContinue}
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
      handle={form.registeredHandle}
      onresolved={() => goTo('home')}
      onfailed={(err) => {
        authError = err;
        goTo('auth_failed');
      }}
    />

  {:else if step === 'home'}
    <IdentityListHome
      onadd={() => { cameFromHome = true; goTo('mode_select'); }}
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
      onsettings={() => goTo('settings')}
      onrekey={(did) => {
        rekeyDid = did;
        rekeyBackupError = null;
        goTo('rekey_review');
      }}
    />

  {:else if step === 'settings'}
    <SettingsScreen onback={() => goTo('home')} />

  {:else if step === 'my_agents'}
    <MyAgentsScreen
      did={selectedDid ?? ''}
      onback={() => goTo('identity_detail')}
      onapprove={() => goTo('agent_approval')}
    />

  {:else if step === 'agent_approval'}
    <AgentClaimApprovalScreen
      did={selectedDid ?? ''}
      onback={() => goTo('my_agents')}
      ondone={() => goTo('my_agents')}
    />

  {:else if step === 'identity_detail'}
    <DIDDocumentScreen
      didDoc={selectedDidDoc ? normalizePlcDocToW3c(selectedDidDoc) : {}}
      onback={() => goTo('home')}
      onchangehandle={selectedDeviceKeyIsRoot === true && selectedDid?.startsWith('did:plc:')
        ? () => goTo('change_handle')
        : undefined}
      onrotatekey={selectedDeviceKeyIsRoot === true && selectedDid?.startsWith('did:plc:')
        ? () => goTo('rotate_repo_key')
        : undefined}
      onapppasswords={() => goTo('app_passwords')}
      onagents={() => goTo('my_agents')}
      onmigrate={selectedDeviceKeyIsRoot === true
        ? () => {
            migrationDid = selectedDid ?? '';
            didWebHosting = 'self';
            migrationHostingChosen = false;
            goTo('migration_start');
          }
        : undefined}
      onremove={selectedDid?.startsWith('did:plc:')
        ? () => goTo('remove_identity')
        : undefined}
    />

  {:else if step === 'remove_identity'}
    <RemoveIdentityScreen
      did={selectedDid ?? ''}
      handle={selectedDidDoc ? (extractHandle(selectedDidDoc) ?? undefined) : undefined}
      onback={() => goTo('identity_detail')}
      oncomplete={(wasLast) => {
        selectedDid = null;
        selectedDidDoc = null;
        selectedDeviceKeyIsRoot = null;
        goTo(wasLast ? 'mode_select' : 'home');
      }}
    />

  {:else if step === 'change_handle'}
    <ChangeHandleScreen
      did={selectedDid ?? ''}
      currentHandle={selectedDidDoc ? extractHandle(selectedDidDoc) : null}
      onback={() => goTo('identity_detail')}
      ondone={() => goTo('home')}
    />

  {:else if step === 'rotate_repo_key'}
    <RotateRepoKeyScreen
      did={selectedDid ?? ''}
      onback={() => goTo('identity_detail')}
      ondone={() => goTo('home')}
    />

  {:else if step === 'rekey_review'}
    <RekeyReviewScreen
      did={rekeyDid ?? ''}
      onback={() => goTo('home')}
      ondone={(result: RekeyResult) => {
        rekeyShare3 = result.share3;
        rekeyShare3Words = result.share3Words;
        goTo('rekey_backup');
      }}
    />

  {:else if step === 'rekey_backup'}
    <ShamirBackupScreen
      share3={rekeyShare3}
      share3Words={rekeyShare3Words}
      confirmError={rekeyBackupError}
      oncomplete={confirmRekeyBackup}
    />

  {:else if step === 'rekey_success'}
    <OnboardingShell
      tone="signet"
      title="Recovery key added"
      subtitle="Your identity now has a recovery key, and your new shares are safely backed up. Nothing you rely on today has changed."
    >
      {#snippet icon()}
        <SealEmblem>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
        </SealEmblem>
      {/snippet}
      <Button onclick={() => goTo('home')}>Done</Button>
    </OnboardingShell>

  {:else if step === 'app_passwords'}
    <AppPasswordsScreen did={selectedDid ?? ''} onback={() => goTo('identity_detail')} />

  {:else if step === 'migration_start'}
    <MigrationStartScreen
      did={migrationDid}
      onnext={({ destPdsUrl, email, inviteCode, sourceHandle, sourcePdsUrl }) => {
        migrationDestPds = destPdsUrl;
        migrationEmail = email;
        migrationInviteCode = inviteCode;
        migrationSourceHandle = sourceHandle;
        migrationSourcePds = sourcePdsUrl;
        goTo('migration_source_auth');
      }}
      onback={() => goTo('identity_detail')}
    />

  {:else if step === 'migration_source_auth'}
    <MigrationSourceAuthScreen
      did={migrationDid}
      handle={migrationSourceHandle}
      pdsUrl={migrationSourcePds}
      onnext={() => goTo('migration_progress')}
      onback={() => goTo('migration_start')}
    />

  {:else if step === 'migration_progress'}
    <MigrationProgressScreen
      did={migrationDid}
      email={migrationEmail}
      inviteCode={migrationInviteCode}
      onnext={() => goTo(migrationDid.startsWith('did:web:') && !migrationHostingChosen ? 'migration_hosting' : 'migration_review')}
      onerror={() => {
        // Stay on the progress screen — it surfaces the error inline and offers Retry itself,
        // rather than rewinding. The parent has nothing to do on a per-leg failure.
      }}
    />

  {:else if step === 'migration_review'}
    {#if migrationDid.startsWith('did:web:')}
      <DidWebMigrationReviewScreen
        did={migrationDid}
        hosting={didWebHosting}
        onnext={(result) => { migrationResult = result; goTo('migration_success'); }}
        oncancel={() => goTo('migration_start')}
      />
    {:else}
      <MigrationReviewScreen
        did={migrationDid}
        onnext={(result) => {
          migrationResult = result;
          goTo('migration_success');
        }}
        oncancel={() => goTo('identity_detail')}
      />
    {/if}

  {:else if step === 'migration_hosting'}
    <DidWebHostingScreen
      onselect={(hosting) => {
        didWebHosting = hosting;
        migrationHostingChosen = true;
        goTo('migration_review');
      }}
      onback={() => goTo('migration_progress')}
    />

  {:else if step === 'migration_success'}
    <MigrationSuccessScreen
      result={migrationResult!}
      destPdsLabel={migrationDestPds}
      ondone={() => goTo('home')}
    />

  {:else if step === 'recover_start'}
    <RecoverStartScreen
      bind:value={form.handleOrDid}
      onnext={(target) => {
        recoveryCollected = target.collected;
        goTo('recover_shares');
      }}
      onback={() => goTo('mode_select')}
    />

  {:else if step === 'recover_shares'}
    <RecoverSharesScreen
      bind:collected={recoveryCollected}
      onescrow={() => goTo('recover_escrow')}
      onverify={() => goTo('recover_verify')}
      onback={() => goTo('recover_start')}
    />

  {:else if step === 'recover_escrow'}
    <RecoverEscrowScreen
      onreleased={(share) => {
        recoveryCollected = [...recoveryCollected.filter((s) => s.index !== share.index), share];
        goTo('recover_shares');
      }}
      onback={() => goTo('recover_shares')}
    />

  {:else if step === 'recover_verify'}
    <RecoverVerifyScreen
      onanchored={() => {
        recoveryResuming = false;
        goTo('recover_epilogue');
      }}
      onback={() => goTo('recover_shares')}
    />

  {:else if step === 'recover_epilogue'}
    <RecoverEpilogueScreen
      resume={recoveryResuming}
      oncomplete={(result) => {
        recoveryShare3 = result.share3;
        recoveryShare3Words = result.share3Words;
        goTo('recover_backup');
      }}
    />

  {:else if step === 'recover_backup'}
    <ShamirBackupScreen
      share3={recoveryShare3}
      share3Words={recoveryShare3Words}
      confirmError={recoveryBackupConfirmError}
      oncomplete={confirmRecoveryBackupAndFinish}
    />

  {:else if step === 'recover_success'}
    <OnboardingShell
      tone="signet"
      title="Identity recovered"
      subtitle="This device now holds your identity's key. Your old backup shares are void; the new set is in place."
    >
      {#snippet icon()}
        <SealEmblem>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 11.5 2 2 4-4" /></svg>
        </SealEmblem>
      {/snippet}
      <Button onclick={() => goTo('home')}>Go to my identities</Button>
    </OnboardingShell>

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
    /* A fixed viewport frame padded clear of the OS chrome. dvh (not vh) tracks the
       real visible height on iOS; overflow:hidden keeps the frame itself from
       scrolling — each screen owns its own scroll within the safe area. The 100vh
       declared first is the fallback for iOS < 16 (deployment floor is iOS 13),
       where dvh is unsupported and would otherwise leave the frame with no height. */
    height: 100vh;
    height: 100dvh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    padding-top: var(--safe-top);
    padding-right: var(--safe-right);
    padding-bottom: var(--safe-bottom);
    padding-left: var(--safe-left);
  }

  .code {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
  }
</style>
