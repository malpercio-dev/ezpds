<script lang="ts">
  import {
    detectMigrationPath,
    prepareDisasterRecovery,
    getRepoBackupStatus,
    isCodedError,
    type PreparedRecovery,
  } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    did,
    onnext,
    onback,
  }: {
    did: string;
    onnext: (result: {
      destPdsUrl: string;
      email: string;
      inviteCode: string | undefined;
      prepared: PreparedRecovery;
    }) => void;
    onback: () => void;
  } = $props();

  let destPdsUrl = $state('');
  let email = $state('');
  let inviteCode = $state('');
  // The offline-handle-domain escape hatch: when the dead PDS served the handle's
  // domain, the old handle won't resolve — the user supplies a destination-served one.
  let handleOverride = $state('');

  let checking = $state(false);
  let error = $state<string | null>(null);
  // Terminal: the wallet holds no rotation key for this DID — recovery is impossible
  // from this device (there is no interop fallback with a dead source).
  let terminalMessage = $state<string | null>(null);
  let retryMessage = $state<string | null>(null);
  // Whether a local/iCloud repo snapshot exists — the thing the rebuild imports from.
  let backupSummary = $state<string | null>(null);
  let backupMissing = $state(false);

  // Surface the backup's presence up front: failing at the import step, four legs in,
  // is a far worse place to learn there is nothing to rebuild from.
  (async () => {
    try {
      const status = await getRepoBackupStatus(did);
      if (status.rev) {
        const mb = (status.sizeBytes / (1024 * 1024)).toFixed(1);
        backupSummary = `Post backup found (${mb} MB${status.lastBackupAt ? `, last backed up ${status.lastBackupAt.slice(0, 10)}` : ''}).`;
      } else {
        backupMissing = true;
      }
    } catch {
      // Status probe is best-effort — the import step still fails closed.
    }
  })();

  function describePrepareError(raw: unknown): string {
    if (isCodedError(raw)) {
      switch (raw.code) {
        case 'DESTINATION_UNREACHABLE':
          return "Couldn't reach the destination PDS. Check the URL and try again.";
        case 'RATE_LIMITED':
          return 'The PLC directory is rate-limiting requests. Wait a moment and try again.';
        case 'PLC_DIRECTORY_ERROR':
          return 'The PLC directory rejected the request. Please try again.';
        case 'INVALID_AUDIT_LOG':
          return "This identity's PLC record could not be read.";
        case 'NETWORK_ERROR':
          return 'Network error. Check your connection and try again.';
        default:
          return `Couldn't prepare the recovery (${raw.code}). Please try again.`;
      }
    }
    return "Couldn't reach the server. Check your connection.";
  }

  async function submit() {
    if (!destPdsUrl.trim() || !email.trim()) return;

    checking = true;
    error = null;
    terminalMessage = null;
    retryMessage = null;

    try {
      // The same authorization check the migration flow runs: the wallet must hold a
      // current rotation key to device-key-sign the recovery's PLC ops.
      try {
        const decision = await detectMigrationPath(did);
        if (decision.path === 'interop') {
          terminalMessage =
            "This wallet doesn't hold a rotation key for this identity, so it can't rebuild the account.";
          return;
        }
        if (decision.path === 'cannot_determine') {
          retryMessage =
            "Couldn't verify this identity's keys — check your connection and try again.";
          return;
        }
      } catch (raw: unknown) {
        console.error('Recovery path detection failed:', raw);
        error = describePrepareError(raw);
        return;
      }

      let prepared: PreparedRecovery;
      try {
        prepared = await prepareDisasterRecovery(
          did,
          destPdsUrl.trim(),
          handleOverride.trim() || undefined,
        );
      } catch (raw: unknown) {
        console.error('Recovery preparation failed:', raw);
        error = describePrepareError(raw);
        return;
      }

      onnext({
        destPdsUrl: destPdsUrl.trim(),
        email: email.trim(),
        inviteCode: inviteCode.trim() || undefined,
        prepared,
      });
    } finally {
      checking = false;
    }
  }
</script>

<OnboardingShell
  title="Rebuild from backup"
  subtitle="Your old PDS doesn't need to cooperate — or even exist. This rebuilds your account on a new PDS from your backed-up posts and media, using the keys this wallet holds."
  onback={terminalMessage ? undefined : onback}
>
  {#if terminalMessage}
    <div class="notice notice--terminal" role="alert">
      <p class="notice-text">{terminalMessage}</p>
    </div>
    <Button variant="secondary" onclick={onback}>Back</Button>
  {:else}
    {#if backupSummary}
      <div class="notice notice--info">
        <p class="notice-text">{backupSummary}</p>
      </div>
    {:else if backupMissing}
      <div class="notice notice--retry" role="alert">
        <p class="notice-text">
          No post backup was found for this identity. Without one, the rebuild has nothing to
          restore — only continue if you know a backup exists on this device's iCloud Drive.
        </p>
      </div>
    {/if}

    <TextField
      bind:value={destPdsUrl}
      type="url"
      placeholder="https://new-pds.example.com"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination PDS URL"
      disabled={checking}
      error={error ?? undefined}
    />
    <TextField
      bind:value={email}
      type="email"
      placeholder="you@example.com"
      autocomplete="email"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination email"
      disabled={checking}
    />
    <TextField
      bind:value={inviteCode}
      type="text"
      placeholder="Invite code (optional)"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Destination invite code (optional)"
      disabled={checking}
    />
    <TextField
      bind:value={handleOverride}
      type="text"
      placeholder="New handle (optional)"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="New handle (optional)"
      disabled={checking}
    />
    <p class="hint">
      If your old PDS served your handle's domain, the old handle won't resolve any more — enter a
      handle the new PDS serves (for example, yourname.new-pds.example.com). Leave blank to keep
      your current handle.
    </p>

    {#if retryMessage}
      <div class="notice notice--retry" role="alert">
        <p class="notice-text">{retryMessage}</p>
      </div>
    {/if}

    <Button disabled={checking || !destPdsUrl.trim() || !email.trim()} onclick={submit}>
      {checking ? 'Checking…' : retryMessage ? 'Retry' : 'Continue'}
    </Button>
    <Button variant="secondary" onclick={onback} disabled={checking}>Back</Button>
  {/if}
</OnboardingShell>

<style>
  .notice {
    width: 100%;
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
  }
  .notice--terminal {
    background: var(--color-surface-sunk);
  }
  .notice--retry {
    background: var(--color-warning-surface);
  }
  .notice--info {
    background: var(--color-surface-sunk);
  }
  .notice-text {
    font-size: var(--text-label);
    margin: 0;
    line-height: 1.4;
  }
  .notice--terminal .notice-text,
  .notice--info .notice-text {
    color: var(--color-muted);
  }
  .notice--retry .notice-text {
    color: var(--color-warning);
  }
  .hint {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.4;
  }
</style>
