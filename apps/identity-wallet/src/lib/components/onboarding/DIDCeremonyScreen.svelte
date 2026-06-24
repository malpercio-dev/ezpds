<script lang="ts">
  import { performDIDCeremony, type DIDCeremonyError } from '$lib/ipc';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  let {
    handle,
    password,
    onsuccess,
  }: {
    handle: string;
    password: string;
    onsuccess: (result: import('$lib/ipc').DIDCeremonyResult) => void;
  } = $props();

  // The ceremony is gated on a deliberate press-and-hold of the signet, which then
  // triggers the real DID genesis. ready → (hold) → sealing → success | error.
  let phase = $state<'ready' | 'sealing' | 'error'>('ready');
  let error = $state<DIDCeremonyError | null>(null);
  let fill = $state(0); // 0..1 hold progress, drives the wax fill

  const HOLD_MS = 1500;
  let raf: number | null = null;
  let startTs: number | null = null;

  let monogram = $derived((handle.charAt(0) || '?').toUpperCase());

  function frame(now: number) {
    if (startTs === null) startTs = now;
    fill = Math.min(1, (now - startTs) / HOLD_MS);
    if (fill >= 1) {
      raf = null;
      startTs = null;
      beginCeremony();
      return;
    }
    raf = requestAnimationFrame(frame);
  }

  function holdStart() {
    if (phase !== 'ready') return;
    startTs = null;
    raf = requestAnimationFrame(frame);
  }

  function holdEnd() {
    if (phase !== 'ready' || raf === null) return;
    cancelAnimationFrame(raf);
    raf = null;
    startTs = null;
    fill = 0;
  }

  async function beginCeremony() {
    phase = 'sealing';
    fill = 1;
    // Defense-in-depth: guard against an empty password reaching the relay.
    // The PasswordScreen enforces ≥8 chars, but this makes the ceremony self-contained.
    if (!password || password.length === 0) {
      error = { code: 'DID_CREATION_FAILED', message: 'Password is required.' };
      phase = 'error';
      return;
    }
    try {
      const result = await performDIDCeremony(handle, password);
      onsuccess(result);
    } catch (raw: unknown) {
      if (
        typeof raw === 'object' &&
        raw !== null &&
        'code' in raw &&
        typeof (raw as DIDCeremonyError).code === 'string'
      ) {
        error = raw as DIDCeremonyError;
      } else {
        error = { code: 'NETWORK_ERROR', message: 'An unexpected error occurred.' };
      }
      phase = 'error';
    }
  }

  function retry() {
    error = null;
    fill = 0;
    phase = 'ready';
  }

  function errorMessage(err: DIDCeremonyError): string {
    switch (err.code) {
      case 'NO_RELAY_SIGNING_KEY':
        return "The relay hasn't been configured yet. Please try again later.";
      case 'RELAY_KEY_FETCH_FAILED':
      case 'NETWORK_ERROR':
        return "Couldn't reach the server. Check your connection.";
      case 'SIGNING_FAILED':
        return 'Device signing failed. Please try again.';
      case 'DID_CREATION_FAILED':
        return "Couldn't create your identity. Please try again.";
      case 'KEYCHAIN_ERROR':
        return "Couldn't save to your device. Please try again.";
      case 'SHARE_STORAGE_FAILED':
        return 'Your identity was created, but we couldn’t save your recovery key. Please contact support — do not retry setup.';
      case 'KEY_NOT_FOUND':
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  function canRetry(err: DIDCeremonyError): boolean {
    // SHARE_STORAGE_FAILED means the DID is already committed — retrying the full
    // ceremony will fail with DID_ALREADY_EXISTS. Only recoverable out-of-band.
    return err.code !== 'SHARE_STORAGE_FAILED';
  }
</script>

{#if phase === 'error' && error}
  <OnboardingShell title="Couldn’t seal your identity" subtitle={errorMessage(error)}>
    {#if canRetry(error)}
      <Button onclick={retry}>Try again</Button>
    {/if}
  </OnboardingShell>
{:else}
  <OnboardingShell
    tone="signet"
    title="Seal your identity"
    subtitle={phase === 'sealing'
      ? 'Sealing your identity…'
      : `Press and hold your signet to mint @${handle}. Your device key becomes the one key that controls it.`}
  >
    <div class="stage" class:sealed={phase === 'sealing'}>
      <button
        class="sealbtn"
        aria-label="Press and hold to seal your identity"
        disabled={phase !== 'ready'}
        onpointerdown={holdStart}
        onpointerup={holdEnd}
        onpointerleave={holdEnd}
        onpointercancel={holdEnd}
      >
        <span class="wax">
          <span class="goldfill" style="transform: scale({fill})"></span>
          <span class="ml">{monogram}</span>
        </span>
      </button>
      {#if phase === 'ready'}
        <p class="press">{fill > 0 ? 'Keep holding…' : 'Press and hold to seal'}</p>
      {:else}
        <Spinner size={22} label="Sealing your identity" />
      {/if}
    </div>
  </OnboardingShell>
{/if}

<style>
  .stage {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-lg);
  }

  .sealbtn {
    position: relative;
    width: 150px;
    height: 150px;
    border: none;
    background: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    touch-action: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .sealbtn:disabled {
    cursor: default;
  }
  .sealbtn::after {
    content: '';
    position: absolute;
    width: 150px;
    height: 150px;
    border-radius: var(--radius-full);
    border: 2px solid var(--color-primary);
    opacity: 0;
  }

  .wax {
    position: relative;
    width: 132px;
    height: 132px;
    border-radius: var(--radius-full);
    background: var(--color-surface-sunk);
    box-shadow: inset 0 0 0 2px oklch(0.86 0.07 80);
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    transition: box-shadow 0.45s ease;
  }
  .goldfill {
    position: absolute;
    inset: 0;
    border-radius: var(--radius-full);
    background: var(--color-primary);
    transform: scale(0);
    transform-origin: center;
    transition: transform 0.1s linear;
  }
  .ml {
    position: relative;
    z-index: 1;
    font-family: var(--font-display);
    font-size: 54px;
    line-height: 1;
    color: oklch(0.62 0.1 72);
    transition: color 0.4s ease;
  }

  .stage.sealed .wax {
    box-shadow:
      inset 0 0 0 2px oklch(0.99 0.05 80 / 0.4),
      inset 0 -4px 10px oklch(0.2 0.05 60 / 0.25);
    animation: stamp 0.5s var(--ease-standard);
  }
  .stage.sealed .ml {
    color: var(--color-on-color);
  }
  .stage.sealed .sealbtn::after {
    animation: ping 0.7s var(--ease-standard);
  }
  @keyframes stamp {
    0% { transform: scale(1.13); }
    60% { transform: scale(0.975); }
    100% { transform: scale(1); }
  }
  @keyframes ping {
    0% { transform: scale(0.92); opacity: 0.5; }
    100% { transform: scale(1.32); opacity: 0; }
  }

  .press {
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-muted);
    margin: 0;
  }
</style>
