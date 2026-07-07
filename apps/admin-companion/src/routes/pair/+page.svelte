<script lang="ts">
  import { tick } from 'svelte';
  import { goto } from '$app/navigation';
  import {
    pairDevice,
    scanQrCode,
    cancelQrScan,
    parsePairingPayload,
    type RelayClientError,
  } from '$lib/ipc';
  import { describeRelayError } from '$lib/errors';
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';

  // Pairing claims a single-use code the operator minted on the relay (master token)
  // and rendered as a QR. On a real iPhone the camera fills these fields from the QR;
  // on the simulator (no camera) the operator types them. Either way the Rust core
  // self-signs `POST /v1/admin/devices`. The nickname is the operator's local name for
  // the server and is always required.
  let relayUrl = $state('');
  let pairingCode = $state('');
  let label = $state('Operator iPhone');
  let nickname = $state('');
  let nicknameError = $state<string | undefined>(undefined);

  let scanning = $state(false);
  let pairing = $state(false);
  let scanHint = $state<string | undefined>(undefined);
  let pairError = $state<string | undefined>(undefined);

  // A monotonic token that supersedes an in-flight scan: Cancel (or a newer scan) bumps
  // it, so a late-settling scanQrCode() can't overwrite fields or collapse a newer overlay,
  // and a cancelled scan never surfaces the "camera unavailable" hint.
  let scanToken = 0;

  // Refs for the focus handoff into/out of scan mode (keyboard + VoiceOver).
  let overlayEl = $state<HTMLDivElement | undefined>();
  let triggerEl = $state<HTMLDivElement | undefined>();

  const canSubmit = $derived(
    relayUrl.trim().length > 0 && pairingCode.trim().length > 0 && nickname.trim().length > 0 && !pairing,
  );

  // Scan mode makes the WebView see-through so the *windowed* camera — which
  // tauri-plugin-barcode-scanner renders BEHIND the web layer — is actually visible.
  // base.css paints an opaque body ground, so drop it to transparent for the duration;
  // the overlay's opaque bars carry the chrome and the middle strip is the live camera.
  $effect(() => {
    if (typeof document === 'undefined') return;
    document.body.classList.toggle('scanning', scanning);
    return () => document.body.classList.remove('scanning');
  });

  // Focus handoff: into Cancel when scan mode opens, back to the trigger when it closes.
  // Guarded so it fires only on an actual open/close transition, not initial mount.
  let wasScanning = false;
  $effect(() => {
    const open = scanning;
    if (open === wasScanning) return;
    wasScanning = open;
    void tick().then(() => {
      const host = open ? overlayEl : triggerEl;
      host?.querySelector<HTMLButtonElement>('button')?.focus();
    });
  });

  async function scan() {
    const token = ++scanToken;
    scanning = true;
    scanHint = undefined;
    pairError = undefined;
    try {
      const payload = parsePairingPayload(await scanQrCode());
      // A newer scan or a Cancel superseded this one — don't touch shared state.
      if (token !== scanToken) return;
      if (payload) {
        relayUrl = payload.relayUrl;
        pairingCode = payload.pairingCode;
      } else {
        scanHint = 'That QR did not carry a relay URL and pairing code. Enter them below.';
      }
    } catch {
      // A cancelled/superseded scan isn't a real failure — leave the current UI alone.
      if (token !== scanToken) return;
      // No camera (simulator/desktop) or permission denied — manual entry is the path.
      scanHint = 'Camera scanning is unavailable here. Enter the relay URL and code below.';
    } finally {
      // Only the scan that still owns the token may clear the shared scanning flag.
      if (token === scanToken) scanning = false;
    }
  }

  async function cancelScan() {
    // Supersede the in-flight scan — its result/error/finally become no-ops via the token —
    // and close the overlay immediately for a responsive Cancel.
    scanToken++;
    scanning = false;
    try {
      await cancelQrScan();
    } catch {
      // best-effort — tearing the overlay down is what matters
    }
  }

  async function submit() {
    // The footer action Button calls submit() directly, bypassing the form's native
    // `type="url"`/required validation — so re-check the inputs here before any IPC.
    const url = relayUrl.trim();
    const code = pairingCode.trim();
    const nick = nickname.trim();

    // Validate nickname: required, no empty string.
    if (nick.length === 0) {
      nicknameError = "Give this server a name — it's how you'll tell environments apart.";
      return;
    }

    if (!url || !code || pairing) return;

    // Mirror the form's URL constraint: a bare host (no scheme) can't be paired against.
    try {
      new URL(url);
    } catch {
      pairError = "That relay URL isn't a valid address — include https://.";
      return;
    }

    pairing = true;
    pairError = undefined;
    nicknameError = undefined;
    try {
      await pairDevice(url, code, label.trim() || 'Operator iPhone', nick);
      await goto('/');
    } catch (e) {
      pairError = describeRelayError(e as RelayClientError);
    } finally {
      pairing = false;
    }
  }
</script>

<div class="pair-shell" class:hidden={scanning}>
  <ScreenShell prompt="pair device" title="Pair this device" onback={() => goto('/')}>
    <section class="intro">
      <p class="lede">
        Claim the single-use pairing code from the relay. Scan its QR, or enter the relay
        URL and code by hand.
      </p>
      <div bind:this={triggerEl}>
        <Button variant="secondary" loading={scanning} onclick={scan}>Scan QR code</Button>
      </div>
      {#if scanHint}
        <p class="hint" role="status">
          <StatusChip status="info" label="manual entry" />
          <span>{scanHint}</span>
        </p>
      {/if}
    </section>

    <form
      class="form"
      onsubmit={(e) => {
        e.preventDefault();
        if (canSubmit) submit();
      }}
    >
      <TextField
        label="Relay URL"
        bind:value={relayUrl}
        placeholder="https://relay.example"
        type="url"
        mono
        inputmode="url"
      />
      <TextField label="Pairing code" bind:value={pairingCode} placeholder="paste the code" mono />
      <TextField
        label="Nickname"
        bind:value={nickname}
        placeholder="staging"
        mono
        error={nicknameError}
      />
      <TextField label="Device label" bind:value={label} placeholder="Operator iPhone" />

      {#if pairError}
        <p class="error" role="alert">
          <StatusChip status="error" label="pairing failed" />
          <span>{pairError}</span>
        </p>
      {/if}
    </form>

    {#snippet actions()}
      <Button variant="primary" type="submit" disabled={!canSubmit} loading={pairing} onclick={submit}>
        Pair device
      </Button>
    {/snippet}
  </ScreenShell>
</div>

{#if scanning}
  <!-- Camera is a native layer BEHIND the transparent WebView; this overlay draws only
       the framing. Opaque top/bottom bars guarantee AAA text over an unknown camera image;
       the middle strip is the live camera, focused by a matte-brass viewfinder. -->
  <div
    class="scan"
    bind:this={overlayEl}
    role="dialog"
    aria-modal="true"
    aria-label="Scanning for a pairing QR code"
  >
    <div class="scan-bar scan-bar--top">
      <p class="scan-prompt">
        <span class="brand">ezpds</span><span class="caret" aria-hidden="true">▸</span>scan
      </p>
      <p class="scan-instruction" role="status">
        Point the camera at the relay's pairing QR code.
      </p>
    </div>

    <div class="scan-stage">
      <div class="reticle" aria-hidden="true">
        <span class="corner corner--tl"></span>
        <span class="corner corner--tr"></span>
        <span class="corner corner--bl"></span>
        <span class="corner corner--br"></span>
      </div>
    </div>

    <div class="scan-bar scan-bar--bottom">
      <p class="scan-status"><span class="glyph" aria-hidden="true">◌</span> scanning…</p>
      <Button variant="secondary" onclick={cancelScan}>Cancel</Button>
    </div>
  </div>
{/if}

<style>
  .pair-shell.hidden {
    display: none;
  }

  .intro {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .lede {
    margin: 0;
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }
  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
  .hint,
  .error {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    margin: 0;
    font-size: var(--text-label);
    line-height: var(--leading-body);
    color: var(--color-ink-soft);
  }

  /* ── Scan mode ──────────────────────────────────────────────────────────
     A framed viewfinder over the native camera. Opaque bars top and bottom
     (Console Slate) keep every label comfortably AAA regardless of the camera
     image; the transparent middle strip is the camera, dimmed outside the
     target square by a single-element spotlight so the brass frame reads. */
  .scan {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    display: flex;
    flex-direction: column;
    background: transparent;
    /* Console Slate at partial alpha — the spotlight scrim, tokenized. */
    --scan-scrim: color-mix(in oklab, var(--color-bg) 55%, transparent);
    animation: scan-in var(--duration-base) var(--ease-standard);
  }

  .scan-bar {
    position: relative; /* lift the bars above the reticle's spotlight scrim */
    z-index: 1;
    background: var(--color-bg);
    padding: var(--space-lg);
    padding-left: max(var(--space-lg), env(safe-area-inset-left));
    padding-right: max(var(--space-lg), env(safe-area-inset-right));
  }
  .scan-bar--top {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    padding-top: max(var(--space-xl), env(safe-area-inset-top));
    border-bottom: var(--border-hairline) solid var(--color-line);
  }
  .scan-bar--bottom {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    padding-bottom: max(var(--space-lg), env(safe-area-inset-bottom));
    border-top: var(--border-hairline) solid var(--color-line);
  }

  /* The prompt is the display moment: mono, brand gold, once — echoes ScreenShell. */
  .scan-prompt {
    margin: 0;
    font-family: var(--font-display);
    font-size: var(--text-data);
    letter-spacing: 0.02em;
    color: var(--color-ink-soft);
  }
  .scan-prompt .brand {
    color: var(--color-primary);
  }
  .scan-prompt .caret {
    margin: 0 var(--space-sm);
    color: var(--color-muted);
  }
  .scan-instruction {
    margin: 0;
    font-family: var(--font-sans);
    font-size: var(--text-body);
    line-height: var(--leading-body);
    color: var(--color-ink);
  }
  /* Activity, not a device status — filament + glyph + text, never a colored signal. */
  .scan-status {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    margin: 0;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .scan-status .glyph {
    color: var(--color-muted);
  }

  .scan-stage {
    flex: 1;
    display: grid;
    place-items: center;
    overflow: hidden; /* clip the spotlight scrim to the camera strip */
  }

  .reticle {
    position: relative;
    width: min(68vw, 300px);
    aspect-ratio: 1;
    border-radius: var(--radius-lg);
    box-shadow: 0 0 0 100vmax var(--scan-scrim);
  }
  /* Matte-brass viewfinder corners — the One Lamp for this state (the operator's
     single locus of attention); a faint slate halo keeps them legible over any camera. */
  .corner {
    position: absolute;
    width: var(--space-xl);
    height: var(--space-xl);
    border: var(--ring-width) solid var(--color-primary);
    filter: drop-shadow(0 0 3px color-mix(in oklab, var(--color-bg) 65%, transparent));
  }
  .corner--tl {
    top: 0;
    left: 0;
    border-right: none;
    border-bottom: none;
    border-top-left-radius: var(--radius-lg);
  }
  .corner--tr {
    top: 0;
    right: 0;
    border-left: none;
    border-bottom: none;
    border-top-right-radius: var(--radius-lg);
  }
  .corner--bl {
    bottom: 0;
    left: 0;
    border-right: none;
    border-top: none;
    border-bottom-left-radius: var(--radius-lg);
  }
  .corner--br {
    bottom: 0;
    right: 0;
    border-left: none;
    border-top: none;
    border-bottom-right-radius: var(--radius-lg);
  }

  @keyframes scan-in {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .scan {
      animation: none;
    }
  }

  /* Drop the opaque body ground so the windowed camera shows through the WebView. */
  :global(body.scanning) {
    background: transparent !important;
  }
</style>
