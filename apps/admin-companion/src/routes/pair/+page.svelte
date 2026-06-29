<script lang="ts">
  import { goto } from '$app/navigation';
  import {
    pairDevice,
    scanQrCode,
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
  // on the simulator (no camera) the operator types them — the path the Phase 8 demo
  // exercises. Either way the Rust core self-signs `POST /v1/admin/devices`.
  let relayUrl = $state('');
  let pairingCode = $state('');
  let label = $state('Operator iPhone');

  let scanning = $state(false);
  let pairing = $state(false);
  let scanHint = $state<string | undefined>(undefined);
  let pairError = $state<string | undefined>(undefined);

  const canSubmit = $derived(
    relayUrl.trim().length > 0 && pairingCode.trim().length > 0 && !pairing,
  );

  async function scan() {
    scanning = true;
    scanHint = undefined;
    pairError = undefined;
    try {
      const payload = parsePairingPayload(await scanQrCode());
      if (payload) {
        relayUrl = payload.relayUrl;
        pairingCode = payload.pairingCode;
      } else {
        scanHint = 'That QR did not contain a relay URL and pairing code. Enter them below.';
      }
    } catch {
      // No camera (simulator/desktop) or permission denied — manual entry is the path.
      scanHint = 'Camera scanning is unavailable here. Enter the relay URL and code below.';
    } finally {
      scanning = false;
    }
  }

  async function submit() {
    pairing = true;
    pairError = undefined;
    try {
      await pairDevice(relayUrl.trim(), pairingCode.trim(), label.trim() || 'Operator iPhone');
      await goto('/');
    } catch (e) {
      pairError = describeRelayError(e as RelayClientError);
    } finally {
      pairing = false;
    }
  }
</script>

<ScreenShell prompt="pair device" title="Pair this device" onback={() => goto('/')}>
  <section class="intro">
    <p class="lede">
      Claim the single-use pairing code from the relay. Scan its QR, or enter the relay
      URL and code by hand.
    </p>
    <Button variant="secondary" loading={scanning} onclick={scan}>Scan QR code</Button>
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

<style>
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
</style>
