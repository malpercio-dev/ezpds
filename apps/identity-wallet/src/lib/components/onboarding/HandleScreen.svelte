<script lang="ts">
  import { onMount } from 'svelte';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { getAvailableUserDomains } from '$lib/ipc';
  import { composeHandle, isValidLabel } from '$lib/handle';

  let {
    value = $bindable(''),
    onnext,
    error = undefined,
  }: {
    value: string;
    onnext: () => void;
    error?: string;
  } = $props();

  // The full handle is assembled from the user's label plus a domain served by the PDS, BEFORE
  // the DID ceremony — so the did:plc genesis op's `alsoKnownAs` carries the real, resolvable
  // handle (`at://alice.ezpds.com`) rather than a bare label that renders as `handle.invalid`.
  type DomainState =
    | { kind: 'loading' }
    | { kind: 'ready'; domain: string }
    | { kind: 'none' }
    | { kind: 'error' };

  let domains = $state<DomainState>({ kind: 'loading' });
  // The leftmost label the user types; the domain suffix is supplied by the PDS.
  let label = $state('');

  let isValid = $derived(domains.kind === 'ready' && isValidLabel(label));
  let preview = $derived(
    domains.kind === 'ready' ? composeHandle(label.trim() || 'your-name', domains.domain) : ''
  );

  async function loadDomains() {
    domains = { kind: 'loading' };
    try {
      const list = await getAvailableUserDomains();
      const domain = list[0];
      if (!domain) {
        domains = { kind: 'none' };
        return;
      }
      domains = { kind: 'ready', domain };
      // Returning to this screen (e.g. after an error rewind) with a full handle already set:
      // recover the label so the field is pre-filled.
      if (value.endsWith(`.${domain}`)) {
        label = value.slice(0, value.length - domain.length - 1);
      }
    } catch (e) {
      console.error('[HandleScreen] failed to load user domains:', e);
      domains = { kind: 'error' };
    }
  }

  function submit() {
    if (domains.kind !== 'ready' || !isValid) return;
    value = composeHandle(label, domains.domain);
    onnext();
  }

  onMount(loadDomains);
</script>

<OnboardingShell
  title="Choose your handle"
  subtitle="This is your unique identity on the network — how others find and verify you."
>
  {#if domains.kind === 'loading'}
    <Spinner size={28} label="Loading available handle domains" />
  {:else if domains.kind === 'error'}
    <p class="status">Couldn’t reach the server to load handle domains.</p>
    <Button onclick={loadDomains}>Try again</Button>
  {:else if domains.kind === 'none'}
    <p class="status">This server has no handle domains configured. Please contact your operator.</p>
  {:else}
    <TextField
      bind:value={label}
      type="text"
      placeholder="alice"
      autocomplete="off"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Handle"
      {error}
    />
    <p class="preview">Your handle: <span class="handle">{preview}</span></p>
    <Button disabled={!isValid} onclick={submit}>Create account</Button>
  {/if}
</OnboardingShell>

<style>
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    text-align: center;
    margin: 0;
  }
  .preview {
    font-size: var(--text-label);
    color: var(--color-muted);
    text-align: center;
    margin: 0;
  }
  .handle {
    font-family: var(--font-mono);
    color: var(--color-ink);
  }
</style>
