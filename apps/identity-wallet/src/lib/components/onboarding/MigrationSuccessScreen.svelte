<script lang="ts">
  import { type ClaimResult } from '$lib/ipc';
  import { extractPdsFromPlcDoc, extractHandle } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    result,
    destPdsLabel,
    ondone,
  }: {
    result: ClaimResult;
    destPdsLabel?: string;
    ondone: () => void;
  } = $props();

  let didId = $derived.by(() => {
    const doc = result.updatedDidDoc;
    if (typeof doc !== 'object' || doc === null) return '—';
    const d = doc as Record<string, unknown>;
    return typeof d.did === 'string' ? d.did : typeof d.id === 'string' ? d.id : '—';
  });

  let handle = $derived.by(() => {
    const doc = result.updatedDidDoc;
    if (typeof doc !== 'object' || doc === null) return null;
    return extractHandle(doc as Record<string, unknown>);
  });

  let pdsEndpoint = $derived.by(() => {
    const doc = result.updatedDidDoc;
    if (typeof doc !== 'object' || doc === null) return destPdsLabel ?? '—';
    return extractPdsFromPlcDoc(doc as Record<string, unknown>) ?? destPdsLabel ?? '—';
  });
</script>

<OnboardingShell
  tone="signet"
  title="Migration complete"
  subtitle="Your identity now lives on its new PDS. Your DID hasn't changed."
>
  {#snippet icon()}
    <SealEmblem size={80}>
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 11.5 2 2 4-4" />
      </svg>
    </SealEmblem>
  {/snippet}

  <div class="summary">
    <div class="row"><span class="k">DID</span><span class="v mono">{didId}</span></div>
    {#if handle}
      <div class="row"><span class="k">Handle</span><span class="v">@{handle}</span></div>
    {/if}
    <div class="row"><span class="k">New PDS</span><span class="v mono">{pdsEndpoint}</span></div>
  </div>

  <Button onclick={ondone}>Done</Button>
</OnboardingShell>

<style>
  .summary {
    width: 100%;
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    text-align: left;
  }
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
  }
  .k {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
  }
  .v {
    font-size: var(--text-body);
    color: var(--color-ink);
    word-break: break-all;
  }
  .v.mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
  }
</style>
