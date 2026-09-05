<script lang="ts">
  import { type ClaimResult } from '$lib/ipc';
  import { extractPdsFromPlcDoc, extractHandle } from '$lib/did-doc-utils';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import SealEmblem from '$lib/components/ui/SealEmblem.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    result,
    title,
    subtitle,
    pdsLabel = 'PDS',
    destPdsLabel,
    ondone,
  }: {
    result: ClaimResult;
    title: string;
    subtitle: string;
    /** Row label for the endpoint line — "PDS" after a claim, "New PDS" after a migration. */
    pdsLabel?: string;
    /** Fallback endpoint text when the served DID document doesn't name one yet (migration only). */
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

<OnboardingShell tone="signet" {title} {subtitle}>
  {#snippet icon()}
    <SealEmblem size={80}>
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 11.5 2 2 4-4" />
      </svg>
    </SealEmblem>
  {/snippet}

  <div class="summary u-card">
    <div class="row u-stack-3xs"><span class="k u-label-muted">DID</span><span class="v mono">{didId}</span></div>
    {#if handle}
      <div class="row u-stack-3xs"><span class="k u-label-muted">Handle</span><span class="v">@{handle}</span></div>
    {/if}
    <div class="row u-stack-3xs"><span class="k u-label-muted">{pdsLabel}</span><span class="v mono">{pdsEndpoint}</span></div>
  </div>

  <Button onclick={ondone}>Done</Button>
</OnboardingShell>

<style>
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
