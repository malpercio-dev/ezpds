<script lang="ts">
  import { onMount } from 'svelte';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { authenticateBiometric, completeDidWebCeremony, prepareDidWebCeremony, type DIDCeremonyResult } from '$lib/ipc';
  import { composeDidWebDocument, didWebDocumentUrl, serializeDidWebDocument, type DidWebHosting } from '$lib/did-web';
  import { shareDidDocument } from '$lib/share';

  let { domain, handle, password, hosting, onsuccess, onback }: { domain: string; handle: string; password: string; hosting: DidWebHosting; onsuccess: (result: DIDCeremonyResult) => void; onback: () => void } = $props();
  let document = $state<Record<string, unknown> | null>(null);
  let rendered = $state('');
  let error = $state('');
  let busy = $state(true);

  onMount(async () => {
    try {
      const keys = await prepareDidWebCeremony();
      document = composeDidWebDocument(domain, handle, keys.deviceKeyMultibase, keys.repoKeyMultibase, keys.pdsUrl);
      rendered = serializeDidWebDocument(document as ReturnType<typeof composeDidWebDocument>);
    } catch { error = 'Could not prepare the domain document. Try again.'; }
    finally { busy = false; }
  });

  async function verifyAndCreate() {
    if (!document) return;
    try { await authenticateBiometric('Approve creation of your domain identity'); }
    catch { return; }
    busy = true; error = '';
    try { onsuccess(await completeDidWebCeremony(rendered, password, hosting === 'custos')); }
    catch { error = `The live document at ${didWebDocumentUrl(String(document.id))} does not match yet. Publish the exported bytes, wait for propagation, then retry.`; }
    finally { busy = false; }
  }
</script>

<OnboardingShell title="Review and publish did.json" subtitle={hosting === 'custos' ? 'Publish this once to prove domain control. Custos will take over serving only after it verifies the live copy.' : 'Export this exact file to your web host. Custos verifies every byte before creating the account.'} {onback}>
  {#if busy && !document}<Spinner label="Preparing keys…" />{/if}
  {#if document}
    <div class="diffs">
      <DiffRow variant="restore" title="Device key" value={`${document.id}#device`} />
      <DiffRow variant="modify" title="Repository signing key" value={`${document.id}#atproto`} />
      <DiffRow variant="modify" title="PDS service" value={`${document.id}#atproto_pds`} />
      <DiffRow variant="restore" title="Domain identity" value={String(document.id)} />
    </div>
    <code>{rendered}</code>
    <Button variant="secondary" onclick={() => shareDidDocument(rendered)}>Export did.json</Button>
    <Button disabled={busy} onclick={verifyAndCreate}>{busy ? 'Verifying live document…' : 'I’ve published this exact file'}</Button>
  {/if}
  {#if error}<p class="error" role="alert">⚠ {error}</p>{/if}
</OnboardingShell>

<style>
  .diffs { display: grid; gap: var(--space-xs); width: 100%; text-align: left; }
  code { display: block; max-height: 11rem; width: 100%; overflow: auto; padding: var(--space-sm); border: 1px solid var(--color-line); border-radius: var(--radius-md); background: var(--color-surface-sunk); color: var(--color-ink); font-family: var(--font-mono); font-size: var(--text-data); text-align: left; white-space: pre; }
  .error { margin: 0; color: var(--color-critical); line-height: var(--leading-body); }
</style>
