<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import DiffRow from '$lib/components/ui/DiffRow.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import { armIdentityLeg, authenticateBiometric, buildDidWebMigrationDocument, finalizeMigration, submitDidWebMigrationDocument, type ClaimResult, type DidWebMigrationDocument } from '$lib/ipc';
  import type { DidWebHosting } from '$lib/did-web';
  import { shareDidDocument } from '$lib/share';
  let { did, hosting, onnext, oncancel }: { did: string; hosting: DidWebHosting; onnext: (result: ClaimResult) => void; oncancel: () => void } = $props();
  let review = $state<DidWebMigrationDocument | null>(null);
  let loading = $state(true);
  let submitting = $state(false);
  let error = $state('');

  async function load() {
    loading = true; error = '';
    try { await armIdentityLeg(did); review = await buildDidWebMigrationDocument(did); }
    catch { error = 'Could not prepare the did.json update. Restart the migration if this continues.'; }
    finally { loading = false; }
  }
  async function submit() {
    if (!review) return;
    try { await authenticateBiometric('Approve the domain identity update'); }
    catch { return; }
    submitting = true; error = '';
    try {
      const result = await submitDidWebMigrationDocument(did, review.documentText, hosting === 'custos');
      await finalizeMigration(did);
      onnext(result);
    } catch { error = 'The live did.json does not match the reviewed bytes yet. Publish the export, wait for propagation, then retry.'; }
    finally { submitting = false; }
  }
  load();
</script>

<OnboardingShell title="Review the domain update" subtitle="These four changes adopt your device key and move the account without a PLC operation." onback={oncancel}>
  {#if loading}<Spinner label="Preparing document…" />
  {:else if review}
    <div class="diffs">
      <DiffRow variant="restore" title="Add device key" value={review.deviceKey} />
      <DiffRow variant="modify" title="Replace #atproto signing key" value={review.repoKey} />
      <DiffRow variant="modify" title="Repoint #atproto_pds" value={review.pdsEndpoint} />
      <DiffRow variant="restore" title="Preserve domain root of trust" value={did} />
    </div>
    <code>{review.documentText}</code>
    <Button variant="secondary" onclick={() => shareDidDocument(review!.documentText)}>Export updated did.json</Button>
    <Button disabled={submitting} onclick={submit}>{submitting ? 'Verifying and finishing…' : 'I’ve published this exact file'}</Button>
  {/if}
  {#if error}<p class="error" role="alert">⚠ {error}</p><Button onclick={load}>Retry preparation</Button>{/if}
</OnboardingShell>

<style>
  .diffs { display: grid; gap: var(--space-xs); width: 100%; text-align: left; }
  code { display: block; max-height: 10rem; width: 100%; overflow: auto; padding: var(--space-sm); border: 1px solid var(--color-line); border-radius: var(--radius-md); background: var(--color-surface-sunk); color: var(--color-ink); font-family: var(--font-mono); font-size: var(--text-data); text-align: left; white-space: pre; }
  .error { margin: 0; color: var(--color-critical); line-height: var(--leading-body); }
</style>
