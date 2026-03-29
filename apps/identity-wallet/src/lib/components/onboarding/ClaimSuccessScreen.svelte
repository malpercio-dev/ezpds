<script lang="ts">
  import { type ClaimResult } from '$lib/ipc';
  import { extractPdsFromPlcDoc } from '$lib/did-doc-utils';

  let {
    claimResult,
    ondone,
  }: {
    claimResult: ClaimResult;
    ondone: () => void;
  } = $props();

  // Extract typed fields from the loosely-typed updatedDidDoc
  let didId = $derived(
    typeof claimResult.updatedDidDoc?.id === 'string'
      ? claimResult.updatedDidDoc.id
      : '—'
  );

  let alsoKnownAs = $derived(
    Array.isArray(claimResult.updatedDidDoc?.alsoKnownAs)
      ? (claimResult.updatedDidDoc.alsoKnownAs as string[])
      : []
  );

  let pdsEndpoint = $derived.by(() => {
    const doc = claimResult.updatedDidDoc;
    if (typeof doc !== 'object' || doc === null) return '—';

    const endpoint = extractPdsFromPlcDoc(doc as Record<string, unknown>);
    return endpoint ?? '—';
  });
</script>

<div class="screen">
  <!-- Success header -->
  <div class="header">
    <div class="checkmark-circle">✓</div>
    <h2 class="title">Identity Claimed Successfully</h2>
    <p class="subtitle">Your rotation key has been updated. You are now in control of this identity.</p>
  </div>

  <!-- DID document summary -->
  <div class="summary-card">
    <div class="summary-item">
      <p class="summary-label">DID</p>
      <code class="summary-value">{didId}</code>
    </div>

    {#if alsoKnownAs.length > 0}
      <div class="summary-item">
        <p class="summary-label">Handle</p>
        <p class="summary-value">{alsoKnownAs[0]}</p>
      </div>
    {/if}

    <div class="summary-item">
      <p class="summary-label">PDS Endpoint</p>
      <p class="summary-value mono">{pdsEndpoint}</p>
    </div>
  </div>

  <!-- Done button -->
  <button class="cta" onclick={ondone}>Done</button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 2rem;
    gap: 2rem;
    text-align: center;
  }

  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
  }

  .checkmark-circle {
    width: 64px;
    height: 64px;
    background: #22c55e;
    color: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    font-weight: 700;
  }

  .title {
    font-size: 1.5rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .subtitle {
    font-size: 0.95rem;
    color: #6b7280;
    margin: 0;
    max-width: 300px;
    line-height: 1.5;
  }

  .summary-card {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1.5rem;
    width: 100%;
    max-width: 400px;
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .summary-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    align-items: flex-start;
    width: 100%;
  }

  .summary-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .summary-value {
    font-size: 0.9rem;
    color: #374151;
    margin: 0;
    word-break: break-all;
    text-align: left;
  }

  .summary-value.mono {
    font-family: monospace;
    font-size: 0.8rem;
  }

  .cta {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
  }
</style>
