<script lang="ts">
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';

  let {
    didDoc,
    onback,
  }: {
    didDoc: Record<string, unknown>;
    onback: () => void;
  } = $props();

  let showRaw = $state(false);
  let copiedKeyId = $state<string | null>(null);
  let failedKeyId = $state<string | null>(null);

  // Extract typed arrays from the loosely-typed didDoc.
  let verificationMethods = $derived(
    Array.isArray(didDoc.verificationMethod)
      ? (didDoc.verificationMethod as Array<Record<string, unknown>>)
      : []
  );

  let alsoKnownAs = $derived(
    Array.isArray(didDoc.alsoKnownAs)
      ? (didDoc.alsoKnownAs as Array<string>)
      : []
  );

  let services = $derived(
    Array.isArray(didDoc.service)
      ? (didDoc.service as Array<Record<string, unknown>>)
      : []
  );

  let rawJson = $derived(JSON.stringify(didDoc, null, 2));

  async function copyKey(keyId: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      copiedKeyId = keyId;
      setTimeout(() => { copiedKeyId = null; }, 2000);
    } catch {
      failedKeyId = keyId;
      setTimeout(() => { failedKeyId = null; }, 2000);
    }
  }
</script>

<div class="screen">
  <button class="back" onclick={onback} aria-label="Back">
    <ChevronLeftIcon />
    Back
  </button>
  <h1 class="title">DID document</h1>

  <div class="section">
    <p class="label">Identifier</p>
    <p class="mono">{didDoc.id ?? '—'}</p>
  </div>

  {#if alsoKnownAs.length > 0}
    <div class="section">
      <p class="label">Also known as</p>
      {#each alsoKnownAs as alias}
        <p class="mono">{alias}</p>
      {/each}
    </div>
  {/if}

  {#if verificationMethods.length > 0}
    <div class="section">
      <p class="label">Verification keys</p>
      {#each verificationMethods as method}
        <div class="card">
          <p class="card-type">{method.type ?? 'Unknown'}</p>
          <p class="card-id">{method.id}</p>
          {#if method.publicKeyMultibase}
            <div class="kv-row">
              <code class="kv">{String(method.publicKeyMultibase).slice(0, 20)}…</code>
              <button
                class="copy"
                onclick={() => copyKey(String(method.id), String(method.publicKeyMultibase))}
              >
                {copiedKeyId === String(method.id) ? 'Copied!' : failedKeyId === String(method.id) ? 'Failed' : 'Copy'}
              </button>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  {#if services.length > 0}
    <div class="section">
      <p class="label">Services</p>
      {#each services as svc}
        <div class="card">
          <p class="card-type">{svc.type ?? 'Unknown'}</p>
          <p class="mono">{svc.serviceEndpoint}</p>
        </div>
      {/each}
    </div>
  {/if}

  <button class="toggle" onclick={() => { showRaw = !showRaw; }}>
    {showRaw ? 'Hide raw JSON' : 'Show raw JSON'}
  </button>

  {#if showRaw}
    <pre class="raw">{rawJson}</pre>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }
  .back {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs) 0;
  }
  .title {
    font-size: var(--text-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }

  .section {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .mono {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    margin: 0;
    word-break: break-all;
  }

  .card {
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .card-type {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink-soft);
    margin: 0;
  }
  .card-id {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-muted);
    margin: 0;
    word-break: break-all;
  }
  .kv-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .kv {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-surface-sunk);
    padding: 3px 6px;
    border-radius: var(--radius-sm);
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .copy {
    background: var(--color-surface);
    color: var(--color-ink);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-sm);
    padding: 5px 12px;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .toggle {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: 10px var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    cursor: pointer;
    text-align: center;
  }
  .raw {
    background: var(--color-surface-sunk);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
    overflow-x: auto;
    white-space: pre;
    word-break: normal;
    margin: 0;
  }
</style>
