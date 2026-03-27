<script lang="ts">
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
  <div class="header">
    <button class="back-btn" onclick={onback} aria-label="Back">‹ Back</button>
    <h2 class="title">DID Document</h2>
  </div>

  <!-- Identity section -->
  <div class="section">
    <p class="section-label">Identifier</p>
    <p class="mono-value">{didDoc.id ?? '—'}</p>
  </div>

  <!-- alsoKnownAs -->
  {#if alsoKnownAs.length > 0}
    <div class="section">
      <p class="section-label">Also Known As</p>
      {#each alsoKnownAs as alias}
        <p class="mono-value">{alias}</p>
      {/each}
    </div>
  {/if}

  <!-- Verification Methods -->
  {#if verificationMethods.length > 0}
    <div class="section">
      <p class="section-label">Verification Keys</p>
      {#each verificationMethods as method}
        <div class="key-card">
          <p class="key-type">{method.type ?? 'Unknown'}</p>
          <p class="key-id">{method.id}</p>
          {#if method.publicKeyMultibase}
            <div class="key-value-row">
              <code class="key-value">{String(method.publicKeyMultibase).slice(0, 20)}…</code>
              <button
                class="copy-btn"
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

  <!-- Services -->
  {#if services.length > 0}
    <div class="section">
      <p class="section-label">Services</p>
      {#each services as svc}
        <div class="service-card">
          <p class="service-type">{svc.type ?? 'Unknown'}</p>
          <p class="service-endpoint">{svc.serviceEndpoint}</p>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Raw JSON toggle -->
  <button
    class="toggle-btn"
    onclick={() => { showRaw = !showRaw; }}
  >
    {showRaw ? 'Hide Raw JSON' : 'Show Raw JSON'}
  </button>

  {#if showRaw}
    <pre class="raw-json">{rawJson}</pre>
  {/if}
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 2rem 1.5rem;
    gap: 1.25rem;
    overflow-y: auto;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .back-btn {
    background: none;
    border: none;
    font-size: 1rem;
    color: #007aff;
    cursor: pointer;
    padding: 0;
    font-weight: 500;
    white-space: nowrap;
  }

  .title {
    font-size: 1.2rem;
    font-weight: 700;
    color: #111827;
    margin: 0;
  }

  .section {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .section-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .mono-value {
    font-family: monospace;
    font-size: 0.8rem;
    color: #374151;
    margin: 0;
    word-break: break-all;
  }

  .key-card {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .key-type {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0;
  }

  .key-id {
    font-family: monospace;
    font-size: 0.75rem;
    color: #6b7280;
    margin: 0;
    word-break: break-all;
  }

  .key-value-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.25rem;
  }

  .key-value {
    font-family: monospace;
    font-size: 0.75rem;
    color: #374151;
    background: #f3f4f6;
    padding: 0.2rem 0.4rem;
    border-radius: 4px;
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .copy-btn {
    background: #007aff;
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 0.3rem 0.75rem;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .service-card {
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .service-type {
    font-size: 0.8rem;
    font-weight: 600;
    color: #374151;
    margin: 0;
  }

  .service-endpoint {
    font-family: monospace;
    font-size: 0.8rem;
    color: #6b7280;
    margin: 0;
    word-break: break-all;
  }

  .toggle-btn {
    background: none;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 0.6rem 1rem;
    font-size: 0.9rem;
    color: #374151;
    cursor: pointer;
    text-align: center;
  }

  .raw-json {
    background: #f3f4f6;
    border: 1px solid #d1d5db;
    border-radius: 8px;
    padding: 1rem;
    font-family: monospace;
    font-size: 0.75rem;
    color: #374151;
    overflow-x: auto;
    white-space: pre;
    word-break: normal;
    margin: 0;
  }
</style>
