<script lang="ts">
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import { isDidWeb } from '$lib/did-doc-utils';

  let {
    didDoc,
    onback,
    onmigrate,
    onchangehandle,
    onapppasswords,
    onremove,
  }: {
    didDoc: Record<string, unknown>;
    onback: () => void;
    /** Only passed when the device key is the DID's root rotation key — gates the
     *  wallet-authorized outbound migration entry point (ADR-0002 path 1). */
    onmigrate?: () => void;
    /** Only passed for a wallet-custodied did:plc (device key in the rotation set) —
     *  gates the sovereign change-handle entry point (device-key-signed alsoKnownAs op). */
    onchangehandle?: () => void;
    /** Opens the app-password surface (sign the Bluesky app into this account). */
    onapppasswords?: () => void;
    /** Opens the permanent-removal flow (delete on PDS + tombstone DID + local wipe). */
    onremove?: () => void;
  } = $props();

  // A did:web identity has no PLC machinery (ADR-0003): no rotation-key hierarchy, no public audit
  // log, no recovery window. We say so plainly rather than presenting the wallet's PLC-only
  // assurances (monitoring, recovery, the claim/Shamir ceremonies) as if they applied.
  let isWebDid = $derived(typeof didDoc.id === 'string' && isDidWeb(didDoc.id));

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

  {#if isWebDid}
    <div class="didweb" role="note">
      <span class="didweb-ic" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      </span>
      <div class="didweb-body">
        <p class="didweb-t">This is a did:web identity</p>
        <p class="didweb-s">
          Its DID document lives at a domain you control — not on the public PLC directory. The
          wallet's PLC protections don't apply here: there is <strong>no rotation-key hierarchy</strong>,
          <strong>no public audit log to monitor</strong>, and <strong>no 72-hour recovery window</strong>.
          This identity is defended by control of its domain, so keep the domain and its
          <code>did.json</code> secure. To move it to another PDS, edit that <code>did.json</code>
          yourself — there is no PLC operation to sign.
        </p>
      </div>
    </div>
  {/if}

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
              <code class="kv">{String(method.publicKeyMultibase)}</code>
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

  {#if onchangehandle}
    <button class="action" onclick={onchangehandle}>Change handle</button>
  {/if}

  {#if onapppasswords}
    <button class="action" onclick={onapppasswords}>Sign in to Bluesky and other apps</button>
  {/if}

  {#if onmigrate}
    <button class="migrate" onclick={onmigrate}>Migrate to another PDS</button>
  {/if}

  {#if onremove}
    <button class="remove" onclick={onremove}>Remove this identity…</button>
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
    gap: var(--space-2xs);
    background: none;
    border: none;
    color: var(--color-accent);
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    cursor: pointer;
    padding: var(--space-xs);
    min-height: var(--size-tap-target);
  }
  .title {
    font-size: var(--text-headline);
    font-weight: var(--weight-bold);
    color: var(--color-ink);
    margin: 0;
  }

  /* did:web explainer — informational, not an alarm: aubergine "reveal the machinery" tone,
     paired with an icon + text (never color alone) per the design brief. */
  .didweb {
    display: flex;
    gap: var(--space-sm);
    background: var(--color-seal-tint);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .didweb-ic {
    width: 34px;
    height: 34px;
    border-radius: var(--radius-full);
    background: var(--color-bg);
    color: var(--color-accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .didweb-body {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }
  .didweb-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .didweb-s {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: 1.5;
  }
  .didweb-s code {
    font-family: var(--font-mono);
    font-size: 0.92em;
    background: var(--color-surface-sunk);
    padding: 1px 4px;
    border-radius: var(--radius-sm);
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
    word-break: break-all;
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

  .migrate,
  .action {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: 10px var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-accent);
    cursor: pointer;
    text-align: center;
  }

  /* Destructive, irreversible action — critical color paired with explicit
     "Remove" text + the trailing ellipsis signalling a further confirmation step
     (status never by color alone, per the design brief). */
  .remove {
    background: var(--color-surface);
    border: 1px solid var(--color-critical);
    border-radius: var(--radius-md);
    padding: 10px var(--space-md);
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
    cursor: pointer;
    text-align: center;
  }
</style>
