<script lang="ts">
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import { isDidWeb } from '$lib/did-doc-utils';

  let {
    didDoc,
    onback,
    onmigrate,
    onrecoverpds,
    onchangehandle,
    onrepairendpoint,
    onrotatekey,
    onrecoverykit,
    onapppasswords,
    onagents,
    onsignin,
    onbackup,
    onremove,
    deviceKeyUnusable = false,
    onrecover,
  }: {
    didDoc: Record<string, unknown>;
    onback: () => void;
    /**
     * The Secure Enclave no longer holds this identity's device key. Every signing entry
     * point above is already withheld (they gate on the device key being root, which can
     * no longer be established) — this says *why* they are gone, so their absence reads
     * as an explanation rather than a missing feature.
     */
    deviceKeyUnusable?: boolean;
    /**
     * Enter the recovery ceremony — the flow that restores this device's ability to sign.
     * did:plc only: the ceremony rotates a fresh key into `rotationKeys[0]`, which a did:web
     * does not have. Callers must withhold it for a did:web, which gets its own remedy above.
     */
    onrecover?: () => void;
    /** Only passed when the device key is the DID's root rotation key — gates the
     *  wallet-authorized outbound migration entry point (ADR-0002 path 1). */
    onmigrate?: () => void;
    /** Only passed when the device key is the DID's root rotation key — gates the
     *  sovereign disaster-recovery entry point: rebuild the account on a new PDS from
     *  the iCloud backups when the current PDS is gone or uncooperative (MM-451). */
    onrecoverpds?: () => void;
    /** Only passed for a wallet-custodied did:plc (device key in the rotation set) —
     *  gates the sovereign change-handle entry point (device-key-signed alsoKnownAs op). */
    onchangehandle?: () => void;
    /** Only passed for a wallet-custodied did:plc — gates the sovereign endpoint-repair
     *  entry point (device-key-signed atproto_pds repoint when the server changed hostname). */
    onrepairendpoint?: () => void;
    /** Only passed for a wallet-custodied did:plc — gates the sovereign repo signing-key
     *  rotation entry point (device-key-signed key-swap op via the hosting PDS). */
    onrotatekey?: () => void;
    /**
     * Only passed for a wallet-custodied did:plc whose host answered describeServer and
     * advertises no `escrow` — gates the escrow-less self-held Shamir kit (a device-key-signed
     * PLC op inserting a derived recovery key, with all three shares held by the user). Withheld
     * on an escrow-capable host, where the escrow-backed ceremony is the better offer, and on a
     * host that could not be asked, so a network blink never routes anyone to a dead end.
     */
    onrecoverykit?: () => void;
    /** Opens the app-password surface (sign the Bluesky app into this account). */
    onapppasswords?: () => void;
    /** Opens the "My agents" surface (consent + audit + revoke) for this identity. */
    onagents?: () => void;
    /** Opens the wallet-confirmed OAuth consent surface (sign in to an app with a typed code). */
    onsignin?: () => void;
    /** Opens the media-backup surface (user-held blob mirror in iCloud Drive). */
    onbackup?: () => void;
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

  {#if deviceKeyUnusable}
    <div class="didweb didweb--warn" role="note">
      <span class="didweb-ic" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.3-2.5"/><path d="m2 2 20 20"/></svg>
      </span>
      <div class="didweb-body">
        <p class="didweb-t">This device can no longer sign for this identity</p>
        {#if isWebDid}
          <!-- No recovery ceremony here: it works by rotating a fresh key into
               rotationKeys[0] via a PLC operation, and a did:web has no rotation keys —
               `start_share_recovery` refuses a non-did:plc identifier outright. The remedy
               is the domain, the same place all of a did:web's authority comes from. -->
          <p class="didweb-s">
            Its key lived in this device's Secure Enclave, which a backup can never restore —
            so a restored or replaced device arrives without it. <strong>The identity itself is
            unaffected</strong>: it lives at your domain, and control of that domain is what
            defends it. Only this device's ability to act for it is gone.
          </p>
          <p class="didweb-s">
            A did:web has no rotation keys, so there is no recovery ceremony to run. To give
            this device a working key again: remove the identity here (which only forgets it
            locally — it publishes nothing), import it again to issue a fresh key, then publish
            that key in your domain's <code>did.json</code>.
          </p>
        {:else}
          <p class="didweb-s">
            Its key lived in this device's Secure Enclave, which a backup can never restore —
            so a restored or replaced device arrives without it. <strong>The identity itself is
            unaffected</strong>: it is intact on the public record, and your recovery shares still
            control it. Only this device's ability to act for it is gone, which is why changing the
            handle, migrating, and repairing the endpoint are unavailable here.
            Recovering issues a new key on this device and installs it as the identity's top
            rotation key.
          </p>
          {#if onrecover}
            <button class="recover-btn" onclick={onrecover}>Recover this identity</button>
          {/if}
        {/if}
      </div>
    </div>
  {/if}

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

  {#if onrepairendpoint}
    <button class="action" onclick={onrepairendpoint}>Repair hosting endpoint</button>
  {/if}

  {#if onrotatekey}
    <button class="action" onclick={onrotatekey}>Rotate signing key</button>
  {/if}

  {#if onrecoverykit}
    <button class="action" onclick={onrecoverykit}>Add a recovery key</button>
  {/if}

  {#if onapppasswords}
    <button class="action" onclick={onapppasswords}>Sign in to Bluesky and other apps</button>
  {/if}

  {#if onsignin}
    <button class="action" onclick={onsignin}>Sign in to an app</button>
  {/if}

  {#if onagents}
    <button class="action" onclick={onagents}>My agents</button>
  {/if}

  {#if onbackup}
    <button class="action" onclick={onbackup}>Back up media</button>
  {/if}

  {#if onmigrate}
    <button class="migrate" onclick={onmigrate}>Migrate to another PDS</button>
  {/if}

  {#if onrecoverpds}
    <button class="migrate" onclick={onrecoverpds}>Rebuild from backup (PDS gone)</button>
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
  /* Same notice shell as the did:web note; the warning tone marks a state that needs
     action, while the icon and the copy carry the meaning on their own. */
  .didweb--warn {
    background: var(--color-warning-surface);
  }
  .didweb--warn .didweb-ic {
    color: var(--color-warning);
  }
  .recover-btn {
    align-self: flex-start;
    margin-top: var(--space-xs);
    min-height: var(--size-tap-target);
    padding: 0 var(--space-md);
    background: var(--color-bg);
    color: var(--color-ink);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    cursor: pointer;
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
    gap: var(--space-xs);
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
