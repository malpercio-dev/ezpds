<script lang="ts">
  import { resolveIdentity, type IdentityInfo, type ResolveError } from '$lib/ipc';

  let {
    value = $bindable(''),
    onnext,
    onback,
  }: {
    value: string;
    onnext: (info: IdentityInfo) => void;
    onback: () => void;
  } = $props();

  let resolving = $state(false);
  let resolved = $state<IdentityInfo | null>(null);
  let error = $state<string | null>(null);

  async function resolve() {
    if (!value.trim()) return;

    resolving = true;
    error = null;
    resolved = null;

    try {
      const info = await resolveIdentity(value.trim());
      resolved = info;
      error = null;
    } catch (raw: unknown) {
      // Map ResolveError codes to user-friendly messages.
      if (typeof raw === 'object' && raw !== null && 'code' in raw) {
        const err = raw as ResolveError;
        switch (err.code) {
          case 'HANDLE_NOT_FOUND':
            error = 'Handle not found. Check the spelling and try again.';
            break;
          case 'DID_NOT_FOUND':
            error = 'DID not found on PLC directory.';
            break;
          case 'PDS_UNREACHABLE':
            error = 'Could not reach the PDS. It may be temporarily offline.';
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = 'An unexpected error occurred. Please try again.';
        }
      } else {
        error = 'An unexpected error occurred. Please try again.';
      }
      resolved = null;
    } finally {
      resolving = false;
    }
  }

  function handleInputChange() {
    if (resolved || error) {
      resolved = null;
      error = null;
    }
  }

  // Truncate the DID for display on narrow mobile screens.
  // "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcdefgh…uvwxyz"
  let displayDid = $derived.by(() => {
    const did = resolved?.did ?? '';
    const prefix = 'did:plc:';
    if (!did.startsWith(prefix)) return did;
    const specific = did.slice(prefix.length);
    if (specific.length < 14) return did;
    return `${prefix}${specific.slice(0, 8)}…${specific.slice(-6)}`;
  });
</script>

<div class="screen">
  <h2>Import Identity</h2>
  <p class="hint">Enter a handle or DID to import an existing identity.</p>

  <input
    type="text"
    class:error={!!error}
    placeholder="alice.example.com or did:plc:..."
    autocomplete="off"
    autocorrect="off"
    autocapitalize="none"
    spellcheck={false}
    bind:value
    oninput={handleInputChange}
  />

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  <button
    disabled={resolving || !value.trim()}
    onclick={resolve}
  >
    {resolving ? 'Resolving…' : 'Resolve'}
  </button>

  {#if resolved}
    <div class="identity-card">
      <div class="card-content">
        <p class="card-label">Handle</p>
        <p class="card-value">@{resolved.handle}</p>

        <p class="card-label">DID</p>
        <p class="card-value did-value">{displayDid}</p>

        <p class="card-label">PDS</p>
        <p class="card-value">{resolved.pdsUrl}</p>

        <p class="card-label">Rotation Key Status</p>
        <p class="card-value" class:status-root={resolved.deviceKeyIsRoot} class:status-not-root={!resolved.deviceKeyIsRoot}>
          {#if resolved.deviceKeyIsRoot}
            Your device is the root key
          {:else}
            Device key is not the root key
          {/if}
        </p>
      </div>
    </div>

    <button class="continue-btn" onclick={() => onnext(resolved!)}>
      Continue
    </button>
  {/if}

  <button class="back-btn" onclick={onback}>
    Back
  </button>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem;
    gap: 1rem;
    height: 100%;
    justify-content: center;
  }

  h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 0;
  }

  .hint {
    font-size: 0.9rem;
    color: #6b7280;
    text-align: center;
    margin: 0;
  }

  input {
    width: 100%;
    max-width: 320px;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #d1d5db;
    border-radius: 12px;
  }

  input.error {
    border-color: #ef4444;
  }

  .error-text {
    color: #ef4444;
    font-size: 0.875rem;
    margin: 0;
    text-align: center;
    max-width: 320px;
  }

  button {
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

  button:disabled {
    background: #9ca3af;
    cursor: not-allowed;
  }

  .identity-card {
    background: #f9fafb;
    border: 1px solid #d1d5db;
    border-radius: 12px;
    padding: 1.25rem;
    width: 100%;
    max-width: 320px;
  }

  .card-content {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .card-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: #6b7280;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .card-value {
    font-size: 0.95rem;
    color: #111827;
    margin: 0;
    word-break: break-word;
  }

  .did-value {
    font-family: monospace;
    font-size: 0.85rem;
  }

  .status-root {
    color: #22c55e;
    font-weight: 600;
  }

  .status-not-root {
    color: #6b7280;
  }

  .continue-btn {
    margin-top: 0.5rem;
  }

  .back-btn {
    background: #f3f4f6;
    color: #000;
    margin-top: auto;
  }
</style>
