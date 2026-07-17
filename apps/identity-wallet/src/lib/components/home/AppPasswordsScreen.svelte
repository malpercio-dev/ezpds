<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';
  import SkeletonCard from '$lib/components/ui/SkeletonCard.svelte';
  import { authenticateBiometric } from '$lib/biometric';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import { formatTimestamp } from '$lib/datetime';
  import {
    listAppPasswords,
    createAppPassword,
    revokeAppPassword,
    ensureIdentitySession,
    sovereignLogin,
    isCodedError,
    type AppPasswordEntry,
    type AppPasswordCreated,
    type AppPasswordsError,
  } from '$lib/ipc';

  let {
    did,
    onback,
  }: {
    did: string;
    onback: () => void;
  } = $props();

  // A sovereign account has no main password, so this minted credential is the only
  // way a password-login client (the official Bluesky app first among them) can sign
  // in. The session it opens is scope-bounded: Bluesky things yes, sovereign things no.

  let loading = $state(true);
  // The list couldn't load because the identity's session needs a passwordless unlock.
  let locked = $state(false);
  let loadError = $state<string | null>(null);
  let passwords = $state<AppPasswordEntry[]>([]);

  // Create form.
  let name = $state('');
  let privileged = $state(false);
  let creating = $state(false);
  let createError = $state<string | null>(null);

  // The one-time secret reveal after a successful mint. Dismissing drops the secret
  // for good — it exists nowhere else but the server's hash.
  let created = $state<AppPasswordCreated | null>(null);
  let copied = $state(false);
  let copyFailed = $state(false);

  // Per-entry revoke flow: explicit confirm step, then biometric.
  let confirmingRevoke = $state<string | null>(null);
  let revoking = $state(false);
  let revokeError = $state<string | null>(null);

  let nameValid = $derived(name.trim().length > 0);

  function messageFor(raw: unknown): string {
    if (!isCodedError(raw)) return 'Something went wrong. Please try again.';
    const err = raw as AppPasswordsError;
    switch (err.code) {
      case 'DUPLICATE_NAME':
        return 'You already have an app password with this name. Pick a different one.';
      case 'RATE_LIMITED':
        return formatRateLimitMessage(err.retryAfter);
      case 'SESSION_LOCKED':
        return 'Couldn’t unlock this identity. Please try again.';
      case 'IDENTITY_NOT_FOUND':
        return 'This identity isn’t registered in the wallet.';
      case 'SERVER_ERROR':
        return formatServerErrorMessage(err.message);
      case 'NETWORK_ERROR':
        return 'Couldn’t reach the server. Check your connection.';
      default:
        return 'Something went wrong. Please try again.';
    }
  }

  async function load() {
    loading = true;
    locked = false;
    loadError = null;
    try {
      passwords = await listAppPasswords(did);
    } catch (e) {
      if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
        locked = true;
      } else {
        console.error('[AppPasswordsScreen] failed to load app passwords:', e);
        loadError = 'Could not load your app passwords. Check your connection and try again.';
      }
    } finally {
      loading = false;
    }
  }

  async function unlockAndReload() {
    try {
      await sovereignLogin(did);
    } catch (e) {
      console.error('[AppPasswordsScreen] sovereign login failed:', e);
      return;
    }
    await load();
  }

  async function doCreate() {
    if (!nameValid || creating) return;
    const trimmed = name.trim();
    creating = true;
    createError = null;
    try {
      // Pre-flight the session with no prompt. If it's locked, unlock it passwordlessly
      // (biometric) BEFORE the mint's own biometric gate — avoids a wasted prompt.
      try {
        await ensureIdentitySession(did);
      } catch (e) {
        if (isCodedError(e) && e.code === 'NEEDS_UNLOCK') {
          await sovereignLogin(did);
        } else {
          throw e;
        }
      }

      let result: AppPasswordCreated;
      try {
        result = await createAppPassword(did, trimmed, privileged);
      } catch (e) {
        // A live token can lapse between the pre-flight and the command. Unlock once and retry.
        if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
          await sovereignLogin(did);
          result = await createAppPassword(did, trimmed, privileged);
        } else {
          throw e;
        }
      }
      created = result;
      copied = false;
      copyFailed = false;
      passwords = [
        ...passwords,
        { name: result.name, createdAt: result.createdAt, privileged: result.privileged },
      ];
      name = '';
      privileged = false;
    } catch (e) {
      console.error('[AppPasswordsScreen] create app password failed:', e);
      createError = messageFor(e);
    } finally {
      creating = false;
    }
  }

  async function copySecret() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.password);
      copied = true;
      copyFailed = false;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch {
      copyFailed = true;
      setTimeout(() => {
        copyFailed = false;
      }, 2000);
    }
  }

  async function doRevoke(entryName: string) {
    if (revoking) return;
    revokeError = null;
    // Set the in-flight flag before the biometric prompt so a second tap during the
    // Face ID wait cannot fire a duplicate prompt/revocation.
    revoking = true;
    try {
      await authenticateBiometric('Revoke this app password');
    } catch {
      revoking = false;
      return; // gate rejected — nothing changes.
    }
    try {
      try {
        await revokeAppPassword(did, entryName);
      } catch (e) {
        if (isCodedError(e) && e.code === 'SESSION_LOCKED') {
          await sovereignLogin(did);
          await revokeAppPassword(did, entryName);
        } else {
          throw e;
        }
      }
      passwords = passwords.filter((p) => p.name !== entryName);
      confirmingRevoke = null;
    } catch (e) {
      console.error('[AppPasswordsScreen] revoke failed:', e);
      revokeError = messageFor(e);
    } finally {
      revoking = false;
    }
  }

  onMount(load);
</script>

<div class="screen">
  <ScreenHeader title="App passwords" {onback} backLabel="Back to identity" />

  <p class="lede">
    Sign in to the official Bluesky app — and other apps that ask for a password — without
    ever exposing your keys. Each app password is a separate, revocable credential.
  </p>

  <div class="scope-card">
    <p class="scope-row scope-row--can">
      <span class="scope-ic" aria-hidden="true">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5L20 7"/></svg>
      </span>
      An app signed in with one can post, like, follow, and browse as you.
    </p>
    <p class="scope-row scope-row--cant">
      <span class="scope-ic" aria-hidden="true">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
      </span>
      It can never touch your identity, keys, account settings, agents, or other app
      passwords — and it can’t recover or take over the account.
    </p>
    <p class="scope-row scope-row--cant">
      <span class="scope-ic" aria-hidden="true">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.5 5.5 13 13"/></svg>
      </span>
      Direct messages stay off unless you allow them below.
    </p>
  </div>

  {#if loading}
    <div class="loading">
      {#each [0, 1] as i (i)}
        <SkeletonCard />
      {/each}
    </div>
  {:else if locked}
    <div class="notice notice--locked">
      <p class="notice-text notice-text--ink">
        This identity is locked. Unlock it with your device key to manage app passwords.
      </p>
      <Button onclick={unlockAndReload}>Unlock</Button>
    </div>
  {:else if loadError}
    <div class="notice" role="alert">
      <p class="notice-text">{loadError}</p>
      <Button variant="secondary" onclick={load}>Try again</Button>
    </div>
  {:else}
    {#if created}
      <div class="reveal" role="status">
        <p class="reveal-title">“{created.name}” is ready</p>
        <p class="reveal-sub">
          Use your handle and this password in the Bluesky app’s sign-in screen. This is the
          only time it will be shown — the wallet doesn’t keep a copy.
        </p>
        <div class="reveal-row">
          <code class="reveal-secret">{created.password}</code>
          <button class="copy" onclick={copySecret}>
            {copied ? 'Copied!' : copyFailed ? 'Failed' : 'Copy'}
          </button>
        </div>
        {#if copyFailed}
          <p class="reveal-copy-error" role="alert">
            Copy failed — press and hold the password to select and copy it manually.
          </p>
        {/if}
        {#if created.privileged}
          <p class="reveal-priv">This password can also access your direct messages.</p>
        {/if}
        <Button variant="secondary" onclick={() => (created = null)}>Done — I saved it</Button>
      </div>
    {:else}
      <div class="form">
        <TextField
          aria-label="App password name"
          placeholder="Name — e.g. Bluesky on my iPhone"
          bind:value={name}
          error={createError ?? undefined}
          oninput={() => (createError = null)}
        />
        <label class="priv">
          <input type="checkbox" bind:checked={privileged} />
          <span class="priv-body">
            <span class="priv-t">Allow direct messages</span>
            <span class="priv-s">
              Lets the app read and send your Bluesky DMs. Leave off unless you need chat.
            </span>
          </span>
        </label>
        <Button onclick={doCreate} disabled={!nameValid || creating}>
          {#if creating}<Spinner size={16} /> Creating…{:else}Create app password{/if}
        </Button>
      </div>
    {/if}

    <p class="section-label">Active app passwords</p>
    {#if passwords.length === 0}
      <p class="empty">
        None yet. Create one above, then sign in to the Bluesky app with your handle and
        that password.
      </p>
    {:else}
      <div class="cards">
        {#each passwords as entry (entry.name)}
          <div class="card">
            <div class="row">
              <span class="info">
                <span class="name truncate">{entry.name}</span>
                <span class="meta-line">
                  <span class="when">Created {formatTimestamp(entry.createdAt)}</span>
                  {#if entry.privileged}
                    <span class="badge badge--priv">
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                      DMs allowed
                    </span>
                  {/if}
                </span>
              </span>
              {#if confirmingRevoke !== entry.name}
                <button
                  class="revoke-link"
                  onclick={() => {
                    confirmingRevoke = entry.name;
                    revokeError = null;
                  }}
                >
                  Revoke
                </button>
              {/if}
            </div>
            {#if confirmingRevoke === entry.name}
              <div class="confirm">
                <p class="confirm-text">
                  Any app signed in with “{entry.name}” is signed out immediately. This cannot
                  be undone.
                </p>
                {#if revokeError}<p class="confirm-error" role="alert">{revokeError}</p>{/if}
                <div class="confirm-actions">
                  <Button onclick={() => doRevoke(entry.name)} disabled={revoking}>
                    {#if revoking}<Spinner size={16} /> Revoking…{:else}Revoke with biometrics{/if}
                  </Button>
                  <Button
                    variant="secondary"
                    onclick={() => {
                      confirmingRevoke = null;
                      revokeError = null;
                    }}
                    disabled={revoking}
                  >
                    Keep it
                  </Button>
                </div>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
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

  .truncate {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .lede {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  /* What the credential can and cannot do — text + icon, never color alone. */
  .scope-card {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .scope-row {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: var(--text-label);
    color: var(--color-ink);
    line-height: 1.45;
    margin: 0;
  }
  .scope-ic {
    flex-shrink: 0;
    margin-top: 2px;
  }
  .scope-row--can .scope-ic {
    color: var(--color-safe);
  }
  .scope-row--cant .scope-ic {
    color: var(--color-muted);
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .priv {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    cursor: pointer;
  }
  .priv input {
    margin-top: 3px;
    accent-color: var(--color-primary);
    width: 18px;
    height: 18px;
    flex-shrink: 0;
  }
  .priv-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .priv-t {
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .priv-s {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.45;
  }

  /* One-time secret reveal. */
  .reveal {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-seal-tint);
    border: 1px solid var(--color-primary);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .reveal-title {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    overflow-wrap: anywhere;
    margin: 0;
  }
  .reveal-sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }
  .reveal-row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .reveal-secret {
    flex: 1;
    font-family: var(--font-mono);
    font-size: var(--text-title);
    letter-spacing: 0.04em;
    color: var(--color-ink);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    overflow-wrap: anywhere;
    user-select: all;
    -webkit-user-select: all;
  }
  .copy {
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    min-height: 44px;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    cursor: pointer;
    flex-shrink: 0;
  }
  .reveal-copy-error {
    font-size: var(--text-label);
    color: var(--color-critical);
    line-height: 1.45;
    margin: 0;
  }
  .reveal-priv {
    font-size: var(--text-label);
    color: var(--color-warning);
    margin: 0;
  }

  .section-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: var(--space-xs) 0 0;
  }

  .empty {
    font-size: var(--text-body);
    color: var(--color-muted);
    line-height: 1.5;
    margin: 0;
  }

  .cards {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: 15px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .name {
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .meta-line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .when {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: var(--radius-full);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    white-space: nowrap;
  }
  .badge--priv {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .revoke-link {
    background: none;
    border: none;
    padding: var(--space-sm) var(--space-xs);
    min-height: 44px;
    min-width: 44px;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-critical);
    cursor: pointer;
    flex-shrink: 0;
  }

  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    border-top: 1px solid var(--color-line);
    padding-top: var(--space-sm);
  }
  .confirm-text {
    font-size: var(--text-label);
    color: var(--color-critical);
    line-height: 1.5;
    overflow-wrap: anywhere;
    margin: 0;
  }
  .confirm-error {
    font-size: var(--text-label);
    color: var(--color-critical);
    margin: 0;
  }
  .confirm-actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .notice {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-md);
    background: var(--color-critical-surface);
    border-radius: var(--radius-lg);
    padding: var(--space-lg);
    text-align: center;
  }
  .notice--locked {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
  }
  .notice-text {
    font-size: var(--text-body);
    color: var(--color-critical);
    margin: 0;
  }
  .notice-text--ink {
    color: var(--color-ink);
  }

  .loading {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
</style>
