<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { checkIdentityStatus, type IdentityStatus, type UnauthorizedChange } from '$lib/ipc';
  import { extractHandle, extractPdsFromPlcDoc, truncateDid, isDidWeb } from '$lib/did-doc-utils';
  import { hostOf } from '$lib/url';
  import {
    deriveIdentityPanelState,
    formatCheckedAgo,
    isVerified,
    type IdentityPanelState,
  } from '$lib/identity-status';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import StatusPanel from '$lib/components/ui/StatusPanel.svelte';
  import NavRow from '$lib/components/ui/NavRow.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import SecurityCheckup from './SecurityCheckup.svelte';

  // The identity instrument panel. State leads, actions follow: the screen opens with what
  // is true of this identity, and every verb hangs off that. The order below is the whole
  // information architecture — status, then the things a normal week touches, then the exit,
  // then the maintenance door — so a screen that used to be a wall of ten equal buttons now
  // sorts them by how often and in what state a person reaches for each.
  let {
    did,
    didDoc,
    deviceKeyIsRoot,
    deviceKeyUnusable,
    onback,
    onsignin,
    onapppasswords,
    onagents,
    onmoveorrebuild,
    onmanage,
    onalert,
    onrecover,
  }: {
    did: string;
    /** The cached PLC-shaped DID document; `{}` when the cache had nothing for this DID. */
    didDoc: Record<string, unknown>;
    deviceKeyIsRoot: boolean | null;
    /** The Secure Enclave no longer holds this identity's device key. */
    deviceKeyUnusable: boolean;
    onback: () => void;
    /** Approve a sign-in to an app (typed consent code or scanned QR). */
    onsignin: () => void;
    /** App passwords — sign the Bluesky app and other clients into this account. */
    onapppasswords: () => void;
    /** The agents connected to this identity, and what each may do. */
    onagents: () => void;
    /** The exit door: move to another server, or rebuild from backup. */
    onmoveorrebuild: () => void;
    /** The maintenance door: everyday tier, then the advanced vestibule. */
    onmanage: () => void;
    /** Open the alarm's own surface for review and override. */
    onalert: (changes: UnauthorizedChange[]) => void;
    /**
     * Enter the recovery ceremony that restores this device's ability to sign. Withheld for
     * a did:web, which has no rotation keys to rotate a fresh key into and whose remedy is
     * the domain instead.
     */
    onrecover?: () => void;
  } = $props();

  let changes = $state<UnauthorizedChange[]>([]);
  /**
   * Whether plc.directory answered for this identity. Starts false — before the first
   * check completes the wallet genuinely has not verified anything this session, and a
   * panel that opened green and then corrected itself would be asserting an all-clear it
   * had not yet earned.
   */
  let plcVerified = $state(false);
  let checkedAt = $state<number | null>(null);
  let now = $state(Date.now());
  let ticker: ReturnType<typeof setInterval> | null = null;
  let unlisten: UnlistenFn | null = null;
  /**
   * Set synchronously by `onDestroy`, which runs before an async `onMount` can finish.
   * Svelte does not treat an async `onMount`'s return value as a cleanup hook, so a
   * subscription that resolves after teardown has to disarm itself.
   */
  let destroyed = false;

  let handle = $derived(extractHandle(didDoc));
  let pdsUrl = $derived(extractPdsFromPlcDoc(didDoc));
  let isWeb = $derived(isDidWeb(did));

  /** Whether the state rests on a reading the wallet could actually take (see the rule). */
  let verified = $derived(isVerified(did, plcVerified));

  let panel = $derived<IdentityPanelState>(
    deriveIdentityPanelState(changes, deviceKeyUnusable, now)
  );

  /** The supporting line under the state word — what is true, or what to do about it. */
  let detail = $derived.by(() => {
    if (panel.urgency === 'critical') {
      return panel.alertCount === 1
        ? 'Someone changed this identity on the public record without your key.'
        : `${panel.alertCount} changes were made to this identity without your key.`;
    }
    if (panel.urgency === 'expired') {
      return 'The window to reverse the change has closed. Review what happened.';
    }
    if (panel.urgency === 'warning') {
      return "This device's key for this identity is gone. The identity itself is unaffected.";
    }
    if (isWeb) {
      // Tested before the unverified branch, not after: a did:web can never be "checked",
      // so neither a pending nor a failed directory read is a fact about it.
      return 'Held at your own domain. Nothing is out of place.';
    }
    if (!verified) {
      return checkedAt === null && changes.length === 0
        ? 'Checking the public record…'
        : "Couldn't reach the public record to check just now.";
    }
    return `Public record checked ${formatCheckedAgo(checkedAt ?? now, now)}.`;
  });

  /** Fold the monitor's answer for THIS identity out of the all-identities sweep. */
  function absorb(statuses: IdentityStatus[]) {
    const mine = statuses.find((s) => s.did === did);
    if (!mine) return;
    changes = mine.unauthorizedChanges;
    plcVerified = !mine.checkFailed;
    if (!mine.checkFailed) checkedAt = Date.now();
  }

  onMount(async () => {
    checkIdentityStatus()
      .then(absorb)
      .catch((e) => {
        // The panel stays unverified, which is exactly what an unanswered check means.
        console.warn('Identity status check failed:', e);
      });

    // The background sweep can land while this screen is open; the panel must follow it
    // rather than hold the reading it took on entry.
    const off = await listen<IdentityStatus[]>('plc_alert', (event) => {
      if (Array.isArray(event.payload)) absorb(event.payload);
    });
    // The await above can resolve after teardown — this screen unmounts on every identity
    // switch and on every step into a door — and by then `onDestroy` has already run with
    // nothing to release. Disarm the late subscription itself rather than parking it in
    // `unlisten`, where nothing would ever call it again.
    if (destroyed) {
      off();
      return;
    }
    unlisten = off;

    // A minute is the resolution of both readouts the clock feeds: the countdown renders
    // whole minutes, and "checked N min ago" cannot move faster than that.
    ticker = setInterval(() => {
      now = Date.now();
    }, 60_000);
  });

  onDestroy(() => {
    destroyed = true;
    if (ticker !== null) clearInterval(ticker);
    unlisten?.();
  });
</script>

<div class="screen u-screen-lg">
  <ScreenHeader
    title={handle ? '@' + handle : truncateDid(did)}
    onback={onback}
    backLabel="Back to identities"
    truncate
  />

  <StatusPanel urgency={panel.urgency} {verified} {detail} deadline={panel.deadline} {now}>
    {#snippet action()}
      {#if panel.urgency === 'critical' || panel.urgency === 'expired'}
        <Button onclick={() => onalert(changes)}>Review &amp; override</Button>
      {:else if panel.urgency === 'warning' && onrecover}
        <Button onclick={onrecover}>Recover this identity</Button>
      {/if}
    {/snippet}

    {#snippet disclosure()}
      {#if panel.urgency === 'safe'}
        <SecurityCheckup {did} {deviceKeyIsRoot} {deviceKeyUnusable} />
      {/if}
    {/snippet}
  </StatusPanel>

  {#if deviceKeyUnusable}
    <!-- The warning panel names the state and offers the remedy; the explanation of WHY a
         restored device arrives without its key — and why the identity is nonetheless fine —
         belongs with it rather than in the DID document, which describes the identity, not
         this device's relationship to it. -->
    <div class="note" role="note">
      {#if isWeb}
        <p class="note-s">
          Its key lived in this device's Secure Enclave, which a backup can never restore —
          so a restored or replaced device arrives without it. <strong>The identity itself is
          unaffected</strong>: it lives at your domain, and control of that domain is what
          defends it. Only this device's ability to act for it is gone.
        </p>
        <p class="note-s">
          There is no recovery ceremony to run for a domain identity. To give this device a
          working key again: remove the identity here (which only forgets it locally — it
          publishes nothing), import it again to issue a fresh key, then publish that key in
          your domain's <code>did.json</code>.
        </p>
      {:else}
        <p class="note-s">
          Its key lived in this device's Secure Enclave, which a backup can never restore —
          so a restored or replaced device arrives without it. <strong>The identity itself is
          unaffected</strong>: it is intact on the public record, and your recovery shares still
          control it. Only this device's ability to act for it is gone, which is why changing
          the handle, moving servers, and repairing the endpoint are unavailable here.
          Recovering issues a new key on this device and installs it as the identity's
          deciding key.
        </p>
      {/if}
    </div>
  {/if}

  <section class="zone u-stack-xs">
    <h2 class="zone-label">Use</h2>
    <NavRow title="Sign in to an app" subtitle="Approve a sign-in with a code or QR" onclick={onsignin}>
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" /><path d="m10 17 5-5-5-5" /><path d="M15 12H3" /></svg>
      {/snippet}
    </NavRow>
    <NavRow
      title="Sign in to Bluesky"
      subtitle="App passwords for Bluesky and other clients"
      onclick={onapppasswords}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.6 10.6a6 6 0 1 0-3.2 3.2L11 15.5l2 .3.3 2L15 19l1.5 1.5 2.5-2.5-6.4-7.4z" /><circle cx="8" cy="8" r="1.2" /></svg>
      {/snippet}
    </NavRow>
    <NavRow title="My agents" subtitle="What you've connected, and what it can do" onclick={onagents}>
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="8" width="16" height="12" rx="2" /><path d="M12 4v4" /><circle cx="12" cy="3" r="1" /><path d="M9 13h.01" /><path d="M15 13h.01" /><path d="M9.5 16.5h5" /></svg>
      {/snippet}
    </NavRow>
  </section>

  <section class="zone u-stack-xs">
    <!-- Two doors sit at this depth by explicit design decision: a credible exit is the
         product's central promise, so it gets its own visible entry rather than being
         filed as maintenance. -->
    <NavRow
      tone="door"
      title="Move or rebuild"
      subtitle={pdsUrl
        ? `Currently hosted on ${hostOf(pdsUrl)}`
        : 'Move to another server, or rebuild from your backup'}
      onclick={onmoveorrebuild}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="7" rx="2" /><rect x="2" y="14" width="20" height="7" rx="2" /><path d="M6 6.5h.01" /><path d="M6 17.5h.01" /></svg>
      {/snippet}
    </NavRow>
    <NavRow
      tone="door"
      title="Manage identity"
      subtitle="Handle, backups, DID document, advanced tools"
      onclick={onmanage}
    >
      {#snippet icon()}
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z" /><path d="M14.5 6.5 17.5 9.5" /></svg>
      {/snippet}
    </NavRow>
  </section>
</div>

<style>
  .note {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .note-s {
    font-size: var(--text-label);
    color: var(--color-ink-soft);
    margin: 0;
    line-height: 1.5;
  }
  .note-s code {
    font-family: var(--font-mono);
    font-size: 0.92em;
    background: var(--color-surface-sunk);
    padding: 1px 4px;
    border-radius: var(--radius-sm);
  }

  .zone-label {
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    letter-spacing: 0.01em;
    margin: 0 0 var(--space-3xs);
  }
</style>
