<script lang="ts">
  import type { Snippet } from 'svelte';
  import { formatCountdown, type Urgency } from '$lib/deadline';
  import { panelLabel } from '$lib/identity-status';

  // The large-format sibling of `UrgencyBadge`: the same four-state safe/warning/critical/
  // expired vocabulary, the same colour + icon + label + position rule (status is never
  // carried by colour alone), rendered as the panel that opens an identity screen.
  //
  // This is the first thing the screen shows, before any menu — state leads, actions follow,
  // so the screen answers "am I okay?" before "what can I do?".
  let {
    urgency,
    verified = true,
    label: labelOverride,
    detail,
    deadline = null,
    now = Date.now(),
    action,
    disclosure,
  }: {
    urgency: Urgency;
    /**
     * Whether the state rests on a reading the wallet actually took. False only in the
     * `safe` state, where an unreachable directory means there is no fresh evidence — the
     * panel drops the green and says "Not checked" rather than asserting an all-clear it
     * did not verify.
     */
    verified?: boolean;
    /**
     * Override the state word. Only the app-level Protection surface passes this: it states
     * the same four states over a *set* of identities ("All identities secure"), which the
     * per-identity vocabulary cannot say. The four states, their colours, and their icons
     * are unchanged — this is the same panel speaking about a wallet instead of a seal, not
     * a fifth state or an escape hatch for arbitrary copy.
     */
    label?: string;
    /** The supporting line under the state word: what is true, or what to do about it. */
    detail: string;
    /** The recovery deadline to count down to; rendered only in the alarm states. */
    deadline?: Date | null;
    /** Millisecond clock, threaded in so the countdown ticks from the owner's timer. */
    now?: number;
    /** The one primary affordance the state earns (e.g. "Review & override"). */
    action?: Snippet;
    /** A quiet secondary disclosure hanging off the panel (the security checkup). */
    disclosure?: Snippet;
  } = $props();

  let label = $derived(labelOverride ?? panelLabel(urgency, verified));
  // `safe` alone does not earn the verified-green ground: an unchecked identity uses the
  // calm slate of the informational tone, which claims nothing.
  let tone = $derived(urgency === 'safe' && !verified ? 'unverified' : urgency);
</script>

<section class="panel panel--{tone}" aria-label="Identity status">
  <div class="head">
    <span class="ic" aria-hidden="true">
      {#if tone === 'safe'}
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
      {:else if tone === 'unverified'}
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M10 9.5a2.2 2.2 0 0 1 4 1.2c0 1.4-1.9 1.8-1.9 2.8" /><path d="M12 16.5h.01" /></svg>
      {:else if tone === 'warning'}
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
      {:else if tone === 'critical'}
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
      {:else}
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
      {/if}
    </span>
    <div class="head-body">
      <p class="label">{label}</p>
      <p class="detail">{detail}</p>
    </div>
  </div>

  {#if deadline && (urgency === 'critical' || urgency === 'expired')}
    <p class="countdown">{formatCountdown(deadline, now)}</p>
  {/if}

  {#if action}
    <div class="action">{@render action()}</div>
  {/if}

  {#if disclosure}
    <div class="disclosure">{@render disclosure()}</div>
  {/if}
</section>

<style>
  .panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    border-radius: var(--radius-xl);
    padding: var(--space-lg) var(--space-md);
  }
  .head {
    display: flex;
    align-items: center;
    gap: var(--space-md);
  }
  .ic {
    width: var(--size-avatar-sm);
    height: var(--size-avatar-sm);
    border-radius: var(--radius-full);
    background: var(--color-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .head-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-3xs);
    min-width: 0;
  }
  .label {
    font-size: var(--text-headline);
    font-weight: var(--weight-bold);
    letter-spacing: -0.01em;
    margin: 0;
  }
  .detail {
    font-size: var(--text-label);
    margin: 0;
    line-height: 1.45;
  }
  /* The countdown is data, so it wears the mono face — the same treatment the alarm
     screens give a recovery window. Sits below the state, never instead of it. */
  .countdown {
    font-family: var(--font-mono);
    font-size: var(--text-body);
    font-weight: var(--weight-semibold);
    margin: 0;
  }
  .action,
  .disclosure {
    display: flex;
    flex-direction: column;
  }

  /* Verified all-clear: the one place in the wallet green means "we checked and it holds". */
  .panel--safe {
    background: var(--color-safe-surface);
  }
  .panel--safe .ic,
  .panel--safe .label {
    color: var(--color-safe);
  }
  .panel--safe .detail {
    color: var(--color-safe-soft);
  }

  /* No fresh reading: calm slate, claiming nothing. Deliberately not green (which would
     assert a check that failed) and not amber (nothing is wrong with the identity). */
  .panel--unverified {
    background: var(--color-info-surface);
  }
  .panel--unverified .ic,
  .panel--unverified .label {
    color: var(--color-info);
  }
  .panel--unverified .detail {
    color: var(--color-info);
  }

  .panel--warning {
    background: var(--color-warning-surface);
  }
  .panel--warning .ic,
  .panel--warning .label {
    color: var(--color-warning);
  }
  .panel--warning .detail {
    color: var(--color-warning-soft);
  }

  .panel--critical {
    background: var(--color-critical-surface);
  }
  .panel--critical .ic,
  .panel--critical .label,
  .panel--critical .countdown {
    color: var(--color-critical);
  }
  .panel--critical .detail {
    color: var(--color-critical-soft);
  }

  /* Ashen and closed — the moment to act has passed, which is a different fact from
     "act now" and must not share the alarm's colour. */
  .panel--expired {
    background: var(--color-expired-surface);
  }
  .panel--expired .ic,
  .panel--expired .label,
  .panel--expired .countdown {
    color: var(--color-expired);
  }
  .panel--expired .detail {
    color: var(--color-expired);
  }
</style>
