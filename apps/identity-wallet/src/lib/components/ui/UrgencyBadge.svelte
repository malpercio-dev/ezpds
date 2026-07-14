<script lang="ts">
  import { formatCountdown, type Urgency } from '$lib/deadline';

  let {
    urgency,
    deadline,
    now,
  }: {
    urgency: Urgency;
    deadline: Date;
    now: number;
  } = $props();
</script>

<span class="badge badge--{urgency}">
  <span class="ic" aria-hidden="true">
    {#if urgency === 'safe'}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
    {:else if urgency === 'warning'}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" /></svg>
    {:else if urgency === 'critical'}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
    {:else}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
    {/if}
  </span>
  {formatCountdown(deadline, now)}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 11px;
    border-radius: var(--radius-md);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    white-space: nowrap;
    width: fit-content;
  }
  .ic {
    display: inline-flex;
  }
  /* safe = calm slate, NOT green: an active attack is never "all clear", only "time remaining". */
  .badge--safe {
    background: var(--color-info-surface);
    color: var(--color-info);
  }
  .badge--warning {
    background: var(--color-warning-surface);
    color: var(--color-warning);
  }
  .badge--critical {
    background: var(--color-critical-surface);
    color: var(--color-critical);
  }
  .badge--expired {
    background: var(--color-expired-surface);
    color: var(--color-expired);
  }
</style>
