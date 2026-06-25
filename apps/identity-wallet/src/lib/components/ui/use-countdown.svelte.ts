import { onMount, onDestroy } from 'svelte';

// Reactive wall-clock `now` that ticks on a fixed interval, with setInterval
// started on mount and cleared on destroy. Used by countdown UIs that re-derive
// urgency/deadline displays as time passes. Caller picks the tick interval.
export function useCountdown(intervalMs: number) {
  const state = $state({ now: Date.now() });
  let timer: ReturnType<typeof setInterval> | null = null;

  onMount(() => {
    timer = setInterval(() => {
      state.now = Date.now();
    }, intervalMs);
  });

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  return state;
}
