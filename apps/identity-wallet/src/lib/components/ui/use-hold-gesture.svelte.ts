// Press-and-hold-to-confirm gesture: a requestAnimationFrame loop fills `progress`
// from 0 to 1 over `durationMs`, firing `oncomplete` when full. Wire the returned
// `start`/`end` to pointerdown and pointerup/pointerleave/pointercancel; `end`
// cancels the in-flight frame and resets progress, so releasing (or the pointer
// leaving / being cancelled) before completion aborts cleanly.
//
// `canStart` gates a fresh hold; `canEnd` gates the cancel path (some callers only
// allow cancellation while in their "ready" phase). Both default to always-true.
export function useHoldGesture(opts: {
  durationMs: number;
  oncomplete: () => void;
  canStart: () => boolean;
  canEnd?: () => boolean;
}) {
  const state = $state({ progress: 0 });
  let raf: number | null = null;
  let startTs: number | null = null;

  function frame(now: number) {
    if (startTs === null) startTs = now;
    state.progress = Math.min(1, (now - startTs) / opts.durationMs);
    if (state.progress >= 1) {
      raf = null;
      startTs = null;
      opts.oncomplete();
      return;
    }
    raf = requestAnimationFrame(frame);
  }

  function start() {
    if (!opts.canStart()) return;
    startTs = null;
    raf = requestAnimationFrame(frame);
  }

  function end() {
    if (opts.canEnd && !opts.canEnd()) return;
    if (raf === null) return;
    cancelAnimationFrame(raf);
    raf = null;
    startTs = null;
    state.progress = 0;
  }

  return { state, start, end };
}
