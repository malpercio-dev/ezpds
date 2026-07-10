// Pure display formatting for the Status screen's health readouts (Functional Core).
//
// The relay's `GET /v1/admin/health` reports literal facts only — no ok/warn verdicts —
// so every presentation judgment (how an age reads, when staleness is worth a marker)
// lives here, where it is unit-testable, not in the API shape.

import type { SweepRun } from '$lib/ipc';

/**
 * Render a duration in seconds as a compact `uptime`-style figure: `47s` under a
 * minute, then the two largest units — `12m 3s`, `4h 12m`, `3d 4h`. Literal and
 * scannable; no rounding a day up to "1 week".
 */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  const units: [string, number][] = [
    ['d', 86_400],
    ['h', 3_600],
    ['m', 60],
    ['s', 1],
  ];
  const parts: string[] = [];
  let rest = s;
  for (const [name, size] of units) {
    const count = Math.floor(rest / size);
    if (count > 0 || parts.length > 0) {
      parts.push(`${count}${name}`);
      rest -= count * size;
    }
    if (parts.length === 2) break;
  }
  return parts.join(' ');
}

/**
 * The firehose backfill window: how far back a reconnecting subscriber's cursor still
 * replays exactly. `null` means the event log is empty — say so literally rather than
 * rendering a zero that would read as "no window".
 */
export function formatBackfillWindow(seconds: number | null): string {
  if (seconds === null) return 'empty log';
  return formatDuration(seconds);
}

/**
 * One background sweep's row on the Status screen.
 *
 * `run` is the sweep's last completed pass (`null` until its first pass after boot —
 * each sweep first runs one full interval after startup). A failed pass records
 * nothing, so a `completedAt` that keeps ageing IS the "sweeps are failing" signal —
 * this line is where that signal becomes visible to the operator.
 *
 * `nowSeconds` is the current unix time, passed in so the function stays pure.
 *
 * Contract (pinned by health.test.ts):
 * - Returns a single monospace-friendly line; status is carried by text/glyphs,
 *   never color (AAA).
 * - Must distinguish "never ran yet" from "ran, swept nothing" — a quiet sweep is
 *   healthy, a missing one may not be: `null` → `not yet run`, a completed pass →
 *   `<age> ago · swept <n>` (`4m ago · swept 7`; `swept 0` stays visible).
 * - Ages ≥ 24h earn a trailing ` !` (quotaBar's glyph-not-color convention). The
 *   relay doesn't report sweep intervals — prod sweeps run on minutes-to-hours
 *   cadences, so a full day without a completed pass is worth a marker on any of
 *   them, while never false-flagging a slow-but-healthy daily-ish sweep.
 */
export function sweepLine(run: SweepRun | null, nowSeconds: number): string {
  if (run === null) return 'not yet run';
  const age = Math.max(0, nowSeconds - run.completedAt);
  const stale = age >= 86_400 ? ' !' : '';
  return `${formatDuration(age)} ago · swept ${run.swept}${stale}`;
}
