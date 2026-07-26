// Pure display formatting for the Status screen's health readouts (Functional Core).
//
// The relay's `GET /v1/admin/health` reports literal facts only — no ok/warn verdicts —
// so every presentation judgment (how an age reads, when staleness is worth a marker)
// lives here, where it is unit-testable, not in the API shape.

import type { SweepRun } from '$lib/ipc';
import { formatBytes } from '$lib/format';

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
 * each sweep first runs one full interval after startup).
 *
 * `nowSeconds` is the current unix time, passed in so the function stays pure.
 *
 * A sweep reports two INDEPENDENT faults, and the operator's response to each differs,
 * so the line must let them be told apart:
 * - **stale** — a pass that fails outright records nothing, so a `completedAt` that
 *   keeps ageing means passes are not completing at all. The sweep is dead; go look at
 *   the server.
 * - **failed** — a fresh `completedAt` carrying `errors > 0` means the pass DID run and
 *   deliberately skipped part of its work. For blob GC that is an account whose
 *   reconcile failed: it is excluded from collection and leaks disk until the fault is
 *   fixed. One broken subject, on an otherwise living sweep; go fix that subject.
 *
 * Contract (pinned by health.test.ts):
 * - Returns a single monospace-friendly line; status is carried by text/glyphs,
 *   never color (AAA).
 * - Must distinguish "never ran yet" from "ran, swept nothing" — a quiet sweep is
 *   healthy, a missing one may not be: `null` → `not yet run`, a completed pass →
 *   `<age> ago · swept <n>` (`4m 0s ago · swept 7`; `swept 0` stays visible).
 * - Each fault appends its own NAMED segment, and a single trailing ` !` marks the line
 *   as wanting attention (quotaBar's glyph-not-color convention). The names are what
 *   make the two readable apart — an unlabelled marker could not say which fault it
 *   meant on a row that has both, and "swept 7 · failed 1 !" must never be mistaken for
 *   a louder version of "stale".
 * - `errors` is a count of broken subjects, not a magnitude — the relay counts failed
 *   operations, not the work they cost — so it is reported as a bare figure with no
 *   severity dressing.
 * - Staleness threshold is 24h. The relay doesn't report sweep intervals — prod sweeps
 *   run on minutes-to-hours cadences, so a full day without a completed pass is worth a
 *   marker on any of them, while never false-flagging a slow-but-healthy daily-ish
 *   sweep. `errors` needs no threshold: one skipped subject is already worth saying.
 */
export function sweepLine(run: SweepRun | null, nowSeconds: number): string {
  if (run === null) return 'not yet run';
  const age = Math.max(0, nowSeconds - run.completedAt);
  const parts = [`${formatDuration(age)} ago`, `swept ${run.swept}`];
  if (run.errors > 0) parts.push(`failed ${run.errors}`);
  if (age >= 86_400) parts.push('stale');
  const attention = run.errors > 0 || age >= 86_400 ? ' !' : '';
  return `${parts.join(' · ')}${attention}`;
}

/** The Storage panel's unowned-blob readout: a fact line plus whether it wants attention. */
export interface UnownedBlobReadout {
  /** The monospace value for the fact sheet. */
  line: string;
  /**
   * True only for a *reported*, standing unowned population. False for both "none" and
   * "not reported" — an unanswerable question is not an alarm, and raising one on every
   * older relay would train the operator to dismiss the row that matters.
   */
  alarm: boolean;
}

/**
 * Stored blob rows that no account claims — the Status screen's one genuinely alertable
 * storage figure, and the only one here that carries a verdict.
 *
 * Why it needs no threshold: GC deletes a physical blob row together with its last owner,
 * so a row is unowned only in the window between two statements. ~0 is therefore the real
 * baseline, not a tuned target, and any standing figure means the same thing — the bytes
 * survived and the ownership rows did not. That is strictly more sensitive than the
 * `blobGc` sweep line beside it: staleness can only report a sweep that stopped, while
 * this fires with the sweep running exactly on schedule, which is how a real loss once
 * stayed invisible for six hours.
 *
 * Contract (pinned by health.test.ts):
 * - Three outcomes, never collapsed: `not reported` (relay predates the field — `null`),
 *   `none` (a real, reported zero), and a populated line.
 * - `null` NEVER renders as `none`. A reported zero is this readout's all-clear; an older
 *   relay has cleared nothing, it simply cannot see the condition.
 * - A populated line names the condition in words and ends with the ` !` attention glyph
 *   (`sweepLine`/`quotaBar`'s convention) — status is text + glyph + position, never color.
 */
export function unownedBlobLine(
  count: number | null,
  bytes: number | null,
): UnownedBlobReadout {
  // Either half missing means the relay didn't report the pair; a half-answer is no answer.
  if (count === null || bytes === null) return { line: 'not reported', alarm: false };
  if (count <= 0) return { line: 'none', alarm: false };
  return {
    line: `${count} · ${formatBytes(bytes)} · ownership lost !`,
    alarm: true,
  };
}
