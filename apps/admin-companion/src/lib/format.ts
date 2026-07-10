// Pure display formatting for the terminal-native facts grids.

/**
 * Render a byte count: a scannable binary-unit figure first (KiB/MiB/GiB — matching
 * the relay's GiB-based quota config), with the exact byte count kept alongside so
 * the rounding never hides the literal truth. One decimal under 10 of a unit, none
 * above, like `ls -lh`. Below 1 KiB the raw count IS the figure, so no parenthetical.
 */
export function formatBytes(bytes: number): string {
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = 'B';
  for (const next of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = next;
  }
  const figure = value < 10 ? value.toFixed(1) : Math.round(value).toString();
  return `${figure} ${unit} (${bytes} B)`;
}

/** Quota-used percentage: two decimals, but never round a nonzero usage to "0.00%". */
export function formatPct(pct: number): string {
  if (pct > 0 && pct < 0.01) return '<0.01%';
  return `${pct.toFixed(2)}%`;
}

/**
 * The account list's per-row blob-quota readout: a fixed-width, 5-cell text meter
 * followed by the literal percentage, e.g. `[▓▓░░░] 42.00%`, with a trailing ` !`
 * marker at ≥90% — `[▓▓▓▓▓] 95.10% !`.
 *
 * Deliberately a *text* readout, not a graphical gauge (a scrolling column of gauges
 * is the "chart-soup" anti-reference): the meter is monospace characters so a column
 * of rows aligns and scans, the exact percentage is always carried as text (status is
 * never signalled by shape or color alone — AAA), and the near-capacity warning is a
 * glyph, not a color change.
 *
 * Contract pinned by format.test.ts:
 * - Always `[` + exactly 5 cells (each `▓` or `░`) + `] ` + formatPct(pct).
 * - Fill is monotonic in pct: 0% → all `░`, 100% (and anything above) → all `▓`.
 * - ` !` is appended exactly when pct ≥ 90.
 * - Out-of-range input is clamped: pct < 0 renders as 0%, pct > 100 fills all cells
 *   (formatPct still reports the literal value — the meter clamps, the text doesn't).
 */
export function quotaBar(pct: number): string {
  // Fill rounds DOWN (terminal progress-bar convention): a cell lights only when fully
  // earned, so the meter never overstates how close to quota an account is — the exact
  // percentage alongside carries the mid-cell truth.
  const filled = Math.min(5, Math.max(0, Math.floor(pct / 20)));
  const meter = '▓'.repeat(filled) + '░'.repeat(5 - filled);
  const marker = pct >= 90 ? ' !' : '';
  return `[${meter}] ${formatPct(pct)}${marker}`;
}
