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
