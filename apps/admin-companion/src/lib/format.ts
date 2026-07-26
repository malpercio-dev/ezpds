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

/**
 * Shorten a long identifier for a single-line row with an EXPLICIT ellipsis —
 * `did:key:zDnae…aH2g` — keeping the method prefix and a tail so it stays
 * recognizable. The visible `…` is the Literal-Truth rule's alternative to
 * silent CSS clipping; the full value always lives one tap away in the row's
 * expanded panel or detail screen.
 */
export function shortenId(id: string): string {
  if (id.length <= 24) return id;
  return `${id.slice(0, 14)}…${id.slice(-4)}`;
}

/** Quota-used percentage: two decimals, but never round a nonzero usage to "0.00%". */
export function formatPct(pct: number): string {
  if (pct > 0 && pct < 0.01) return '<0.01%';
  return `${pct.toFixed(2)}%`;
}

/**
 * The account-detail panel's uploader reading: the physical blob rows naming this account
 * as their first uploader, beside the ownership figures the rest of the panel reports.
 *
 * Deliberately verdict-free — this is a *second reading*, not a warning. Blobs are
 * content-addressed and shared, so owned-not-uploaded and uploaded-not-owned both happen
 * in ordinary operation; a badge on that benign divergence would teach the operator to
 * ignore the badge. The two lines sit side by side and the operator draws the conclusion.
 *
 * `null` (either half) is "the relay didn't report this", never zero — a reported zero
 * beside a nonzero owned count is itself a reading worth having.
 */
export function uploadedBlobsLine(count: number | null, bytes: number | null): string {
  if (count === null || bytes === null) return 'not reported';
  return `${count} · ${formatBytes(bytes)}`;
}

/**
 * The account row's did:web hosting indicator: whether Custos serves this account's DID
 * document.
 *
 * Returns `null` — render nothing — for a did:plc account, where the question does not
 * arise: its document lives on plc.directory and the flag is always false. Printing
 * "not served here" on every did:plc row would be true, useless, and would bury the rows
 * where the answer means something.
 *
 * For a did:web account the flag is the whole point: the serve path 404s
 * indistinguishably from an unknown host when hosting is off, so the console is the only
 * place that can tell "not hosted" apart from "broken". `null` hosting therefore has to
 * say "not reported" and not guess.
 */
export function didWebHostingLine(did: string, hosting: boolean | null): string | null {
  if (!did.startsWith('did:web:')) return null;
  if (hosting === null) return 'hosting: not reported';
  return hosting ? 'hosting: served here' : 'hosting: not served here';
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
