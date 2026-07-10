import { describe, expect, it } from 'vitest';

import { formatBytes, formatPct, quotaBar } from './format';

describe('formatBytes', () => {
  it('renders sub-KiB counts as raw bytes with no parenthetical', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1023)).toBe('1023 B');
  });

  it('keeps the exact byte count alongside the rounded binary figure', () => {
    expect(formatBytes(2048)).toBe('2.0 KiB (2048 B)');
    expect(formatBytes(1073741824)).toBe('1.0 GiB (1073741824 B)');
  });

  it('uses one decimal under 10 of a unit and none above, like ls -lh', () => {
    expect(formatBytes(9625)).toBe('9.4 KiB (9625 B)');
    expect(formatBytes(500 * 1024)).toBe('500 KiB (512000 B)');
  });

  it('caps at TiB rather than inventing larger units', () => {
    expect(formatBytes(1024 ** 5)).toBe(`1024 TiB (${1024 ** 5} B)`);
  });
});

describe('formatPct', () => {
  it('renders two decimals', () => {
    expect(formatPct(12.345)).toBe('12.35%');
    expect(formatPct(0)).toBe('0.00%');
  });

  it('never rounds a nonzero usage down to 0.00%', () => {
    expect(formatPct(0.0001)).toBe('<0.01%');
  });
});

// Invariant tests: they pin the readout's *contract* (shape, literal % text, the ≥90%
// glyph, monotonic fill, clamping) while leaving the fill-rounding choice — floor vs
// round — to the implementation.
describe('quotaBar', () => {
  const cells = (bar: string): string => {
    const match = /^\[([▓░]{5})\] /.exec(bar);
    expect(match, `"${bar}" must start with a 5-cell [▓░] meter`).not.toBeNull();
    return match![1];
  };
  const filled = (bar: string): number => cells(bar).split('▓').length - 1;

  it('is always a 5-cell meter followed by the literal formatPct text', () => {
    for (const pct of [0, 0.004, 12.5, 42, 89.99, 90, 100]) {
      const bar = quotaBar(pct);
      cells(bar);
      expect(bar).toContain(formatPct(pct));
    }
  });

  it('fills no cells at 0% and every cell at 100%', () => {
    expect(filled(quotaBar(0))).toBe(0);
    expect(filled(quotaBar(100))).toBe(5);
  });

  it('fill is monotonic in the percentage', () => {
    let prev = 0;
    for (let pct = 0; pct <= 100; pct += 5) {
      const now = filled(quotaBar(pct));
      expect(now).toBeGreaterThanOrEqual(prev);
      prev = now;
    }
  });

  it('appends the " !" marker exactly at ≥90%', () => {
    expect(quotaBar(89.99).endsWith(' !')).toBe(false);
    expect(quotaBar(90).endsWith(' !')).toBe(true);
    expect(quotaBar(100).endsWith(' !')).toBe(true);
  });

  it('clamps the meter for out-of-range input while the text stays literal', () => {
    expect(filled(quotaBar(-5))).toBe(0);
    const over = quotaBar(120);
    expect(filled(over)).toBe(5);
    expect(over).toContain('120.00%');
    expect(over.endsWith(' !')).toBe(true);
  });
});
