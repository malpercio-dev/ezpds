import { describe, expect, it } from 'vitest';

import { formatBytes, formatPct } from './format';

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
