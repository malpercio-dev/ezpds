import { describe, expect, it } from 'vitest';

import {
  didWebHostingLine,
  formatBytes,
  formatPct,
  quotaBar,
  uploadedBlobsLine,
} from './format';

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

describe('uploadedBlobsLine', () => {
  it('reports the uploader figures as a plain second reading', () => {
    expect(uploadedBlobsLine(5, 4096)).toBe('5 · 4.0 KiB (4096 B)');
  });

  // A reported zero is a real reading — "the physical rows naming this uploader are
  // gone" — and reads very differently beside a nonzero owned count.
  it('renders a reported zero literally rather than hiding it', () => {
    expect(uploadedBlobsLine(0, 0)).toBe('0 · 0 B');
  });

  // The degradation posture: an older relay must read as unanswered, not as zero.
  it('says "not reported" when the relay predates the field', () => {
    expect(uploadedBlobsLine(null, null)).toBe('not reported');
    expect(uploadedBlobsLine(null, 4096)).toBe('not reported');
    expect(uploadedBlobsLine(5, null)).toBe('not reported');
  });

  // This is a second reading, not a fault channel: sharing makes divergence benign in
  // both directions, so nothing here may carry an attention marker.
  it('never marks a divergence from the owned figures as a fault', () => {
    expect(uploadedBlobsLine(0, 0)).not.toContain('!');
    expect(uploadedBlobsLine(9000, 9_000_000)).not.toContain('!');
    expect(uploadedBlobsLine(null, null)).not.toContain('!');
  });
});

describe('didWebHostingLine', () => {
  it('states both hosting answers for a did:web account', () => {
    expect(didWebHostingLine('did:web:alice.example', true)).toBe('hosting: served here');
    expect(didWebHostingLine('did:web:alice.example', false)).toBe('hosting: not served here');
  });

  // The question does not arise for did:plc — its document lives on plc.directory — and
  // answering it on every row would bury the rows where the answer means something.
  it('stays silent for a did:plc account, whatever the flag says', () => {
    expect(didWebHostingLine('did:plc:abc123', false)).toBeNull();
    expect(didWebHostingLine('did:plc:abc123', null)).toBeNull();
    expect(didWebHostingLine('did:plc:abc123', true)).toBeNull();
  });

  // The flag exists to separate "not hosted" from "broken"; guessing `false` for an
  // older relay would answer that question wrongly with full confidence.
  it('says "not reported" rather than guessing when the relay omits the flag', () => {
    expect(didWebHostingLine('did:web:alice.example', null)).toBe('hosting: not reported');
  });
});
