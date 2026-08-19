import { describe, it, expect } from 'vitest';
import {
  composeHandle,
  isValidHandle,
  isValidLabel,
  normalizeDomain,
  normalizeHandle,
} from './handle';

describe('handle utils', () => {
  describe('composeHandle', () => {
    it('joins a label and domain into a full handle', () => {
      expect(composeHandle('alice', 'ezpds.com')).toBe('alice.ezpds.com');
    });

    it('trims surrounding whitespace from the label', () => {
      expect(composeHandle('  alice  ', 'ezpds.com')).toBe('alice.ezpds.com');
    });

    it('preserves a multi-label domain', () => {
      expect(composeHandle('bob', 'users.ezpds.com')).toBe('bob.users.ezpds.com');
    });

    // describeServer may serve either shape; a doubled separator would be an empty DNS
    // label, which the server rejects as structurally invalid.
    it('does not double the separator when the domain carries the leading dot', () => {
      expect(composeHandle('alice', '.ezpds.com')).toBe('alice.ezpds.com');
      expect(composeHandle('alice', '.bsky.social')).toBe('alice.bsky.social');
    });
  });

  describe('normalizeDomain', () => {
    it('strips a leading dot', () => {
      expect(normalizeDomain('.ezpds.com')).toBe('ezpds.com');
    });

    it('leaves a dotless domain alone', () => {
      expect(normalizeDomain('ezpds.com')).toBe('ezpds.com');
    });

    it('never strips an interior or trailing dot', () => {
      expect(normalizeDomain('users.ezpds.com')).toBe('users.ezpds.com');
      expect(normalizeDomain('.users.ezpds.com')).toBe('users.ezpds.com');
    });
  });

  describe('isValidLabel', () => {
    it('accepts a simple alphanumeric label', () => {
      expect(isValidLabel('alice')).toBe(true);
      expect(isValidLabel('a1')).toBe(true);
    });

    it('accepts an internal hyphen', () => {
      expect(isValidLabel('al-ice')).toBe(true);
    });

    it('rejects an empty label', () => {
      expect(isValidLabel('')).toBe(false);
      expect(isValidLabel('   ')).toBe(false);
    });

    it('rejects a label containing a dot (that would create extra labels)', () => {
      expect(isValidLabel('alice.bob')).toBe(false);
    });

    it('rejects leading or trailing hyphens', () => {
      expect(isValidLabel('-alice')).toBe(false);
      expect(isValidLabel('alice-')).toBe(false);
    });

    it('rejects underscores, spaces, and non-ascii characters', () => {
      expect(isValidLabel('ali_ce')).toBe(false);
      expect(isValidLabel('ali ce')).toBe(false);
      expect(isValidLabel('älice')).toBe(false);
    });

    it('enforces the RFC 1035 63-character label limit', () => {
      expect(isValidLabel('a'.repeat(63))).toBe(true);
      expect(isValidLabel('a'.repeat(64))).toBe(false);
    });
  });

  describe('isValidHandle', () => {
    it('accepts a two-label handle and an apex domain', () => {
      expect(isValidHandle('alice.example.com')).toBe(true);
      expect(isValidHandle('example.com')).toBe(true);
      expect(isValidHandle('obsign.org')).toBe(true);
    });

    it('tolerates surrounding whitespace and a leading @', () => {
      expect(isValidHandle('  alice.example.com  ')).toBe(true);
      expect(isValidHandle('@obsign.org')).toBe(true);
    });

    it('rejects a bare single label (the handle.invalid bug)', () => {
      expect(isValidHandle('alice')).toBe(false);
    });

    it('rejects empty and interior-whitespace input', () => {
      expect(isValidHandle('')).toBe(false);
      expect(isValidHandle('ali ce.example.com')).toBe(false);
    });

    it('rejects empty labels', () => {
      expect(isValidHandle('.example.com')).toBe(false);
      expect(isValidHandle('alice..com')).toBe(false);
      expect(isValidHandle('alice.')).toBe(false);
    });

    it('rejects invalid label characters and hyphen placement', () => {
      expect(isValidHandle('ali_ce.example.com')).toBe(false);
      expect(isValidHandle('-alice.example.com')).toBe(false);
      expect(isValidHandle('alice-.example.com')).toBe(false);
    });

    it('rejects a final label starting with a digit (never IPv4-shaped)', () => {
      expect(isValidHandle('alice.123')).toBe(false);
      expect(isValidHandle('123.example.com')).toBe(true);
    });

    it('enforces the 253-character total limit', () => {
      const label63 = 'a'.repeat(63);
      // 63*4 + 3 dots = 255 chars: every label valid, total too long.
      expect(isValidHandle([label63, label63, label63, label63].join('.'))).toBe(false);
    });
  });

  describe('normalizeHandle', () => {
    it('trims, strips a leading @, and lowercases', () => {
      expect(normalizeHandle('  @Obsign.ORG ')).toBe('obsign.org');
      expect(normalizeHandle('alice.example.com')).toBe('alice.example.com');
    });
  });
});
