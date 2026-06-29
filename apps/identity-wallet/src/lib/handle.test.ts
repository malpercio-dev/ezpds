import { describe, it, expect } from 'vitest';
import { composeHandle, isValidLabel } from './handle';

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
});
