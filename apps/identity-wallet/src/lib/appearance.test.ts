import { describe, it, expect } from 'vitest';
import { normalizePreference, toColorScheme } from './appearance';

describe('normalizePreference', () => {
  it('passes through the two override values', () => {
    expect(normalizePreference('light')).toBe('light');
    expect(normalizePreference('dark')).toBe('dark');
  });

  it('maps system to system', () => {
    expect(normalizePreference('system')).toBe('system');
  });

  it('coerces anything unrecognized to system', () => {
    expect(normalizePreference(null)).toBe('system');
    expect(normalizePreference(undefined)).toBe('system');
    expect(normalizePreference('')).toBe('system');
    expect(normalizePreference('sepia')).toBe('system');
    expect(normalizePreference('DARK')).toBe('system');
    expect(normalizePreference(42)).toBe('system');
  });
});

describe('toColorScheme', () => {
  it('maps system to the empty override (follow the system)', () => {
    expect(toColorScheme('system')).toBe('');
  });

  it('maps light and dark to themselves', () => {
    expect(toColorScheme('light')).toBe('light');
    expect(toColorScheme('dark')).toBe('dark');
  });
});
