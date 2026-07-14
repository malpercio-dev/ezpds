import { describe, it, expect } from 'vitest';
import { hostOf } from './url';

describe('hostOf', () => {
  it('extracts host from an https URL', () => {
    expect(hostOf('https://bsky.social')).toBe('bsky.social');
  });

  it('drops a trailing slash and path', () => {
    expect(hostOf('https://bsky.social/')).toBe('bsky.social');
    expect(hostOf('https://obsign.org/xrpc/_health')).toBe('obsign.org');
  });

  it('retains the port', () => {
    expect(hostOf('http://localhost:8080')).toBe('localhost:8080');
    expect(hostOf('http://10.0.0.41:3000/base')).toBe('10.0.0.41:3000');
  });

  it('falls back to the trimmed raw string for an invalid URL', () => {
    expect(hostOf('not a url')).toBe('not a url');
    expect(hostOf('  spaced  ')).toBe('spaced');
  });
});
