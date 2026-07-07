import { describe, it, expect } from 'vitest';
import { hostOf, serverIdentity } from './server-identity';
import type { Pairing } from './ipc';

describe('hostOf', () => {
  it('extracts host from https URL', () => {
    expect(hostOf('https://relay.example')).toBe('relay.example');
  });

  it('extracts host from https URL with trailing slash', () => {
    expect(hostOf('https://relay.example/')).toBe('relay.example');
  });

  it('retains port from URL', () => {
    expect(hostOf('https://relay.example:8443')).toBe('relay.example:8443');
  });

  it('extracts host and port from http URL with path', () => {
    expect(hostOf('http://10.0.0.41:3000/base')).toBe('10.0.0.41:3000');
  });

  it('falls back to raw string for invalid URL', () => {
    expect(hostOf('not a url')).toBe('not a url');
  });

  it('trims fallback string for invalid URL', () => {
    expect(hostOf('  spaced  ')).toBe('spaced');
  });
});

describe('serverIdentity', () => {
  it('uses nickname when provided', () => {
    const pairing: Pick<Pairing, 'nickname' | 'relayUrl'> = {
      nickname: 'staging',
      relayUrl: 'https://staging.example.com',
    };
    const identity = serverIdentity(pairing);
    expect(identity.nickname).toBe('staging');
    expect(identity.host).toBe('staging.example.com');
  });

  it('falls back to host when nickname is empty string', () => {
    const pairing: Pick<Pairing, 'nickname' | 'relayUrl'> = {
      nickname: '',
      relayUrl: 'https://example.com',
    };
    const identity = serverIdentity(pairing);
    expect(identity.nickname).toBe('example.com');
    expect(identity.host).toBe('example.com');
  });

  it('falls back to host when nickname is whitespace-only', () => {
    const pairing: Pick<Pairing, 'nickname' | 'relayUrl'> = {
      nickname: '   ',
      relayUrl: 'https://example.com',
    };
    const identity = serverIdentity(pairing);
    expect(identity.nickname).toBe('example.com');
    expect(identity.host).toBe('example.com');
  });
});
