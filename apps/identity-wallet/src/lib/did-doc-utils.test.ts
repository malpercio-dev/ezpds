import { describe, expect, it } from 'vitest';
import {
  didMethod,
  isDidWeb,
  docNeedsRotationKeysRefresh,
  isOldModelRecovery,
} from './did-doc-utils';

describe('isOldModelRecovery', () => {
  const twoKey = { rotationKeys: ['did:key:zDevice', 'did:key:zPds'] };
  const threeKey = { rotationKeys: ['did:key:zDevice', 'did:key:zRecovery', 'did:key:zPds'] };

  it('is true for a did:plc identity with exactly 2 rotation keys (old model)', () => {
    expect(isOldModelRecovery('did:plc:abc', twoKey)).toBe(true);
  });

  it('is false for a new-model (3-key) did:plc identity', () => {
    expect(isOldModelRecovery('did:plc:abc', threeKey)).toBe(false);
  });

  it('is false for a did:web identity regardless of doc shape', () => {
    expect(isOldModelRecovery('did:web:example.com', twoKey)).toBe(false);
  });

  it('is false when the doc is missing or lacks a rotationKeys array (stale cache)', () => {
    expect(isOldModelRecovery('did:plc:abc', null)).toBe(false);
    expect(isOldModelRecovery('did:plc:abc', { rotationKeys: 'nope' })).toBe(false);
    expect(isOldModelRecovery('did:plc:abc', {})).toBe(false);
  });
});

describe('didMethod', () => {
  it('extracts the method from a did:plc', () => {
    expect(didMethod('did:plc:abc123')).toBe('plc');
  });

  it('extracts the method from a did:web', () => {
    expect(didMethod('did:web:malpercio.dev')).toBe('web');
    expect(didMethod('did:web:example.com:users:alice')).toBe('web');
  });

  it('returns null for a malformed DID', () => {
    expect(didMethod('not-a-did')).toBe(null);
    expect(didMethod('did:web')).toBe(null);
    expect(didMethod('did::abc')).toBe(null);
    expect(didMethod('')).toBe(null);
  });
});

describe('isDidWeb', () => {
  it('is true only for did:web', () => {
    expect(isDidWeb('did:web:malpercio.dev')).toBe(true);
    expect(isDidWeb('did:web:example.com:users:alice')).toBe(true);
  });

  it('is false for did:plc and malformed DIDs', () => {
    expect(isDidWeb('did:plc:abc123')).toBe(false);
    expect(isDidWeb('did:key:zabc')).toBe(false);
    expect(isDidWeb('not-a-did')).toBe(false);
  });
});

describe('docNeedsRotationKeysRefresh', () => {
  it('requests a refresh when no doc is cached', () => {
    expect(docNeedsRotationKeysRefresh(null)).toBe(true);
  });

  it('requests a refresh for a W3C-shaped doc (no rotationKeys field)', () => {
    // The exact shape earlier builds cached after claim/migration/recovery.
    expect(
      docNeedsRotationKeysRefresh({
        id: 'did:plc:test',
        alsoKnownAs: ['at://alice.test'],
        verificationMethod: [],
        service: [],
      })
    ).toBe(true);
  });

  it('requests a refresh when rotationKeys is empty', () => {
    expect(docNeedsRotationKeysRefresh({ did: 'did:plc:test', rotationKeys: [] })).toBe(true);
  });

  it('requests a refresh when rotationKeys is not an array', () => {
    expect(
      docNeedsRotationKeysRefresh({ did: 'did:plc:test', rotationKeys: 'did:key:zNotAnArray' })
    ).toBe(true);
  });

  it('keeps a healthy PLC data doc', () => {
    expect(
      docNeedsRotationKeysRefresh({
        did: 'did:plc:test',
        rotationKeys: ['did:key:zDevice', 'did:key:zPds'],
        services: { atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://pds' } },
      })
    ).toBe(false);
  });
});
