import { describe, expect, it } from 'vitest';
import { docNeedsRotationKeysRefresh } from './did-doc-utils';

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
