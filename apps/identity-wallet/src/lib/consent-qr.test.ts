import { describe, it, expect } from 'vitest';
import { parseConsentQr } from './consent-qr';

describe('parseConsentQr', () => {
  const REQ = 'poauth_abcDEF012_-xyz98765';

  it('extracts request_id from the full private-use URI', () => {
    expect(parseConsentQr(`org.obsign.identitywallet:/consent?request_id=${REQ}`)).toBe(REQ);
  });

  it('ignores the origin param and returns only the request_id', () => {
    const uri = `org.obsign.identitywallet:/consent?request_id=${REQ}&origin=https%3A%2F%2Fapp.example.com`;
    expect(parseConsentQr(uri)).toBe(REQ);
  });

  it('trims surrounding whitespace', () => {
    expect(parseConsentQr(`  org.obsign.identitywallet:/consent?request_id=${REQ}  `)).toBe(REQ);
  });

  it('accepts a bare query string as a lenient fallback', () => {
    expect(parseConsentQr(`request_id=${REQ}&origin=https://app.example.com`)).toBe(REQ);
  });

  it('rejects a payload without the poauth_ prefix', () => {
    expect(parseConsentQr('org.obsign.identitywallet:/consent?request_id=deadbeef')).toBeNull();
  });

  it('rejects an unrelated URL that merely carries a request_id param', () => {
    // Not a poauth_ id — the server would 404 anyway, but reject before any network call.
    expect(parseConsentQr('https://evil.example.com/?request_id=notapoauthid')).toBeNull();
  });

  it('rejects empty and non-payload text', () => {
    expect(parseConsentQr('')).toBeNull();
    expect(parseConsentQr('   ')).toBeNull();
    expect(parseConsentQr('just some text')).toBeNull();
  });
});
