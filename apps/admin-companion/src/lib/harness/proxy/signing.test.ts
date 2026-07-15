import { describe, it, expect } from 'vitest';
import { registrationSignString, requestSignString, sha256Hex } from './signing';
import { base64urlNoPad, getDeviceKey, deviceDidKey, signWithDeviceKey } from './device-key';

// The proxy signing envelopes must match the Rust signing.rs (and the relay's auth.rs)
// byte-for-byte. These pin the exact same golden literals the Rust golden tests pin, so a
// drift on either side is caught here too.
const EMPTY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('admin proxy signing envelopes', () => {
  it('sha256Hex matches known vectors', async () => {
    expect(await sha256Hex(new Uint8Array(0))).toBe(EMPTY_SHA256_HEX);
    expect(await sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('registrationSignString matches the relay golden', () => {
    expect(registrationSignString('CODE', 'did:key:zABC', 1700)).toBe('CODE\ndid:key:zABC\n1700');
  });

  it('requestSignString matches the relay golden', async () => {
    expect(await requestSignString('POST', '/x', 1700, 'abc', new Uint8Array(0))).toBe(
      `POST\n/x\n1700\nabc\n${EMPTY_SHA256_HEX}`
    );
  });

  it('base64url-no-pad matches the relay golden', () => {
    expect(base64urlNoPad(new Uint8Array([0xff, 0xfe, 0xfd]))).toBe('__79');
    const encoded = base64urlNoPad(new Uint8Array(64));
    expect(encoded.includes('=')).toBe(false);
  });

  it('produces a real device signature that verifies (AC3.3)', async () => {
    const { publicKey } = await getDeviceKey();
    const message = new TextEncoder().encode(
      await requestSignString('POST', '/v1/accounts/claim-codes', 1700, 'n', new Uint8Array(0))
    );
    const sig = await signWithDeviceKey(message);
    expect(sig).toHaveLength(64);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sig as unknown as BufferSource,
      message as unknown as BufferSource
    );
    expect(ok).toBe(true);
  });

  it('exports a well-formed did:key', async () => {
    expect(await deviceDidKey()).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  });
});
