import { describe, it, expect } from 'vitest';
import { getDeviceKey, deviceDidKey, signWithDeviceKey } from './device-key';

// AC3.2: the proxy device key is a real WebCrypto P-256 keypair producing signatures the
// PDS would accept. Node's global WebCrypto backs these in the test environment.
describe('proxy device key', () => {
  it('is a stable P-256 keypair for the session', async () => {
    const a = await getDeviceKey();
    const b = await getDeviceKey();
    expect(a).toBe(b);
    expect(a.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
    expect(a.privateKey.extractable).toBe(false);
  });

  it('exports a well-formed did:key multibase', async () => {
    const didKey = await deviceDidKey();
    expect(didKey).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it('produces a 64-byte low-S signature that verifies', async () => {
    const { publicKey } = await getDeviceKey();
    const data = new TextEncoder().encode('harness-signing-test');
    const sig = await signWithDeviceKey(data);
    expect(sig).toHaveLength(64);

    // Low-S: the S half must be in the lower range of the curve order.
    const s = sig.slice(32, 64);
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    let sInt = 0n;
    for (const b of s) sInt = (sInt << 8n) | BigInt(b);
    expect(sInt <= n >> 1n).toBe(true);

    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sig as unknown as BufferSource,
      data as unknown as BufferSource
    );
    expect(ok).toBe(true);
  });
});
