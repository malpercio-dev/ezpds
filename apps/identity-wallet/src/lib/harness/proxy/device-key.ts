/**
 * A real WebCrypto P-256 device key for the wallet harness's proxy mode
 * (browser-harness.AC3.2).
 *
 * Stands in for the Secure-Enclave / Keychain device key an iPhone would hold: signing is
 * genuinely real (ECDSA over P-256, low-S normalized as the PLC directory and PDS require),
 * only the durable hardware-backed storage is not — the private key is non-extractable and
 * lives for the browser session. It exports a `did:key` in the same multibase form the Rust
 * `device_key` module produces, so the value the PDS receives is well-formed.
 */

let keyPairPromise: Promise<CryptoKeyPair> | null = null;

/** Get-or-create the session device key. Idempotent, like the Rust `get_or_create`. */
export function getDeviceKey(): Promise<CryptoKeyPair> {
  if (!keyPairPromise) {
    keyPairPromise = crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      // Non-extractable private key; the public key stays exportable regardless.
      false,
      ['sign', 'verify']
    );
  }
  return keyPairPromise;
}

/** The compressed 33-byte SEC1 public key. */
export async function compressedPublicKey(): Promise<Uint8Array> {
  const { publicKey } = await getDeviceKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)); // 0x04 || X || Y
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);
  return compressed;
}

/** The device key as a `did:key:z…` multibase string (P-256 multicodec 0x8024). */
export async function deviceDidKey(): Promise<string> {
  const compressed = await compressedPublicKey();
  const prefixed = new Uint8Array(2 + compressed.length);
  prefixed[0] = 0x80; // P-256 multicodec varint, low byte
  prefixed[1] = 0x24; // high byte
  prefixed.set(compressed, 2);
  return `did:key:z${base58btc(prefixed)}`;
}

/**
 * Sign `data` with the device key: raw 64-byte r‖s ECDSA over SHA-256, low-S normalized
 * (WebCrypto already returns raw r‖s; we normalize S to the lower half as atproto requires).
 */
export async function signWithDeviceKey(data: Uint8Array): Promise<Uint8Array> {
  const { privateKey } = await getDeviceKey();
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      data as unknown as BufferSource
    )
  );
  return normalizeLowS(sig);
}

/** The P-256 group order n. */
const P256_N = BigInt(
  '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
);
const P256_HALF_N = P256_N >> 1n;

/** Normalize the S value of a raw r‖s signature to the lower half of the curve order. */
function normalizeLowS(sig: Uint8Array): Uint8Array {
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  let sInt = bytesToBigInt(s);
  if (sInt > P256_HALF_N) {
    sInt = P256_N - sInt;
  }
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(bigIntToBytes(sInt, 32), 32);
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Minimal base58btc encoder (Bitcoin alphabet), enough for did:key multibase. */
function base58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}
