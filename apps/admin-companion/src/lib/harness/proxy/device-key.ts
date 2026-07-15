/**
 * A real WebCrypto P-256 admin device key for the admin-companion harness's proxy mode
 * (browser-harness Phase 6).
 *
 * Stands in for the Secure-Enclave / Keychain admin credential a real device holds:
 * signing is genuinely real (ECDSA over P-256, low-S normalized as the relay's verifier
 * requires), only the durable hardware-backed storage is not. The relay accepts the
 * signatures where it verifies them — pairing registration and every signed operator
 * request — because they are produced by this real key and encoded exactly as the Rust
 * `device_key` + `signing` modules encode them.
 */

let keyPairPromise: Promise<CryptoKeyPair> | null = null;

/** Get-or-create the session admin key. Idempotent, like the Rust `get_or_create`. */
export function getDeviceKey(): Promise<CryptoKeyPair> {
  if (!keyPairPromise) {
    keyPairPromise = crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
  }
  return keyPairPromise;
}

/** The compressed 33-byte SEC1 public key. */
export async function compressedPublicKey(): Promise<Uint8Array> {
  const { publicKey } = await getDeviceKey();
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);
  return compressed;
}

/** The admin key as a `did:key:z…` multibase string (the value sent as `publicKey`). */
export async function deviceDidKey(): Promise<string> {
  const compressed = await compressedPublicKey();
  const prefixed = new Uint8Array(2 + compressed.length);
  prefixed[0] = 0x80;
  prefixed[1] = 0x24;
  prefixed.set(compressed, 2);
  return `did:key:z${base58btc(prefixed)}`;
}

/** Sign `data`: raw 64-byte r‖s ECDSA over SHA-256, low-S normalized. */
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

/** Base64url-no-pad of `bytes` — the exact wire form the relay decodes signatures from. */
export function base64urlNoPad(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const P256_HALF_N = P256_N >> 1n;

function normalizeLowS(sig: Uint8Array): Uint8Array {
  const r = sig.slice(0, 32);
  const s = sig.slice(32, 64);
  let sInt = bytesToBigInt(s);
  if (sInt > P256_HALF_N) sInt = P256_N - sInt;
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
