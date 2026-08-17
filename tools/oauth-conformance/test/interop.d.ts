// tools/interop is plain JavaScript with JSDoc types; declare the modules the suite borrows
// from it. Unlike tools/mcp's copy, `password` is named explicitly: the OAuth consent form
// needs a real credential, and leaving it in the index signature would type it `unknown`.
//
// The wallet consent path needs more than a credential — it signs as the account's rotation
// key and its authority is read from the account's PLC audit log, so the ceremony's key
// material is named here too rather than arriving as `unknown` from the index signature.
declare module 'ezpds-interop/src/account.js' {
  export function createAccount(opts: {
    name: string;
    kind: 'persistent' | 'ephemeral';
    handle?: string;
    claimCode?: string;
  }): Promise<{
    did: string;
    handle: string;
    email: string;
    accessJwt: string;
    password?: string;
    /** `rotationKeys[0]` — the account's root of control, and what the wallet signs with. */
    rotationKeyId: string;
    rotationKeyPrivateHex: string;
    /** `rotationKeys[1]` and `rotationKeys[2]`; needed to rebuild the genesis operation. */
    recoveryKeyId: string;
    repoSigningKeyId: string;
    [key: string]: unknown;
  }>;
}

declare module 'ezpds-interop/src/crypto.js' {
  /** An `@atproto/crypto` P256Keypair; only its `sign` is used here. */
  export interface Keypair {
    did(): string;
    sign(message: Uint8Array): Promise<Uint8Array>;
  }

  export function keypairFromHex(privateKeyHex: string): Promise<Keypair>;

  /** A fresh exportable P-256 keypair — a key deliberately outside any account's authority. */
  export function newKeypair(): Promise<{
    keypair: Keypair;
    keyId: string;
    privateKeyHex: string;
    publicKeyBase64: string;
  }>;

  export function buildGenesisOp(opts: {
    rotationKeyId: string;
    recoveryKeyId: string;
    repoSigningKeyId: string;
    rotationKeypair: Keypair;
    handle: string;
    pdsUrl: string;
  }): Promise<{ did: string; signedOp: Record<string, unknown>; cid: string }>;

  export function computeCid(signedOp: unknown): string;
}
