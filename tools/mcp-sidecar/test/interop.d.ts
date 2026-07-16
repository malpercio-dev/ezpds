// tools/interop is plain JavaScript with JSDoc types. Two of its modules reach
// this package's type-check program: `crypto.js` is imported directly by the e2e
// fixture (wallet-side child genesis), and `account.js` arrives transitively —
// the fixture imports tools/mcp's test harness, whose dynamic import of the
// interop account ceremony must still resolve here (ambient declarations are
// per-program, so tools/mcp's own shim does not carry over).

declare module 'ezpds-interop/src/crypto.js' {
  /** An exportable P-256 keypair as tools/interop generates it. */
  export interface InteropKeypair {
    keypair: unknown;
    /** did:key form of the public key. */
    keyId: string;
    privateKeyHex: string;
    publicKeyBase64: string;
  }

  export function newKeypair(): Promise<InteropKeypair>;

  export function buildGenesisOp(opts: {
    rotationKeyId: string;
    repoSigningKeyId: string;
    rotationKeypair: unknown;
    handle: string;
    pdsUrl: string;
  }): Promise<{ did: string; signedOp: Record<string, unknown> }>;

  export function randomSuffix(len?: number): string;
}

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
    [key: string]: unknown;
  }>;
}
