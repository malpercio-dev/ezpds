// tools/interop is plain JavaScript with JSDoc types; declare the modules the
// harness and the conformance suite borrow from it.
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

declare module 'ezpds-interop/src/crypto.js' {
  export function newKeypair(): Promise<{
    keypair: unknown;
    keyId: string;
    privateKeyHex: string;
    publicKeyBase64: string;
  }>;
  export function buildGenesisOp(opts: {
    rotationKeyId: string;
    recoveryKeyId: string;
    repoSigningKeyId: string;
    rotationKeypair: unknown;
    handle: string;
    pdsUrl: string;
  }): Promise<{ did: string; signedOp: Record<string, unknown>; cid: string }>;
}
