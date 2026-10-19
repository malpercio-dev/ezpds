// tools/interop is plain JavaScript with JSDoc types; declare the modules the
// harness and the conformance suite borrow from it.
declare module 'ezpds-interop/src/http.js' {
  export class HttpError extends Error {
    status: number;
    body: unknown;
    url: string;
    constructor(status: number, body: unknown, url: string);
    readonly errorCode: string | null;
    readonly errorDescription: string | null;
  }
  export function sleep(ms: number): Promise<void>;
  export function request(
    url: string,
    options?: {
      method?: string;
      headers?: Record<string, string>;
      body?: unknown;
      token?: string;
      raw?: boolean;
      minIntervalMs?: number;
      maxRetries?: number;
    },
  ): Promise<any>;
  export function xrpc(
    serviceUrl: string,
    nsid: string,
    options?: {
      method?: string;
      headers?: Record<string, string>;
      body?: unknown;
      token?: string;
      raw?: boolean;
      params?: Record<string, unknown>;
      minIntervalMs?: number;
      maxRetries?: number;
    },
  ): Promise<any>;
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

declare module 'ezpds-interop/src/hermetic-pds.js' {
  export function pdsBinary(repoRoot: string, explicit?: string): string;
  export function freePort(): Promise<number>;
  export function startMockPlc(): Promise<{ url: string; close: () => void }>;
  export function startTlsProxy(
    tls: { key: Buffer; cert: Buffer },
    opts?: { port?: number; upstreamPort?: number },
  ): Promise<{ port: number; setUpstreamPort: (port: number) => void; close: () => void }>;
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
