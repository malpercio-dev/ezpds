// tools/interop is plain JavaScript with JSDoc types. Four of its modules reach
// this package's type-check program: `crypto.js` is imported directly by the e2e
// fixture (wallet-side child genesis), `account.js` arrives transitively — the
// fixture imports tools/mcp's test harness, whose dynamic import of the interop
// account ceremony must still resolve here — and so do `hermetic-pds.js` (the
// PDS-spawn primitives the harness imports) and `http.js` (tools/mcp's src/http.ts
// thin-wraps it, and src/session.ts and src/server.ts import that transitively via
// tools/mcp's auth.ts/tools.ts). Ambient declarations are per-program, so tools/mcp's
// own shim does not carry over.

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
