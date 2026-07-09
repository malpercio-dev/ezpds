// tools/interop is plain JavaScript with JSDoc types; declare the one module
// the harness borrows from it.
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
