// tools/interop is plain JavaScript with JSDoc types; declare the one module the fixture
// borrows from it. Unlike tools/mcp's copy, `password` is named explicitly: the OAuth consent
// form needs a real credential, and leaving it in the index signature would type it `unknown`.
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
    [key: string]: unknown;
  }>;
}
