// A mock plc.directory that can actually answer a DID lookup.
//
// tools/mcp's stub answers every path with `{}`, which is all its suite needs: the PDS POSTs
// a genesis operation during account creation and never reads anything back. A real OAuth
// *client* is different — it resolves the `sub` DID it was handed, finds that DID's PDS, and
// checks the token really came from there. That is the whole point of the check (it stops a
// hostile authorization server minting tokens for someone else's account), so a client that
// performs it correctly cannot be tested against a directory that returns `{}`.
//
// This is a local variant rather than a change to the shared harness: two other suites depend
// on that module, and neither needs a stateful directory.
//
// The documents served here are not synthesized. The harness reads each one back from the PDS
// (`com.atproto.repo.describeRepo` returns `didDoc`) and registers it, so a client resolving a
// DID sees the same document the server would have published to the real directory.

import * as http from 'node:http';

export interface MockPlc {
  url: string;
  /** Publish a DID document, making `GET /{did}` resolvable. */
  register: (did: string, document: unknown) => void;
  close: () => void;
}

export function startMockPlc(): Promise<MockPlc> {
  const documents = new Map<string, unknown>();

  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const path = decodeURIComponent((req.url ?? '/').split('?')[0] ?? '/');
      const did = path.slice(1);
      const document = documents.get(did);

      if (req.method === 'GET' && document) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(document));
        return;
      }
      if (req.method === 'GET' && did.startsWith('did:')) {
        // An unregistered DID genuinely does not exist as far as this directory is concerned;
        // 404 is what the real one returns, and answering `{}` would turn a wiring mistake
        // into a confusing parse error inside the client instead.
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: 'DID not registered in the mock directory' }));
        return;
      }
      // Everything else — notably the genesis-operation POST the PDS makes during account
      // creation — keeps the stub's accept-everything behaviour.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });

    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        register: (did, document) => documents.set(did, document),
        close: () => server.close(),
      });
    });
  });
}
