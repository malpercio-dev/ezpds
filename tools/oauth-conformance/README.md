# OAuth conformance suite

Drives complete AT Protocol OAuth flows against a hermetic, locally spawned PDS and asserts
the wire contract that real third-party atproto clients depend on.

```bash
just oauth-conformance-setup   # once
just oauth-conformance-test
```

## Why this exists

Five OAuth interop bugs reached production while the Rust test suite stayed green — including
a token response missing `sub` (which 500'd tangled.org's callback) and 300-second access
tokens that killed every third-party session minutes after login. The
[2026-08-03 interop audit](../../docs/2026-08-03-oauth-interop-audit.md) traced all five to
one cause: **every test was written against our own reading of the protocol**, so a
misunderstanding got tested into permanence. The unit tests asserted our own error envelope,
which is precisely why they never noticed it was the wrong shape.

This suite's assertions are written from the *client's* side of the wire instead. Assertions
tagged `REGRESSION:` in the tests correspond to bugs that actually shipped; they are the
suite's justification and should not be deleted without a replacement.

## How it works

- **Hermetic PDS.** Spawned per test file by `test/fixture.ts`, reusing `spawnPds` /
  `startMockPlc` / the loopback TLS proxy from [`tools/mcp/test/harness.ts`](../mcp/test/harness.ts)
  rather than growing a second spawner. Nothing reaches the network.
- **A real account.** Provisioned through the same ceremony the identity wallet uses
  (claim code → mobile account → client-signed did:plc genesis → handle), via `tools/interop`.
  The fixture keeps the account's **password**, which the consent form needs.
- **A loopback client.** `startClientHost()` publishes an OAuth client metadata document over
  plain-http loopback. The PDS resolves URL-shaped `client_id`s by fetching them, and loopback
  is the spec's local-development exception — which is what makes a hermetic third-party-client
  harness possible at all.
- **A hand-rolled wire client** (`src/wire-client.ts`), plain `fetch` + `jose`. Written by hand
  on purpose: an SDK hides the wire, retrying the DPoP nonce dance and normalizing error bodies
  before a test could ever see them, and those details are exactly where the bugs lived.

## The consent seam

An authorization flow needs a human to approve at a consent page. Ours is a password form, so
`src/consent.ts` fills it directly — no browser.

**`src/consent.ts` is the only file that knows the consent page's markup.** Every test goes
through `approveConsent()`, so restyling the page is a one-line fix here rather than a diff
across the suite, and `parseConsentForm()` throws a message naming itself when the page stops
matching instead of failing downstream as a confusing "missing parameter" from the server.

A test-only auto-approve endpoint was considered and rejected: it would be immune to markup
changes, but it would exercise a code path no real client takes — the same
test-our-own-assumptions failure mode this suite exists to correct.

## Conventions

- Node 22's native TypeScript, no build step; `node:test`, no test framework.
- `pnpm check` type-checks; `pnpm test` runs the suite.
- **One fixture per test file.** `tools/interop`'s config module reads `EZPDS_BASE_URL` at
  first import and caches it, so a second fixture in the same process would provision against
  the first PDS. `node --test` gives each file its own process, which makes the rule safe.
- Tests need a `pds` binary: `cargo build -p pds`, or point `CUSTOS_MCP_TEST_PDS_BIN` at one.

## Current coverage and gaps

`flow.test.ts` covers discovery, PAR (including without `state`), the consent leg, the DPoP
nonce dance, token-response shape (`sub`, `token_type`, `expires_in`, `cnf.jkt` binding), code
replay, and scope rejection.

`resource-errors.test.ts` covers what a client sees *after* login: the flat `ExpiredToken` /
`InvalidToken` / `AuthMissing` strings clients dispatch on, on both a local and a proxied
endpoint, plus the refusal of a DPoP-bound token presented as `Bearer`. It runs its own PDS
with `oauth.access_token_ttl_secs = 2` so a token genuinely lapses mid-test rather than the
suite waiting out a real one.

`refresh.test.ts` covers rotation: that both tokens rotate and the new access token works,
that rotations chain, that `sub` and the granted scope survive each one, that the DPoP key and
`client_id` are enforced, that a rejected refresh does not consume the token, and — the case
that matters most — that **two concurrent refreshes carrying the same token both succeed**.

`confidential-client.test.ts` covers `private_key_jwt`: a full flow with a valid assertion,
and refusal when the assertion is missing, signed by the wrong key, minted for another
audience, or expired — on the refresh grant as well as the initial exchange. The `jwks_uri`
branch is deliberately not exercised here: it would have to point at loopback, which the
SSRF-hardened client correctly refuses in production. That branch is covered by
`client_auth.rs`'s wiremock tests instead.

Each of these was checked by breaking the server and watching the suite go red: removing the
error-shape middleware fails five tests, removing the refresh grace window fails the
concurrency test with the server's literal response in the message, and skipping client
authentication fails five more — one of them printing the full token set the server handed to
a client that proved nothing. That is the property worth
maintaining — these reproduce the production bugs rather than restating current behaviour.

Not yet covered, in rough priority order:

1. **Stale refresh-token reuse revoking the session family.** The grace window is 60 seconds,
   so a black-box test would have to sit through it. Covered instead by the Rust unit test
   `refresh_token_stale_reuse_revokes_session_family`, which backdates `superseded_at`
   directly. Worth revisiting if the window ever becomes configurable.
2. **The absolute session lifetime.** Rotation must not extend a session past its original
   grant, but a refresh token's expiry is never exposed to the client, so this is not
   observable from outside. Covered by a Rust unit test.
3. **The official SDK** (`@atproto/oauth-client-node`) as a second persona. Attempted and
   currently **blocked**, for a reason worth recording: the SDK refuses to treat an
   `https:` loopback origin as a resource server, and this PDS refuses a non-https
   `public_url` (RFC 8414 requires an https issuer). A hermetic run needs one side to give
   way, and weakening the server's issuer rule to satisfy a test is the wrong direction.
   Getting past it means either a non-loopback hostname resolving to 127.0.0.1 in the test
   environment, or an http-issuer exception scoped to loopback — a deliberate decision, not
   a test-harness convenience.

   The attempt was still worth making: on its first run the SDK rejected our client_id
   outright, which is how we learned this server did not implement the spec's **loopback
   client** identifiers (`http://localhost?redirect_uri=…&scope=…`, whose metadata is
   synthesized from the identifier rather than fetched). That is now supported, so any
   developer building an app against a local Custos can use the standard development
   client. One run of an oracle we did not write found a real conformance gap before it
   ever completed a flow.
4. **The wallet consent path — and with it, the DPoP key binding.** Real third-party logins to
   sovereign accounts go through the device-key path, not this password form. That is also the
   only path that carries a pushed request's DPoP key through to the issued code: the password
   form's pushed request is consumed by the GET that renders it, so the code is issued unbound
   (deliberately — see `oauth_authorize.rs`). `flow.test.ts` pins that gap rather than leaving
   it implicit, and the enforcement itself is covered only by a Rust test that writes the
   binding directly onto the code row. Covering the wallet path needs a JS port of the consent
   envelope (Rust-only today, with a golden vector at
   `test-vectors/oauth-consent-envelope-v1.json` to pin against) and a mock plc.directory that
   serves real audit logs — the current one serves DID documents only. Tracked as MM-502.

Design and rationale: [docs/design-plans/2026-08-03-oauth-conformance-harness.md](../../docs/design-plans/2026-08-03-oauth-conformance-harness.md).
