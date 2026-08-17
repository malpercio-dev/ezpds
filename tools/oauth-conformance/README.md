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
  The fixture keeps the account's **password**, which the consent form needs, and its
  **rotation key**, which the wallet consent path signs with.
- **A directory that answers.** `test/mock-plc.ts` serves the account's DID document *and* its
  operation log at `GET /{did}/log/audit`, because `rotationKeys` — the set an approval is
  checked against — exist only in PLC operations, never in a DID document. The log is not
  synthesized: `test/plc-audit-log.ts` rebuilds the ceremony's genesis operation from the
  persisted key material and refuses to serve it unless the DID it derives is the account's,
  which (a did:plc *being* the hash of its signed genesis op) proves the bytes are the ones the
  PDS accepted.
- **A loopback client.** `startClientHost()` publishes an OAuth client metadata document over
  plain-http loopback. The PDS resolves URL-shaped `client_id`s by fetching them, and loopback
  is the spec's local-development exception — which is what makes a hermetic third-party-client
  harness possible at all.
- **A hand-rolled wire client** (`src/wire-client.ts`), plain `fetch` + `jose`. Written by hand
  on purpose: an SDK hides the wire, retrying the DPoP nonce dance and normalizing error bodies
  before a test could ever see them, and those details are exactly where the bugs lived.

## The consent seam

An authorization flow needs a human to approve at a consent page, and ours offers two ways to
do it. The **password form** is filled directly by `src/consent.ts` — no browser. The **wallet
path** is what real third-party logins to sovereign accounts take: the account approves out of
band by signing a canonical envelope with a key in its PLC rotation set, and the browser's only
remaining job is to POST the completion form.

**`src/consent.ts` is the only file that knows the consent page's markup**, for both paths.
Every test goes through `approveConsent()` or `parseWalletPath()`, so restyling the page is a
one-line fix here rather than a diff across the suite, and both parsers throw a message naming
themselves when the page stops matching instead of failing downstream as a confusing "missing
parameter" from the server.

The wallet's own side is `src/wallet-consent.ts` — a hand-rolled client for the four device-key
endpoints, hand-rolled for the same reason as `wire-client.ts`. It signs with
`src/consent-envelope.ts`, a **JavaScript port of a wire format defined only in Rust**
(`crates/crypto/src/oauth_consent.rs`). Two implementations of one format are safe here only
because both are pinned to a file neither owns: `test-vectors/oauth-consent-envelope-v1.json`,
asserted by `consent-envelope.test.ts` on this side and
`canonical_envelope_has_a_stable_golden_vector` on the other. A drift in either direction fails
a test rather than producing envelopes the server rejects as an unexplained
"consent approval rejected".

A test-only auto-approve endpoint was considered and rejected: it would be immune to markup
changes, but it would exercise a code path no real client takes — the same
test-our-own-assumptions failure mode this suite exists to correct. The same rule is why the
wallet path is driven over HTTP with a real signature rather than by writing the approval into
the PDS's database.

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

`wallet-consent.test.ts` covers the device-key path: preview by `user_code` and by
`request_id`, the uniform 404 that keeps a guessed code from probing request state, a signed
approval driving a full flow to a working session, scope narrowing surviving to the issued
token, denial, and the single-use completion. Its envelope-binding half proves an approval
cannot be replayed onto its own request or re-pointed at another, widened past the scope it
signed, back-dated, or signed by a key outside the account's current `rotationKeys`. And — the
assertion the password path cannot reach — that a code issued here **is** bound to the DPoP key
proved at PAR time: a second key gets `invalid_grant`, and the rightful key still redeems
afterwards.

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
4. **Number matching on a push-delivered request (V060).** Once a `login-approval` push has
   gone out, approval additionally requires the two-digit number displayed on the sign-in page
   — the anti-MFA-fatigue proof that the approver can see the login surface. Reaching that
   state black-box is not possible here: the requirement latches only after `notify_device`
   actually enqueues a sealed payload, which needs `[notifications] relay` **and**
   `[iroh] enabled`, and iroh binds with the `N0` preset (n0 discovery + relay servers) — real
   network, which this suite deliberately does not touch. `wallet-consent.test.ts` covers the
   half that is reachable and is the half an over-eager mitigation would break: with no push
   dispatched, `matchRequired` is false, no number is disclosed anywhere, and approval does not
   demand one. The enforcement itself is covered by the Rust test
   `push_delivered_request_requires_the_matching_number` (wrong number → 403 with the request
   left pending; a denial never requires it). Latching the code by writing to the spawned PDS's
   database was considered and rejected for the same reason as a test-only auto-approve
   endpoint.

Design and rationale: [docs/archive/design-plans/2026-08-03-oauth-conformance-harness.md](../../docs/archive/design-plans/2026-08-03-oauth-conformance-harness.md).
