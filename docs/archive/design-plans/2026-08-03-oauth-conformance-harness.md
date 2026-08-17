# OAuth conformance harness

Status: implemented — see [Status](#status) below. Follows [the 2026-08-03 OAuth interop audit](../../2026-08-03-oauth-interop-audit.md),
whose item 6 this is.

## Why

Five OAuth interop bugs reached production, and every one was invisible to a green CI run:

| Bug | Why our tests missed it |
|---|---|
| Token response omitted `sub` | Our tests asserted RFC 6749 fields; only a real atproto client reads `sub`. |
| Nested error envelope on `/xrpc/*` | Our tests asserted *our own* envelope, so they locked the bug in. |
| `private_key_jwt` advertised, unimplemented | No test ever sent a `client_assertion`. |
| `rpc:` audience fragment mismatch | Both call sites were unit-tested in isolation; nothing crossed them. |
| 5-minute access tokens killing sessions | No test outlived a token. |

The common cause is not laziness — it is that **every test was written against our own
understanding of the protocol**, so a misunderstanding was tested into permanence. The fix is a
suite whose oracle is external: real client libraries and the literal wire text of the spec.

## Goal and non-goals

**Goal.** A CI-runnable suite that drives complete OAuth flows against a hermetic, locally
spawned PDS and fails when our wire behavior stops matching what real atproto clients require.

**Non-goals.**
- Not a load or fuzz harness.
- Not a replacement for the Rust unit tests. Those pin internal behavior fast; this pins
  *external contract* and is allowed to be slower.
- Not a test of the wallet (device-key) consent path — see Coverage gaps.

## Shape

A new `tools/oauth-conformance/` package, sibling to `tools/mcp/` and reusing its hermetic-PDS
spawner rather than growing a second one.

### Three client personas

Each persona catches a different class of bug, and the third is the one our current tests
structurally cannot replace.

**A — Hand-rolled wire client (the workhorse).** Plain `fetch` + `jose` for ES256 DPoP proofs.
Because it owns every byte, it is the only persona that can assert *exact wire text*: that an
expired token yields the literal string `ExpiredToken`, that `DPoP-Nonce` appears on the
challenge, that `state` is absent rather than empty. Most assertions live here.

**B — Official SDK (`@atproto/oauth-client-node`).** The compatibility oracle. It encodes
Bluesky's own reading of the spec, so it fails on things we would never think to assert. We do
not inspect its internals; we assert only that a full flow completes and an authenticated call
succeeds. Its value is precisely that we did not write it.

**C — Deliberately naive client.** Reproduces the shapes that actually failed in the wild:
skips PAR entirely, omits `state`, writes `rpc:` audiences with a `#serviceId` fragment,
retries the nonce dance only at the initial exchange. This is the pckt.blog / rpg.actor
persona, and it exists to keep us honest about leniency we have promised.

### The consent seam

An authorization flow needs a human at a consent page. Our consent page is a password form, so
the harness drives it directly: GET the page, extract the hidden inputs by `name`, POST them
back with `identifier`, `password`, `action=approve`, and the `granted_scope` checkboxes.

This couples the suite to the page's markup, which is a real cost — a CSS refactor should not
turn the OAuth suite red. Containment: **exactly one** helper (`approveConsent()`) knows the
markup, every test goes through it, and it throws a diagnostic naming itself when the page
stops matching, rather than failing as a confusing parse error somewhere downstream. A markup
change is then a one-line fix in one file.

Rejected alternative: a test-only auto-approve endpoint. It would be stable, but it would test
a code path no real client ever takes, which is the exact failure mode this whole document
exists to correct.

## Coverage

Coverage spans discovery, PAR, consent, token exchange, refresh, resource-server errors,
scopes, and confidential clients. The tests themselves are the catalogue: each one names the
regression it guards, and those tagged `REGRESSION:` correspond to a bug that actually
shipped. Those are the suite's justification and should never be deleted without a
replacement. `tools/oauth-conformance/README.md` keeps the current coverage-and-gaps list.

## Open decisions

### 1. Testing an expired access token (assertion 30) — RESOLVED, shipped

Took option (a), the config knob. `OAuthConfig` turned out to be an empty placeholder struct
already wired into `Config`, so this was one field: `oauth.access_token_ttl_secs`, default 900,
env override `EZPDS_OAUTH_ACCESS_TOKEN_TTL_SECS`, validated to 1–1800 (a zero-second token
expires before any client can use it; one above the profile's recommended ceiling is a real
exposure window on a server with no token introspection). `resource-errors.test.ts` spawns its
PDS with `2` via the `pds.toml` escape hatch, so a token genuinely lapses mid-test.

Rejected (b), a test-only minting seam, for the reason that recurs throughout this document:
it would exercise a path production never takes.

### 2. Where it runs in CI

The suite needs a built `pds` binary. The MCP conformance suite already solves this by reusing
the binary `cargo test --workspace` built earlier in the same job. Following that precedent
costs no extra build. The alternative — a separate path-filtered lane like `mcp-check.yml` —
would need its own `cargo build -p pds` and roughly doubles the lane's cost.

**Recommendation: fold into the existing PDS lane**, as a step after the Rust tests.

## Coverage gaps (stated, not hidden)

- **The wallet consent path is not covered.** Production logs show real third-party logins to
  sovereign accounts going through the device-key path, not the password form. Covering it
  needs a registered device key and a signed approval envelope — worth doing, but it is a
  second phase, and the protocol legs on either side of consent are shared with the path this
  suite does cover.
- **No real-network test.** Everything is hermetic by design; a live check against the
  deployed instance stays a manual step (`tools/interop/`).
- **Persona B pins one SDK version.** A `@atproto/oauth-client-node` bump can change what
  "conformant" means. That is a feature — it is how we learn the ecosystem moved — but the
  bump must be a deliberate, reviewed dependency change, not a floating range.

## Status

Implemented as `tools/oauth-conformance/`. The persona plan above survived contact only
partly: personas A (hand-rolled wire client) and C (deliberately naive shapes, folded into the
individual test files) exist; persona B, the official SDK, is blocked — see the README's gap
list for the reason and the two ways past it.
