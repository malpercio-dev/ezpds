# OAuth interop audit — why third-party atproto apps fail against Custos

Date: 2026-08-03. Prompted by mixed real-world results: tangled works, rpg.actor logs in but
actions fail, pckt.blog dies mid-flow, Beacon (beaconbits.app) can't log in at all. This audit
diffs our OAuth surface against the reference `@atproto/oauth-provider` (what bsky.social runs,
August 2026 state) and tranquil-pds, and correlates the gaps with production log evidence.

## Live evidence (Railway, pds.obsign.org, 2026-08-01 → 08-03)

- **rpg.actor** (20:57Z 08-03): full healthy login — PAR 201 → authorize → wallet approve →
  complete 303 → token 400 `use_dpop_nonce` → token 200. The nonce dance works. Whatever fails,
  fails *after* login.
- **pckt.blog** (20:56Z 08-03): skipped PAR entirely (direct `GET /oauth/authorize`, which we
  accept despite advertising `require_pushed_authorization_requests: true`), consent approved,
  `complete` 303'd back with the code — and **no token exchange ever arrived**. Five seconds
  later a bare `GET /oauth/authorize` returned 400. The flow dies on the client's callback leg.
- **Unattributed burst** (23:14Z 08-02): a bsky-deck-style client got uniform 401s on
  `getSession`, `getTimeline`, `getPreferences`, `chat.bsky.convo.getLog`, etc. — the signature
  of a session whose access token expired and whose client never managed to refresh.
- **Beacon**: zero trace in the current deployment's logs. Its failure either predates the log
  window or happens client-side before our PDS is ever contacted (client-metadata fetch,
  handle→PDS resolution, or metadata validation on their end).
- Recurring token-endpoint 400s are all `use_dpop_nonce`; most are followed by a successful
  retry (normal bootstrap), but several are not — consistent with clients that don't retry the
  nonce dance on *refresh* (see gap 4).

## Client stacks involved

| App | Stack | Scope style | Client auth |
|---|---|---|---|
| tangled.org | Rust `atproto-oauth` | granular `repo:sh.tangled.* rpc:sh.tangled.* blob:*/* identity:handle` | `private_key_jwt` (ES256) |
| rpg.actor | custom TS (PKCE+DPoP) | granular, repo-only: nine `repo:<nsid>` + `blob:image/*`, **no `rpc:`** | `none` |
| pckt.blog | custom (non-PAR!) | granular incl. `include:<nsid>` permission sets and `rpc:...?aud=did:web:marque.at#marque_registrar` | `none` |
| Beacon | unknown (metadata not fetchable at common paths) | unknown | unknown |

The generational divide: everything that fails uses the 2026 granular scope grammar and/or a
non-official client stack; the transitional-scope, official-stack path is the one we validated
against (wallet, tangled after the `sub` fix).

## Gap matrix vs the reference provider

### P0 — actively breaking real apps

1. **Gap 1 — Resource-call error shape is not atproto XRPC shape.** `common::ApiError` emits
   `{"error": {"code": "TOKEN_EXPIRED", "message": ...}}` (nested, SCREAMING_SNAKE); atproto
   clients key refresh-on-401 off the flat `{"error": "ExpiredToken", "message": ...}` body
   (`@atproto/api`, indigo, atcute all match on the string `ExpiredToken`). The correctly named
   `ErrorCode::ExpiredToken` variant exists but is only used for password-reset tokens;
   `jwt.rs` returns `TokenExpired` for expired access tokens. Combined with our **300 s access
   tokens** (reference: 15 min, spec allows up to 30), every client session hits an
   unrecognizable expiry error within five minutes of login and never refreshes. This is the
   best single explanation for "logs in fine, actions around the site fail" (rpg.actor, and the
   23:14Z burst). Also: **no `WWW-Authenticate` header on any 401** anywhere in the tree, so
   spec-following clients can't even discover the failure class.

1. **Gap 2 — `private_key_jwt` advertised but not implemented.** `TokenRequestForm` has no
   `client_assertion`/`client_assertion_type` fields; serde silently drops them and the client
   is treated as public. Confidential clients (tangled!) currently "work" only because we skip
   their authentication entirely — an interop time bomb and a real security gap (a leaked
   authorization code for a confidential client is exchangeable by anyone holding the DPoP
   key). Either implement RFC 7523 client assertions (with clock tolerance — see reference
   issue #4474: allow ~30 s skew on `iat`) or stop advertising the method.

1. **Gap 3 — `rpc:` scope `aud` matching is inconsistent with itself and the ecosystem.**
   `xrpc_dispatch` passes the **raw `atproto-proxy` header including the `#serviceId`
   fragment** into `require_rpc`, while `getServiceAuth` strips the fragment before the same
   check; `aud_matches` is exact string equality. Meanwhile real clients are split on
   convention — pckt.blog's scopes carry `aud=did:web:marque.at#marque_registrar` (with
   fragment), the spec's examples use the bare DID. Result: a granular `rpc:` grant can pass
   one path and fail the other, and which one works depends on how the client wrote its scope
   string. Matching must normalize (compare DID, and treat fragment as an optional refinement)
   on both paths.

1. **Gap 4 — Refresh semantics are far tighter than the ecosystem assumes.**
   - Refresh-token TTL **24 h** (reference: 2 weeks public / 3 months confidential since
     June 2025, PR #3883). Any client idle a day is silently logged out.
   - Rotation is strictly single-use with **no reuse-detection grace window**: a concurrent
     double-refresh (multi-tab, mobile background+foreground) races; the loser's token is
     already deleted and the session strands. The reference keeps a short grace period and
     revokes the family on true reuse.
   - Every refresh **requires a fresh server nonce**, so refresh is always a
     `use_dpop_nonce` → retry two-step; clients that only implement the nonce dance at the
     initial exchange (common in hand-rolled stacks) fail here. The unretried
     `use_dpop_nonce` 400s in the logs fit this.

### P1 — spec divergences that will bite specific clients

1. **Gap 5 — PAR is advertised as required but not enforced** — direct `GET /oauth/authorize` works
   (deliberate, documented). Harmless for lenient clients, but it means we never bind
   `dpop_jkt` at PAR time, and:
1. **Gap 6 — Authorization codes are not DPoP-key-bound at issuance** (no `jkt` column on the code
   row) — the reference binds the key at PAR. Whoever presents the code binds it.
1. **Gap 7 — `state` is mandatory at PAR** — nonstandard (RECOMMENDED in OAuth; the atproto profile
   does not require it). A client relying on PKCE alone gets `invalid_request`.
1. **Gap 8 — Client metadata is barely validated**: only `client_id` and `redirect_uris` are read.
   `grant_types`, `response_types`, `scope`, `application_type`, `dpop_bound_access_tokens`,
   `token_endpoint_auth_method`, `jwks`/`jwks_uri` are ignored. The reference validates and
   *enforces* these (e.g. a client whose metadata omits a scope can't be granted it; auth
   method must match). Prerequisite for fixing gap 2.
1. **Gap 9 — `prompt` parameter unsupported** (`login`/`consent`/`create` — reference added
   `prompt=create` account-signup flows in Jan 2026; `prompt_values_supported` absent from our
   metadata is fine, but an arriving `prompt` param should not be silently dropped).
1. **Gap 10 — Scope-consent checkbox narrowing is invisible to clients that don't check `scope`** —
    fine per the negotiated-scope model, but combined with the refresh-path legacy coercion
    (an unparseable stored scope silently becomes bare `atproto`, which grants *nothing*), a
    session can degrade to useless while staying authenticated.
1. **Gap 11 — Resource endpoints never issue or require DPoP nonces.** The reference PDS runs the
    nonce scheme on the resource server too (clients track nonces per-AS *and* per-PDS). Being
    lenient here is survivable, but clients that expect a `DPoP-Nonce` header to appear on
    resource responses (python cookbook pattern) never see one.

### P2 — robustness / scale

12. Process-local state everywhere security-relevant: DPoP nonce store, permission-set cache,
    client negative-cache, consent poll throttle — all `Arc<Mutex<HashMap>>`. Restart = every
    in-flight nonce dance breaks; horizontal scaling breaks correctness, not just perf.
13. No `jti` replay store for DPoP proofs (documented gap).
14. No per-endpoint rate limits on `/oauth/par` or `/oauth/token` (only the global IP limiter).
15. Metadata omissions vs reference: `protected_resources` on the AS doc, `prompt_values_supported`;
    plus we advertise two nonstandard grant types (`jwt-bearer`, `urn:workos:agent-auth:...`)
    that a strict validator could balk at (no observed failures from this yet).

## Per-app diagnosis

- **tangled** — works, but by accident on the auth leg: its `client_assertion` is silently
  ignored (gap 2). Its granular repo/rpc writes work because direct-to-PDS repo writes only
  need `require_repo`, which is correct.
- **rpg.actor** — login is healthy end-to-end. Failure is post-login: 300 s tokens + the
  `TOKEN_EXPIRED` shape (gap 1) kill the session minutes in, and its custom client also holds
  zero `rpc:` scopes, so *any* PDS-proxied appview read 403s (that part would fail on
  bsky.social too, but the 5-minute session death is ours).
- **pckt.blog** — dies on the callback leg before ever calling `/oauth/token`; our redirect
  (code+state+iss, query mode) looks spec-correct, so the proximate failure is client-side —
  but we can't rule out that its custom non-PAR client chokes on something in our authorize
  response. Needs one instrumented repro (browser devtools on the callback). Once past that,
  its `include:` permission sets and fragment-style `rpc:` `aud`s land on gaps 3 and 8.
- **Beacon** — never reaches us in the current logs. First step is a repro while tailing logs;
  if truly nothing arrives, the failure is in their client-metadata/PDS-discovery step, not our
  OAuth surface.

## Tranquil comparison

Tranquil (tranquil.farm/tranquil-pds, Rust/axum like us, custom OAuth — not the reference
package) has publicly walked the same road: DPoP `htu` mismatch bugs (their issue #11), scope
declaration errors with third-party apps (#28), OAuth-only accounts unable to re-auth (#77),
consent UI broken by ad-blockers (#76), app discovery 500s breaking Discord's integration
(#94). Nothing in their surface is fundamentally ahead of ours except: they run the nonce
scheme more completely, they ship an `/oauth/introspect` endpoint, and their consent UI has
per-scope human-readable descriptions. Their issue list is a useful preview of our next six
months of interop bugs if we don't build a conformance harness.

## Status

**Gaps 1–5 shipped on branch `claude/oauth-atproto-failures-4ff55e` (2026-08-03), unreleased.**
Five commits, one per gap, each with tests: the flat XRPC error shape (`e0fcd2f2`), token
lifetimes + refresh grace/reuse detection (`28c9e25d`, V061), `rpc:` audience fragment
normalization (`0b04bdb4`), `private_key_jwt` client authentication (`3cfdaf3b`), and DPoP
key binding at PAR + optional `state` (`bfd3f8c8`, V062).

**Item 6 (the conformance harness) also shipped** as `tools/oauth-conformance/`, running in
CI's PDS lane. Building it surfaced two further gaps not in the matrix above — a `jwks_uri`
held to a stricter transport rule than the `client_id` it is fetched from, and no support for
the spec's loopback client identifiers — both now fixed. Item 7 remains open, and **none of
this is verified against a live third-party client yet**: the suite is hermetic by
construction, so re-running the real pckt.blog and Beacon logins after deploy is still what
would close them.

## Recommended order of work

1. Fix the XRPC error envelope for auth failures (flat `{"error": "ExpiredToken"}` +
   `WWW-Authenticate`) — smallest change, unblocks every official-SDK client's refresh loop.
2. Lengthen access tokens to ~15 min and refresh TTL to ≥2 weeks; add refresh grace
   window/reuse detection.
3. Normalize `rpc:` `aud` matching across `xrpc_dispatch` and `getServiceAuth`.
4. Implement `private_key_jwt` (with 30 s clock tolerance) or de-advertise it; validate client
   metadata fields while there.
5. Bind `dpop_jkt` at PAR/code issuance; make `state` optional.
6. ~~Build a client-conformance smoke harness~~ — **done** (`tools/oauth-conformance/`). Drive a real login with `@atproto/oauth-client-node`,
   atcute, and a hand-rolled non-PAR client against a hermetic PDS in CI — the tangled `sub`
   bug and this entire audit both trace to "we only ever tested our own clients."
7. Reproduce pckt.blog (callback capture) and Beacon (log tail) individually.

## Addendum (2026-08-12): pckt.blog root cause — gap 12, absent `request_uri` capability fields

The instrumented repro (item 7) landed and the pckt.blog failure is fully explained. It was
never the callback redirect: a HAR of the real flow plus controlled curl probes against
pckt's own endpoints showed their Laravel backend *receives* our `code`+`state`+`iss`
callback with a live session, passes its state check (wrong/absent state 403s; the real flow
302s with a "couldn't complete the login" flash), then fails locally in ~100 ms without ever
contacting our token endpoint.

The discriminating experiment: pckt uses **PAR** against bsky.social *and* against a
third-party self-hosted reference PDS (pds.robocracy.org) — but silently downgrades to a
legacy direct-authorize flow against us, for did:plc and did:web accounts alike. The one
relevant metadata difference: the reference provider emits `request_uri_parameter_supported`,
`require_request_uri_registration`, and `request_parameter_supported` explicitly, and we
emitted none of them. OpenID Connect Discovery §3 (which defines all three fields) defaults
`request_uri_parameter_supported` to `true` when absent — and the atproto profile pins
`require_request_uri_registration`'s default to `true` and forbids `false` — but pckt's
client reads absence as "legacy server without PAR" and takes a fallback path whose callback
half is broken (their bug — but absence is indistinguishable from incapability to such
clients). Beacon remains unexplained (still zero server contact).

Fix: emit the three fields explicitly (`request_uri_parameter_supported: true`,
`require_request_uri_registration: true`, and — honestly, diverging from the reference —
`request_parameter_supported: false`, since we do not implement JAR). Conformance suite pins
their presence. The suites only prove serialization — they cannot prove a deployed client
*selects* PAR — so the live probe is the release gate for this item: after the production
deploy, start pckt's flow for an obsign-hosted handle and check the redirect URL for
`request_uri=` (PAR path) instead of inline `state`/`code_challenge` (legacy path), and
record the outcome here before closing the pckt.blog item. If pckt still downgrades, the
next lever is their gate possibly requiring `request_parameter_supported: true`, which we
should not lie about — that would mean implementing JAR or contacting pckt.
