# Provider-Driven Agent Revocation via Security Event Tokens (MM-172)

## Summary

The Wave 8 auth.md agent surface lets an autonomous agent register, complete a claim ceremony,
exchange a service-signed `identity_assertion` for a Bearer token, and be revoked **by the account
owner** (`POST /v1/agents/{registration_id}/revoke`, `crates/pds/src/routes/agents.rs`). The AS
metadata (`/.well-known/oauth-authorization-server`) already advertises an `events_endpoint`
(`/agent/event/notify`) and one `events_supported` entry
(`https://schemas.workos.com/events/agent/auth/identity/assertion/revoked`), but no handler served
it — the served `auth.md` §7 and its metadata note both said provider-driven revocation was "not
yet enabled," and `routes/agent_auth_test.rs` deliberately skipped round-tripping the endpoint.

This change implements that endpoint. It receives a **Security Event Token** (SET,
[RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)) pushed by a trusted identity provider
([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) push delivery) and revokes the matching agent
registration at the registration layer. It is the **provider-initiated counterpart** to the
owner-driven revoke: the same identity provider whose ID-JAG vouched for an `identity_assertion`
agent (§3.1) can retract that trust when the user is offboarded, the provider key is compromised, or
the agent is decommissioned.

## Trust model — implicit gating

A SET is honored **iff its `iss` is on the existing `[agent_auth] trusted_issuers` list** — the same
trust anchor that mints `identity_assertion` registrations. There is deliberately **no separate
config toggle**:

- The provider you trust to *vouch* for agents is exactly the party you trust to *revoke* them.
  Requiring a second opt-in would silently drop a trusted provider's revocation SETs — a security
  footgun.
- A default deployment has no trusted issuers, so every SET is refused with `invalid_issuer`;
  nothing is exposed until an operator deliberately trusts a provider.
- The SET is authenticated end-to-end by its signature against the trust list, so an
  unauthenticated caller can at most trigger a signature check (bounded, and covered by the existing
  global per-IP rate limiter) before rejection.

Only `identity_assertion` registrations are reachable: they are the only ones keyed by an
`(issuer, subject)` pair, which is exactly how a SET names its target. `service_auth` / `anonymous`
registrations remain owner-revoked only.

## Definition of Done

1. **Endpoint.** `POST /agent/event/notify` accepts a SET (a signed compact JWT) delivered as
   `application/secevent+jwt`. Success is `202 Accepted` with an empty body (RFC 8935 §2.3).

2. **Verification reuses the ID-JAG trust machinery.** The SET is verified exactly like an ID-JAG —
   select the `TrustedIssuer` by `iss`, resolve its key (inline `public_key_pem` or cached
   `jwks_url`), verify signature + `iss` + `aud`. `exp` is validated only if present (a SET need not
   carry one). This logic is extracted from `routes/agent_identity.rs` into a shared
   `crates/pds/src/auth/issuer_trust.rs` (routes can't import each other), which both handlers now
   call. The extraction is behavior-preserving for the ID-JAG flow.

3. **Subject → registration.** The SET names the target by its top-level `sub` (falling back to a
   `subject` in the revoked-event payload — a bare string or an object with a `sub` — for CAEP /
   [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493)-style placements). Combined with the verified
   `iss`, `db::agent_auth::get_agent_identity_by_issuer_subject(iss, sub)` locates the registration.
   The `events` claim must carry `REVOKED_EVENT_TYPE`.

4. **Revocation is atomic and idempotent.** A found, not-yet-revoked identity is flipped to
   `revoked` and one `Revoked` audit event (`detail.source = "provider_set"`) is written in one
   transaction — the same pattern as `agents.rs::revoke_agent`, with the `status != 'revoked'` guard
   making a repeat a no-op. An unknown or already-revoked subject is still `202` (no existence
   oracle; replay-safe, so no `jti` dedup store is needed).

5. **Errors follow RFC 8935 §2.4.** Failures return `400` (or `500` for a transient server fault)
   with a JSON `{ "err", "description" }` body — distinct from the XRPC `ApiError` envelope and the
   auth.md `{error, error_description}` envelope. Codes: `invalid_request` (malformed body / wrong
   content type / missing-or-unsupported event / no subject), `invalid_issuer` (absent or untrusted
   `iss`), `authentication_failed` (bad signature / claims).

6. **Revocation reaches the token endpoint.** After a SET revokes an identity, re-exchanging its
   `identity_assertion` at `/oauth/token` returns `access_denied` — the same terminal-refusal path
   the owner-driven revoke exercises.

7. **Discovery + docs stay truthful.** `events_supported` is sourced from the shared
   `REVOKED_EVENT_TYPE` constant. The served `auth.md` §7 documents the working SET push path; the
   two "not yet live" caveats are corrected (they also incorrectly listed the machine-pollable claim
   grant, which had already shipped in `oauth_token.rs::handle_claim_polling` — corrected here too).
   `bruno/agent_event_notify.bru` keeps route parity; `pds.dev.toml` notes the implicit gating.

## Non-goals

- **No `jti` replay store.** Revocation is idempotent, so replaying a revocation SET is harmless.
- **No new rate-limit family.** The signature check precedes any DB work; the global per-IP limiter
  covers the endpoint.
- **No `service_auth` / `anonymous` SET revocation.** Those have no `(issuer, subject)` and stay
  owner-revoked.
- **No stream-management / SET status endpoints** (RFC 8936 poll delivery, verification SETs). Only
  the single push event type this server advertises is handled.

## Files

- **New:** `crates/pds/src/auth/issuer_trust.rs` (shared verification + `REVOKED_EVENT_TYPE`);
  `crates/pds/src/routes/agent_event.rs` (handler + SET-error responder + unit tests);
  `bruno/agent_event_notify.bru`; this doc + the companion test plan.
- **Modified:** `auth/mod.rs`, `routes/mod.rs`, `app.rs` (registration); `routes/agent_identity.rs`
  (call the shared module); `routes/oauth_server_metadata.rs` (`REVOKED_EVENT_TYPE`);
  `routes/agent_auth_test.rs` (round-trip the endpoint + full SET journey); `crates/pds/assets/auth.md`
  (§ scope note, § metadata note, §7); `crates/pds/CLAUDE.md`; `pds.dev.toml`.

## Verification

Automated coverage is exhaustive because a SET is a locally-forgeable signed JWT (unlike, say, a
live AppView):

- `routes/agent_event.rs` unit tests: untrusted issuer → `invalid_issuer`; malformed body →
  `invalid_request`; bad signature → `authentication_failed`; missing event type →
  `invalid_request`; wrong content type → `invalid_request`; unknown subject → `202` no-op; matching
  identity → revoked + one provider-driven audit event, idempotent on replay; subject taken from the
  event payload.
- `routes/agent_auth_test.rs`: the discovery round-trip now reaches the handler, and
  `identity_assertion_provider_set_revokes_and_blocks_reexchange` drives register → confirm →
  exchange → SET → `202` → re-exchange `access_denied`.
- `just bruno-check`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all --check`.

The one thing local tests can't prove — that a **real** third-party IdP's SET format interoperates —
is the companion human test plan (`docs/test-plans/2026-07-09-agent-provider-revocation-set.md`).
