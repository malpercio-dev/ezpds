# Provider-Driven Agent Revocation (SET) — Human Test Plan

Companion to the automated suite for MM-172 (the `POST /agent/event/notify` Security Event Token
receiver). The automated tests (`cargo test -p pds agent_event` and the
`identity_assertion_provider_set_revokes_and_blocks_reexchange` journey in `agent_auth_test`) forge
SETs with a local ES256 key and cover every branch — issuer trust, signature, event/subject parsing,
idempotent revocation, and the terminal `access_denied` on re-exchange.

The items below (HV-1…HV-3) cannot be reproduced in-process: they depend on a **real external
identity provider** actually emitting a SET, and on the endpoint being reachable over the network as
deployed. They require a deployed ezpds PDS with a trusted issuer configured.

## Prerequisites

- A deployed ezpds PDS, `EZPDS_PUBLIC_URL` set to its public origin.
- `[agent_auth]` configured with **one real trusted issuer** — either an inline `public_key_pem` or
  a `jwks_url` — for an identity provider you control (e.g. a WorkOS environment, or any IdP that can
  mint an ID-JAG *and* push a SET). The issuer's `iss` must match exactly.
- A local ezpds account whose email matches the identity the provider will assert, and a completed
  `identity_assertion` registration for that agent (register → confirm the claim → the identity is
  `claimed`), so there is a live `(iss, sub)` to revoke.
- `curl`, and the ability to have the provider send a revocation event (or a captured real SET JWT).
- Baseline: `nix develop --impure --accept-flake-config -c cargo test -p pds agent_event` green, and
  the `agent_auth_test` SET journey green.

## HV-1 — A real provider SET is accepted and revokes the registration

Proves the endpoint interoperates with a genuine third-party SET (real header/claim shape, real
signing key, real network delivery) — not just our locally-forged one.

| Step | Action | Expected |
|------|--------|----------|
| 1 | Confirm the target agent is live: its `identity_assertion` exchanges for a token via `POST /oauth/token` (jwt-bearer). | `200` with a Bearer token. |
| 2 | Trigger the provider's "assertion revoked" event for that agent (or replay a captured SET), delivered to `POST {{public_url}}/agent/event/notify` with `Content-Type: application/secevent+jwt` and the SET JWT as the raw body. | `202 Accepted`, empty body. |
| 3 | `SELECT status FROM agent_identities WHERE issuer=... AND subject=...` (operator DB access), or observe via the owner's `GET /v1/agents`. | Status is `revoked`; a `revoked` audit event with `detail.source = "provider_set"` is present. |
| 4 | Re-exchange the same `identity_assertion` at `POST /oauth/token`. | `400` `{ "error": "access_denied" }` — the provider's retraction is enforced. |

If step 2 returns `invalid_issuer`, the provider's `iss` does not match a configured trusted issuer
(check exact string, including scheme/trailing slash). If `authentication_failed`, the SET is signed
by a key not in the issuer's inline PEM / published JWKS (check `kid` / key rotation).

## HV-2 — Idempotent replay and unknown subject are both acknowledged

| Step | Action | Expected |
|------|--------|----------|
| 1 | POST the **same** SET from HV-1 again. | `202`; status stays `revoked`; **no** second `revoked` audit event. |
| 2 | POST a valid SET (correctly signed by the trusted issuer) naming a `sub` with no registration. | `202`; nothing changes; no error leaked about whether the subject exists. |

## HV-3 — Untrusted / malformed SETs are rejected without side effects

| Step | Action | Expected |
|------|--------|----------|
| 1 | POST a SET whose `iss` is not on the trust list. | `400` `{ "err": "invalid_issuer", ... }`. |
| 2 | POST a SET signed by the wrong key (tamper the signature). | `400` `{ "err": "authentication_failed", ... }`. |
| 3 | POST a garbage body (`not-a-jwt`) with the SET content type. | `400` `{ "err": "invalid_request", ... }`. |
| 4 | POST the SET with `Content-Type: application/json`. | `400` `{ "err": "invalid_request", ... }`. |
| 5 | Confirm no registration changed status across steps 1–4. | All target identities unchanged. |

## Notes

- The endpoint is on the permissive-CORS public surface; the SET signature is the only credential.
  There is no bearer/DPoP auth on this route by design.
- Delivery is push-only (RFC 8935). Poll-based delivery (RFC 8936) and SET stream management are out
  of scope.
