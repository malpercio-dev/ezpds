# custos-oauth

Last verified: 2026-10-21

The OAuth authorization server feature crate: PAR, `/oauth/authorize` and its wallet-confirmed
consent half, the token endpoint (authorization code, refresh, and the auth.md jwt-bearer and
claim-polling grants), revocation, the two discovery documents, the server's JWKS and client
metadata, and the `walletConsent` capability entry. It depends on
[`custos-core`](../custos-core/AGENTS.md) and [`custos-db`](../custos-db/AGENTS.md), never on `pds`
or a sibling feature, so `cargo test -p custos-oauth` builds neither Spaces nor the rest of `pds`.
The feature-crate contract is [`custos-spaces`' map](../custos-spaces/AGENTS.md#what-pds-consumes);
this crate differs only in owning no state.

The client-facing wire contract (`PAR → consent → token → authenticated call`) is pinned from the
client's side by `tools/oauth-conformance/`; the interop failures it guards slipped past the Rust
tests, so run it when changing an OAuth response shape — see its README.

This file is a map; mechanism and invariants live in each module's `//!` doc.

## What `pds` consumes

| Export | Use in `pds` |
|---|---|
| `router()` | merged into `app.rs`'s public (CORS'd) group before the layer stack; generic over any state with `CoreState: FromRef<S>`. No gate: the authorization server is always on |
| `CAPABILITY` | `walletConsent`, listed in `pds`'s `CAPABILITIES` in its original slot |
| `test_support` (`test-support` feature) | `test_app(state)` plus `custos_core::test_support` re-exported |

Handlers extract `State<CoreState>`. Everything the OAuth server reads that another feature also
reads lives in core: the claim-poll tracker and agent assertion machinery (the token endpoint's
agent grants), the account notifier (the login-approval push), and the space type cache (the
consent page's `space:` labels, `custos_core::scope_display`).

## Module Map

```
src/
  lib.rs            — the exports above; aliases `custos_core`'s `identity`, `rate_limit`, `time` and `common::code_gen` at the crate root so the moved files' `crate::…` paths resolve
  router.rs         — the route table (`scripts/bruno-parity.sh` and `scripts/generate-docs-reference.mjs` read its `.route(` literals)
  capability.rs     — `CAPABILITY`, the `walletConsent` entry of the `describeServer` table
  oauth_templates.rs, oauth_errors.rs, oauth_dpop.rs — handler-free support shared by the routes (table below)
  auth/             — `oauth_response_mode.rs`: `ResponseMode` (`query` | `fragment`), validated at PAR, threaded through both consent paths, read back off the pending row; `custos_core::auth` is re-exported here
  db/               — `pending_oauth_authorizations.rs`: the wallet-confirmed consent primitive (V056 + V060) and the append-only consent audit trail; `custos_db`'s `oauth`, `accounts`, `handles`, and agent modules are re-exported here crate-privately
  routes/           — one file per endpoint (table below); private, only handler functions leave it
  test_support.rs   — `test-support` feature (and this crate's own tests): `test_app` wraps `router()` in the layers `pds` applies to its public group, so a path no OAuth route claims is a plain 404 here — tests that call a `pds` route with an OAuth-issued token live in `pds`
```

### Support modules

| File | Contents |
|---|---|
| `oauth_templates.rs` | pure HTML rendering helpers |
| `oauth_errors.rs` | shared `OAuthTokenError` — the RFC 6749 §5.2 responder used by `oauth_token/` and `oauth_revoke.rs` |
| `oauth_dpop.rs` | shared handler-free support for `oauth_token/`'s grant handlers and `oauth_revoke.rs` `token_endpoint_dpop` — the RFC 9449 multiple-header check, proof extraction, and `validate_dpop_for_token_endpoint` dispatch against the caller's own URL |

### `routes/`

| File | Endpoint |
|---|---|
| `oauth_authorize.rs` | `GET/POST /oauth/authorize` — consent page + code issuance; PAR-only (a GET without a PAR `request_uri`, or carrying a JAR `request` object, is refused), and the GET's wallet path owns the Phase C login-approval push dispatch |
| `oauth_consent.rs` | `GET /oauth/authorize/{consent-request,status}`, `POST /oauth/authorize/{approve,complete}` — the wallet-confirmed (passwordless) consent half; approval is a device-key envelope verified against `identity::authority`, never the cached DID doc |
| `oauth_par.rs` | `POST /oauth/par` — RFC 9126; enforces the atproto reverse-FQDN private-use-redirect rule (`custos_core::auth::oauth_client_resolution`) and stores `response_mode` |
| `oauth_token/` | `POST /oauth/token` — one route module, per-grant submodules (`authorization_code`, `refresh`, `jwt_bearer`, `claim_polling`); grants incl. the RFC 7523 jwt-bearer exchange and the `urn:workos:agent-auth:grant-type:claim` poll — each submodule's doc carries its grant's rules |
| `oauth_revoke.rs` | `POST /oauth/revoke` — RFC 7009; refresh tokens only, DPoP proof-of-possession, uniform 200-empty non-disclosure |
| `oauth_protected_resource.rs` | `GET /.well-known/oauth-protected-resource` |
| `oauth_server_metadata.rs` | `GET /.well-known/oauth-authorization-server` |
| `oauth_jwks.rs` | `GET /oauth/jwks` |
| `oauth_client_metadata.rs` | `GET /oauth/client-metadata.json` — the wallet's OAuth client metadata; fixed canonical client_id except under a loopback `public_url` — see module doc |

## Rules

- **Routes do not import routes.** Shared route support goes in the crate-root `oauth_*` modules,
  `auth/`, or `db/`.
- **Never depend on `pds` or a sibling feature crate.** Anything another feature also needs moves
  down to `custos-core` (or `custos-db` for a table).
- **A new OAuth route** is registered in `router.rs` and gets a `.bru` file in `bruno/` (root
  AGENTS.md).
- **Migrations stay in `custos-db`.**
