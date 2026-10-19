# custos-client

Last verified: 2026-09-06

## Purpose

The DPoP/OAuth/XRPC HTTP client, extracted from identity-wallet's `src-tauri` so it can be
reused by a platform-agnostic wallet core, and — in a later PR, if a genuinely shared piece
turns up — admin-companion. Tauri-free: no `tauri`, no Keychain, no diagnostics-UI dependency.
Apps supply those as trait objects — see Contracts.

**Scope note.** A 2026-09-05 codebase audit assumed admin-companion hand-rolls DPoP alongside
the wallet. It doesn't: admin-companion authenticates via a completely different scheme
(ADR-0018's device-signed request envelope — method‖path‖timestamp‖nonce‖sha256(body) signed
with `ios-device-key`, no OAuth, no XRPC). This crate is the wallet's own DPoP/OAuth/XRPC
client, extracted for the Tauri-free-core reason above, not for cross-app dedup that doesn't
exist.

## Map

| File | What it is |
|---|---|
| `src/dpop.rs` | `DpopKeypair` — RFC 9449 DPoP proof construction/signing, generic over `ios_device_key::KeychainStore` |
| `src/error.rs` | `PdsClientError` (the XRPC failure shape), `classify_xrpc_error`/`parse_xrpc_error_envelope` (pure), `classify_xrpc_response`/`xrpc_ok`/`xrpc_json` (the classification tail), `TransportObserver` |
| `src/oauth_client.rs` | `OAuthClient` — DPoP and Bearer auth modes, lazy refresh, nonce retry, `TokenPersister` |
| `src/custos_client.rs` | `CustosClient` — the pre-session HTTP client for one configured PDS (plain JSON/Bearer requests, PAR/token-exchange) |
| `src/identity.rs` | typed XRPC methods for `com.atproto.identity.*` (the claim trio: `requestPlcOperationSignature`, `signPlcOperation`, `getRecommendedDidCredentials`) |
| `src/app_passwords.rs` | typed XRPC methods for `com.atproto.server.{create,list,revoke}AppPassword` |
| `src/migration.rs` | typed XRPC methods for the outbound-migration set (service auth, destination account creation, repo/blob import, preferences, account status/lifecycle) — no orchestration, that stays in the caller |
| `src/pds_client.rs` | `PdsClient` — discovery/auth/XRPC against *arbitrary* PDS endpoints and plc.directory (handle resolution, DID-doc discovery, `describeServer`/`createSession`, OAuth against a discovered AS, plc.directory reads/writes, repo/blob sync) |
| `src/sovereign_session.rs` | the Custos passwordless full-access session ceremony (`sovereign_login`: sign the shared canonical envelope with a caller-supplied closure, `POST /v1/sessions/sovereign` via `PdsClient`, validate the response DID and JWT sub/aud) plus the pure helpers apps reuse for a restored session (`bearer_jwt_claims`, `audience_matches_server`, `fresh_nonce`, `unix_timestamp`) — no Keychain/persistence concept, the caller resolves signing and persists the result |
| `src/base64url.rs` | the one base64 alphabet this crate uses (unpadded base64url) |

## Contracts

- **`DpopKeypair::get_or_create::<K>(account)` reuses `ios_device_key::KeychainStore`** rather
  than a bespoke trait — the account-name parameter is what makes one `KeychainStore` impl
  reusable across an app's several Keychain-backed keys. It does **not** currently sit on
  `ios_device_key::sign` itself (which never exposes the raw private scalar, the Secure Enclave
  path's whole point) — `dpop.rs`'s module doc names this as an open follow-up, not done here
  to keep no Keychain-schema change.
- **Diagnostics and token persistence are injected, never called directly.** `TransportObserver`
  (transport/server breadcrumbs) and `TokenPersister` (DPoP-mode refreshed-token storage) are
  traits an app implements; `NoopObserver`/`NoopTokenPersister` are the defaults for callers
  with nothing to wire up (every test, and `OAuthClient::new_bearer`'s plain 3-arg form).
- **`OAuthClient::new_bearer_with_observer`, not `new_bearer`, for any client whose failures a
  user could plausibly need to export.** The plain `new_bearer` records no breadcrumbs by
  design — a silent-by-default constructor this extraction *introduced*, not one it inherited:
  pre-extraction there was one `OAuthClient` and it recorded breadcrumbs unconditionally. Every
  `new_bearer` call site in identity-wallet today is a test fixture (verified: none live
  outside `#[cfg(test)]`); the 5 real production call sites all use the `_with_observer` form.
  `#[cfg(test)]`-gating the crate's own `new_bearer` was considered and rejected: a downstream
  crate's test build cannot see a dependency's `#[cfg(test)]` items, so gating it here would
  break every one of the wallet's own test-only call sites (the same cross-crate visibility
  limit `PdsClient::new_for_test` already documents).
- **`PdsClientError`/`OAuthError`/`DpopError` never carry Rust-authored user-facing prose**
  (ADR-0031) — they are the typed seam; the app's own frontend or command-level enum maps
  `code` to a sentence. This crate's job stops at a typed, classified failure.
- **`OAuthClient::new`/`DpopKeypair::get_or_create` have no production caller in
  identity-wallet today** — the DPoP-mode OAuth client login was retired when the create flow
  started ending at `home` with no OAuth round trip (see identity-wallet's `oauth.rs` module
  doc). A Bearer client no longer creates or reads the `oauth-dpop-key-priv` Keychain item at
  all (`dpop: None`); both are kept, fully tested, because the claim/migration password logins
  still depend on the surrounding machinery, and a revived create-flow login would need this
  exact entry point.

## Boundaries

- No `tauri`, `security-framework`, or app-specific Keychain/diagnostics code here — those are
  what `KeychainStore`/`TransportObserver`/`TokenPersister` exist to keep out.
- The wallet's own OAuth client identity (`CANONICAL_CLIENT_ID`, `REDIRECT_URI`,
  `client_id_for_pds`'s loopback exception, and the compile-time default PDS base URL) stays in
  `identity-wallet/src-tauri/src/pds_client.rs`/`http.rs` — it names the app itself, not a thing
  two apps could share. `OAuthClient::new`/`refresh_token_dpop` and `CustosClient::par`/
  `token_exchange` all take `client_id`/`redirect_uri` as plain parameters instead of deriving
  them internally.
- The typed XRPC methods in `identity.rs`/`app_passwords.rs`/`migration.rs` take an explicit
  `observer: &dyn TransportObserver` parameter — unlike `OAuthClient`/`CustosClient`/`PdsClient`,
  which own their observer at construction — because these are free functions, not methods on a
  long-lived client. Callers (identity-wallet's `pds_client.rs`) wrap each with the same
  original signature (no new parameter), closing over the app's observer, so none of this
  file's ~70 XRPC call sites needed to change.
- **`PdsClient::describe_server` reports the `custos` capability extension to a second,
  separate trait — `DescribeServerObserver`** — not folded into `TransportObserver`.
  `pds_capabilities::probe` (identity-wallet) reads its own cache rather than
  `describe_server`'s return value directly, so a no-op describe-observer silently starves it:
  every `PdsClient` construction site an app's tests use for capability-gated routing needs the
  real observer wired, not just the one production instance. Identity-wallet solves this with
  its own `pds_client::new_for_test` (real observers, `#[cfg(test)]`, distinct from this
  crate's `PdsClient::new_for_test`, which defaults to no-ops and is deliberately *not*
  `#[cfg(test)]` — see that constructor's doc comment for why) — this is the one place the
  "no-op by default" pattern from the rest of this crate does not hold, and a lesson for the
  next PR that adds a per-construction-site observer: check whether *anything* reads the
  side effect back out of a shared cache before defaulting it away.
- `PdsClient`'s own OAuth client identity parameters (`client_id`/`redirect_uri` on `pds_par`/
  `pds_token_exchange`) follow the same pattern as `OAuthClient`/`CustosClient` — plain
  parameters, never derived internally.
- **`sovereign_session::sovereign_login` takes a signing closure, not an identity/Keychain
  trait.** The genuinely reusable slice of the old `sovereign_login_impl` was small (build the
  signed request, POST, classify the response); everything around it — resolving the per-DID
  device key, signing via `IdentityStore`, and persisting a `SovereignTokenRecord` into
  Keychain — is app-shaped state this crate does not model. identity-wallet's
  `sovereign_session.rs` is now a thin wrapper: it resolves the device key + signer from
  `IdentityStore`, calls this module's `sovereign_login`, and persists the result; its own
  `SovereignLoginError` stays a superset (adds pre-flight variants like `IdentityNotFound`/
  `KeychainFailure` this crate's classification can't produce) with a `From` conversion for the
  rest. `fresh_nonce`/`unix_timestamp` are reused well beyond this one ceremony — every other
  device-key-signed wallet flow (agents, app passwords, identity removal, migration, rotation,
  …) calls them too, so the wallet re-exports both from its own `sovereign_session.rs` rather
  than only using them internally.
- The auth.md agent-flow console (agent consent/audit, the sovereign-child parent console) is
  still identity-wallet-only orchestration in `agents.rs`/`session_provider.rs` — larger in
  scope than the sovereign-login ceremony above and not yet redesigned behind injected traits.
  Lexicon-generated (vs. hand-written) typed methods is a separate, not-yet-decided follow-up.
