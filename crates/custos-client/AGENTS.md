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
| `src/base64url.rs` | the one base64 alphabet this crate uses (unpadded base64url) |

## Contracts

- **`DpopKeypair::get_or_create::<K>(account)` reuses `ios_device_key::KeychainStore`** rather
  than a bespoke trait — the account-name parameter is what makes one `KeychainStore` impl
  reusable across an app's several Keychain-backed keys. It does **not** currently sit on
  `ios_device_key::sign` itself (which never exposes the raw private scalar, the Secure Enclave
  path's whole point) — `dpop.rs`'s module doc names this as an open follow-up, not done here
  to keep the extraction a pure relocation with no Keychain-schema change.
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
  doc). Both are kept, fully tested, because Bearer construction and the claim/migration
  password logins still depend on the surrounding machinery, and a revived create-flow login
  would need this exact entry point.

## Boundaries

- No `tauri`, `security-framework`, or app-specific Keychain/diagnostics code here — those are
  what `KeychainStore`/`TransportObserver`/`TokenPersister` exist to keep out.
- The wallet's own OAuth client identity (`CANONICAL_CLIENT_ID`, `REDIRECT_URI`,
  `client_id_for_pds`'s loopback exception) stays in `identity-wallet/src-tauri/src/pds_client.rs`
  — it names the app itself, not a thing two apps could share. `OAuthClient::new`/
  `refresh_token_dpop` take `client_id` as a plain constructor parameter instead.
- `CustosClient` (the wallet's `http.rs`: PAR/token-exchange against the *configured* PDS) has
  not moved here yet — its `par`/`token_exchange` methods have zero callers today (the same
  retired create-flow login), so folding them in is low-risk future work, not done in this PR
  to keep the diff to the DPoP/XRPC-envelope/OAuthClient layer.
- Typed XRPC request/response structs for individual lexicon methods
  (`getServiceAuth`/`createAccount`/`signPlcOperation`/…) and the service-auth/sovereign-session/
  auth.md agent-flow logic built on top of them stay in identity-wallet's `pds_client.rs`/
  `migration_orchestrator.rs`/`agents.rs`/`sovereign_session.rs` for now — moving those (and
  deciding whether they're hand-written or lexicon-generated) is follow-up work, not this
  extraction.
