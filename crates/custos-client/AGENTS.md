# custos-client

Last verified: 2026-09-06

## Purpose

The Bearer-session/XRPC HTTP client, extracted from identity-wallet's `src-tauri` so it can be
reused by a platform-agnostic wallet core, and — in a later PR, if a genuinely shared piece
turns up — admin-companion. Tauri-free: no `tauri`, no Keychain, no diagnostics-UI dependency.
Apps supply those as trait objects — see Contracts.

**Scope note.** A 2026-09-05 codebase audit assumed admin-companion hand-rolls DPoP alongside
the wallet. It doesn't: admin-companion authenticates via a completely different scheme
(ADR-0018's device-signed request envelope — method‖path‖timestamp‖nonce‖sha256(body) signed
with `ios-device-key`, no OAuth, no XRPC). This crate is the wallet's own Bearer-session/XRPC
client, extracted for the Tauri-free-core reason above, not for cross-app dedup that doesn't
exist.

## Map

| File | What it is |
|---|---|
| `src/error.rs` | `PdsClientError` (the XRPC failure shape), `classify_xrpc_error`/`parse_xrpc_error_envelope` (pure), `classify_xrpc_response`/`xrpc_ok`/`xrpc_json` (the classification tail), `TransportObserver` |
| `src/oauth_client.rs` | `OAuthClient` — Bearer sessions, lazy in-memory refresh via `refreshSession` |
| `src/custos_client.rs` | `CustosClient` — the pre-session HTTP client for one configured PDS (plain JSON/Bearer requests, PAR/token-exchange) |
| `src/identity.rs` | typed XRPC methods for `com.atproto.identity.*` (the claim trio: `requestPlcOperationSignature`, `signPlcOperation`, `getRecommendedDidCredentials`) |
| `src/app_passwords.rs` | typed XRPC methods for `com.atproto.server.{create,list,revoke}AppPassword` |
| `src/migration.rs` | typed XRPC methods for the outbound-migration set (service auth, destination account creation, repo/blob import, preferences, account status/lifecycle) — no orchestration, that stays in the caller |
| `src/pds_client.rs` | `PdsClient` — discovery/auth/XRPC against *arbitrary* PDS endpoints and plc.directory (handle resolution, DID-doc discovery, `describeServer`/`createSession`/`refresh_session`, OAuth against a discovered AS, plc.directory reads/writes, repo/blob sync) |
| `src/sovereign_session.rs` | the Custos passwordless full-access session ceremony (`sovereign_login`: sign the shared canonical envelope with a caller-supplied closure, `POST /v1/sessions/sovereign` via `PdsClient`, validate the response DID and JWT sub/aud) plus the pure helpers apps reuse for a restored/rotated session (`bearer_jwt_claims`, `audience_matches_server`, `fresh_nonce`, `unix_timestamp`) and `refresh_bearer_session` (rotate via `PdsClient::refresh_session` + re-validate the same sub/aud binding, for any Bearer full-access session) — no Keychain/persistence/session-lifecycle-policy concept, the caller resolves signing, decides when to refresh, and persists the result |
| `src/agents.rs` | typed methods for auth.md's own agent-consent/child-lifecycle endpoints (`list_agents`, `revoke_agent`, `get_agent_audit`, `preview_agent_claim`, `confirm_agent_claim`, `list_children`, `revoke_child`, `delete_child`, `remint_child_assertion`) plus `AgentError`/`map_ceremony_error`/`CeremonyErrorBody` — these aren't `com.atproto.*` XRPC, so they classify responses themselves rather than through `error.rs`'s envelope tail |
| `src/base64url.rs` | the one base64 alphabet this crate uses (unpadded base64url) |

## Contracts

- **Diagnostics are injected, never called directly.** `TransportObserver` (transport/server
  breadcrumbs) is a trait an app implements; `NoopObserver` is the default for callers with
  nothing to wire up (every test, and `OAuthClient::new_bearer`'s plain 3-arg form).
  `OAuthClient` persists nothing: a refreshed pair lives in memory, and the caller stores it.
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
- **`PdsClientError`/`OAuthError` never carry Rust-authored user-facing prose**
  (ADR-0031) — they are the typed seam; the app's own frontend or command-level enum maps
  `code` to a sentence. This crate's job stops at a typed, classified failure.
- **Credentials only travel over HTTPS (or loopback).** `pds_url_is_secure` is the one check;
  `OAuthClient::new_bearer*` returns `OAuthError::InsecureTransport` for anything else, and the
  password and sovereign logins call the same function.
- **No DPoP key or DPoP-mode client lives here.** The password logins (claim, outbound
  migration) and every per-DID sovereign session are Bearer sessions; none depends on a DPoP
  keypair. `CustosClient::par`/`token_exchange` and `PdsClient::pds_par`/`pds_token_exchange`
  still take a caller-built DPoP proof, but nothing in the wallet calls them today.

## Boundaries

- No `tauri`, `security-framework`, or app-specific Keychain/diagnostics code here — those are
  what `TransportObserver` exists to keep out.
- The wallet's own OAuth client identity (`CANONICAL_CLIENT_ID`, `REDIRECT_URI`,
  `client_id_for_pds`'s loopback exception, and the compile-time default PDS base URL) stays in
  `crates/obsign-core/src/pds_client.rs`/`http.rs` — it names the app itself, not a thing
  two apps could share. `CustosClient::par`/
  `token_exchange` take `client_id`/`redirect_uri` as plain parameters instead of deriving
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
  `SovereignLoginError` stays a superset (embeds obsign-core's `SharedFailure` for pre-flight
  failures like `IDENTITY_NOT_FOUND`/`KEYCHAIN_ERROR` this crate's classification can't produce) with a `From` conversion for the
  rest. `fresh_nonce`/`unix_timestamp` are reused well beyond this one ceremony — every other
  device-key-signed wallet flow (agents, app passwords, identity removal, migration, rotation,
  …) calls them too, so the wallet re-exports both from its own `sovereign_session.rs` rather
  than only using them internally.
- **`agents::AgentError` covers only what a network response can itself produce** — it has no
  `NotProvisioned`/`HandleRejected` (mint-ceremony concepts needing a delegation seed) or
  `SessionLocked` (a `SessionProvider` concept). identity-wallet's own `AgentsError` stays a
  superset with a `From` conversion for the shared variants. Minting a child account
  (`mint_child_from_claim`) and post-recovery reconciliation (`reconcile_children`) stay in
  identity-wallet entirely — both derive rotation keys off the wallet's delegation seed and
  sign a did:plc genesis operation, wallet key material this crate does not hold; only the
  `list_children` call inside `reconcile_children_impl` is a crate *network* call (both also
  reach into the crate for `CeremonyErrorBody`/`map_ceremony_error`, the shared ceremony-code
  classification `map_child_confirm_error` widens ahead of).
- **`refresh_bearer_session` is the network+validation slice of a Bearer rotation; the
  decision ladder around it stays in identity-wallet.** `SessionProvider::full_access_client`
  (restore / decide-to-refresh / `SessionLocked`, the per-DID coalescing lock,
  `IdentityStore`'s `SovereignTokenRecord` reads/writes) is still identity-wallet-only
  orchestration in `session_provider.rs` — it calls this function once it has decided a
  rotation is needed, then persists the result or discards the record on a classified
  revocation (`map_refresh_error`, session_provider.rs's own mapping from `PdsClientError`
  to obsign-core's shared `SharedFailure`). `sovereign_login` likewise passes a discovery
  failure up unclassified (`SovereignLoginError::Discovery`); obsign-core classifies it.
  A candidate for a future PR if the wallet-core extraction needs the ladder itself moved,
  not yet redesigned behind injected traits.
- **Typed methods stay hand-written; lexicon codegen (`atrium-api`) was investigated and
  rejected for this crate** — five independent reasons (missing Custos lexicon extensions,
  newtype ripple, narrower error classification, no DPoP, no lexicon at all for `agents.rs`)
  and the revisit trigger are [ADR-0038](../../docs/architecture/decisions/0038-hand-written-xrpc-methods-over-lexicon-codegen.md).
