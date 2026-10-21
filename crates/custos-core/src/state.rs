// pattern: Imperative Shell

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use common::Config;
use reqwest::Client;

use crate::auth::{DpopNonces, OAuthSigningKey, PermissionSetCache};
use crate::identity::dns::{DnsProvider, TxtResolver};
use crate::identity::well_known::WellKnownResolver;

/// In-memory store for failed login attempts per identifier, shared across all login endpoints.
/// Maps identifier string → timestamps of recent failures.
/// `std::sync::Mutex` is used because the critical section never awaits.
///
/// **Known limitation:** `createSession` keys by DID or handle; `POST /v1/accounts/sessions`
/// keys by email. Both share this store, so an attacker gets `RATE_LIMIT_MAX_FAILURES` attempts
/// per endpoint independently against the same account. Acceptable for v0.1; a future revision
/// should normalise all identifiers to DID before keying.
pub type FailedLoginStore = Arc<Mutex<HashMap<String, VecDeque<Instant>>>>;

/// The state every core helper takes and every feature handler can extract: each field a core
/// module reads, or that more than one feature reads. Feature-owned fields live in the feature's
/// own state, which embeds this one (`pds`'s `AppState`).
#[derive(Clone)]
pub struct CoreState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub http_client: Client,
    /// Shared, pooled HTTP client for every fetch to a caller-influenced target — the
    /// `atproto-proxy` header target, a did:web document, and a Lexicon-authority permission-set
    /// record. Hardened against SSRF: redirects disabled, env proxies ignored, and a custom DNS
    /// resolver that re-applies the public-address allowlist to every domain resolution at connect
    /// time (see [`crate::identity::proxy::build_hardened_client`]). Distinct from `http_client`,
    /// which serves admin-configured, trusted upstreams (plc.directory, the default AppView/chat).
    pub hardened_http_client: crate::identity::proxy::HardenedClient,
    /// Optional DNS provider for subdomain record creation on handle registration.
    /// `None` in v0.1 — operators manage DNS records manually.
    /// Populated by real provider implementations (Cloudflare, Route53) when configured.
    pub dns_provider: Option<Arc<dyn DnsProvider>>,
    /// Optional DNS TXT resolver for handle resolution fallback.
    /// When `None`, `resolveHandle` skips DNS and returns `HandleNotFound` for
    /// handles not present in the local database.
    pub txt_resolver: Option<Arc<dyn TxtResolver>>,
    /// Optional HTTP well-known resolver for handle resolution fallback.
    /// Used as the third step after local DB and DNS TXT: calls
    /// `GET https://<handle>/.well-known/atproto-did`.
    pub well_known_resolver: Option<Arc<dyn WellKnownResolver>>,
    /// TTL cache resolving a dynamic-trust issuer's JWKS (`[agent_auth] trusted_issuers[].jwks_url`)
    /// to a decoding key when verifying an ID-JAG. Shared via Arc; the static-PEM trust path never
    /// touches it. See [`crate::auth::jwks::JwksCache`].
    pub jwks_cache: Arc<crate::auth::jwks::JwksCache>,
    /// TTL cache resolving a confidential OAuth client's `jwks_uri` to a decoding key for
    /// `private_key_jwt` client authentication at the token endpoint. A separate instance from
    /// `jwks_cache` (own `[oauth] client_jwks_*` config, and a fetcher wired to the SSRF-hardened
    /// client) — see [`crate::auth::jwks::JwksCache`]'s module doc for why the two trust domains
    /// don't share a cache instance.
    pub oauth_client_jwks_cache: Arc<crate::auth::jwks::JwksCache>,
    /// HS256 signing secret for JWT access/refresh tokens. Loaded at startup from the
    /// `jwt_signing_secret` table (V015) when `signing_key_master_key` is configured;
    /// otherwise generated per boot (ephemeral — tokens invalidate on restart).
    pub jwt_secret: [u8; 32],
    /// Persistent ES256 keypair for signing OAuth access tokens.
    /// Loaded at startup from `oauth_signing_key` table (or generated + stored on first boot).
    pub oauth_signing_keypair: OAuthSigningKey,
    /// Rotating server-issued DPoP nonce, derived from `jwt_secret` — stateless, so it needs
    /// no map or cleanup and agrees across instances and restarts whenever the JWT secret does.
    pub dpop_nonces: DpopNonces,
    /// In-memory cache of resolved `include:<nsid>` permission sets. Shared across all OAuth
    /// authorize requests.
    pub permission_set_cache: PermissionSetCache,
    /// TTL cache of *remote* DID documents (1h stale / 24h hard, stale-while-revalidate),
    /// consulted after the `did_documents` table and populated by every resolution that reaches
    /// plc.directory or a did:web endpoint. Without it the `atproto-proxy` target lookup,
    /// service-auth verification, and Lexicon-authority fetch each pay a live third-party
    /// request every time. See [`crate::identity::resolution`]'s module doc for the two tiers.
    pub did_document_cache: crate::identity::resolution::DidDocumentCache,
    /// In-memory sliding-window store for failed createSession attempts (rate limiting).
    /// Shared across all requests via Arc<Mutex<...>>.
    pub failed_login_attempts: FailedLoginStore,
    /// Shared request rate-limiter state (global per-IP + per-endpoint per-IP + per-account write
    /// points). The middleware in [`crate::rate_limit`] reads it per request; the repo-write path
    /// charges write points through it. Shared via Arc.
    pub rate_limiter: Arc<crate::rate_limit::RateLimiterState>,
    /// Test-only relaxation of the `atproto-proxy` SSRF guard
    /// (`identity::proxy::resolve_atproto_proxy_target`): when `true`, a loopback address is
    /// accepted alongside public ones, so tests can proxy to a local `wiremock` server standing in
    /// for a labeler. Always `false` in the real server (`main.rs`) — only `test_state()` sets it.
    pub allow_loopback_proxy_targets: bool,
    /// Typed handles for every instrument the PDS records (see `crate::metrics`). Always
    /// present — when `[telemetry] metrics_enabled = false` this is the reader-less
    /// pipeline that drops measurements, so call sites never branch. Shared via Arc.
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Readable last-run state per periodic sweep, recorded beside the write-only OTel
    /// gauges so the operator health endpoint can report it as JSON. Shared via Arc.
    pub sweeps: Arc<crate::sweep_status::SweepStatus>,
    /// Process start, for the health endpoint's uptime readout.
    pub started_at: std::time::Instant,
    /// In-memory last-poll clock for the auth.md claim-polling grant, keyed by the SHA-256 of each
    /// agent's `claim_token`. Paces polling to the advertised `interval` (returns `slow_down` when
    /// exceeded). Read by the OAuth token endpoint and the agents surface; ephemeral (resets on
    /// restart).
    pub poll_tracker: crate::auth::ClaimPollTracker,
    /// Pushes to an account's registered devices. `None` when `[notifications] relay` is unset,
    /// which turns every account push into a no-op. `pds` installs it (`AppState::
    /// set_notify_sender`); features push through it without seeing the relay client.
    pub account_notifier: Option<Arc<dyn crate::notify::AccountNotifier>>,
}
