// pattern: Imperative Shell

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use common::Config;
use reqwest::Client;

use crate::auth::{ClaimPollTracker, DpopNonceStore, OAuthSigningKey, PermissionSetCache};
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

/// Shared application state cloned into every request handler via Axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub http_client: Client,
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
    /// HS256 signing secret for JWT access/refresh tokens.
    /// Generated randomly at startup via OsRng (ephemeral — rotates on restart).
    pub jwt_secret: [u8; 32],
    /// Persistent ES256 keypair for signing OAuth access tokens.
    /// Loaded at startup from `oauth_signing_key` table (or generated + stored on first boot).
    pub oauth_signing_keypair: OAuthSigningKey,
    /// In-memory store for server-issued DPoP nonces. Shared across all token endpoint requests.
    pub dpop_nonces: DpopNonceStore,
    /// In-memory last-poll clock for the auth.md claim-polling grant, keyed by the SHA-256 of each
    /// agent's `claim_token`. Paces polling to the advertised `interval` (returns `slow_down` when
    /// exceeded). Shared across all token endpoint requests; ephemeral (resets on restart).
    pub poll_tracker: ClaimPollTracker,
    /// In-memory cache of resolved `include:<nsid>` permission sets. Shared across all OAuth
    /// authorize requests.
    pub permission_set_cache: PermissionSetCache,
    /// In-memory sliding-window store for failed createSession attempts (rate limiting).
    /// Shared across all requests via Arc<Mutex<...>>.
    pub failed_login_attempts: FailedLoginStore,
    /// In-memory firehose pipeline: every repo commit emits a sequenced event here, which
    /// `com.atproto.sync.subscribeRepos` fans out to connected relays/BGSes. Shared via Arc.
    pub firehose: Arc<crate::firehose::Firehose>,
    /// Outbound `requestCrawl` notifier: after each commit, pings the configured relays/BGSes
    /// so newly produced content is crawled promptly. Shared via Arc.
    pub crawlers: Arc<crate::crawler::CrawlerNotifier>,
    /// Bound Iroh QUIC endpoint, when `[iroh] enabled`. `None` when the tunnel is disabled.
    /// Handlers read `iroh.node_id` to advertise the pds's node id. Shared via Arc.
    pub iroh: Option<Arc<crate::iroh_tunnel::IrohState>>,
    /// Shared request rate-limiter state (global per-IP + per-endpoint per-IP + per-account write
    /// points). The middleware in [`crate::rate_limit`] reads it per request; the repo-write path
    /// charges write points through it. Shared via Arc.
    pub rate_limiter: Arc<crate::rate_limit::RateLimiterState>,
    /// Outbound email sender (password reset, email confirmation, email update). The default
    /// `LogEmailSender` logs instead of sending, so tests and a fresh install need no mail server;
    /// `email.provider = "smtp"` swaps in real SMTP delivery. Shared via Arc.
    pub email: Arc<dyn crate::email::EmailSender>,
    /// Test-only relaxation of the `atproto-proxy` SSRF guard
    /// (`identity::resolution::resolve_atproto_proxy_target`): when `true`, a loopback address is
    /// accepted alongside public ones, so tests can proxy to a local `wiremock` server standing in
    /// for a labeler. Always `false` in the real server (`main.rs`) — only `test_state()` sets it.
    pub allow_loopback_proxy_targets: bool,
    /// Typed handles for every instrument the PDS records (see `crate::metrics`). Always
    /// present — when `[telemetry] metrics_enabled = false` this is the reader-less
    /// pipeline that drops measurements, so call sites never branch. Shared via Arc.
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Per-DID locks serializing each repo's logical write sequence (root read → commit CAS →
    /// post-commit GC) so one request's GC can never delete a concurrent same-repo write's
    /// freshly written blocks. Shared via Arc; see [`crate::record_write::RepoWriteLocks`].
    pub repo_write_locks: Arc<crate::record_write::RepoWriteLocks>,
    /// Readable last-run state per periodic sweep, recorded beside the write-only OTel
    /// gauges so the operator health endpoint can report it as JSON. Shared via Arc.
    pub sweeps: Arc<crate::sweep_status::SweepStatus>,
    /// Process start, for the health endpoint's uptime readout.
    pub started_at: std::time::Instant,
}

#[cfg(test)]
pub(crate) async fn test_state() -> AppState {
    test_state_with_plc_url("https://plc.directory".to_string()).await
}

#[cfg(test)]
pub async fn test_state_with_plc_url(plc_directory_url: String) -> AppState {
    use crate::auth::{new_claim_poll_tracker, new_nonce_store, new_permission_set_cache};
    use crate::db::{open_pool, run_migrations};
    use common::{
        AppViewConfig, BlobsConfig, ChatConfig, CrawlersConfig, FirehoseConfig, IrohConfig,
        OAuthConfig, RateLimitConfig, TelemetryConfig,
    };
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use std::path::PathBuf;
    use std::time::Duration;

    let db = open_pool("sqlite::memory:").await.expect("test pool");
    run_migrations(&db).await.expect("test migrations");

    let http_client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("test http client");

    // Generate a fresh ephemeral P-256 keypair for tests (no DB persistence needed).
    let test_signing_key = {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let pkcs8 = sk
            .to_pkcs8_der()
            .expect("PKCS#8 encoding must succeed for test key");
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y"));
        let public_key_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });
        OAuthSigningKey {
            key_id: "test-oauth-key-01".to_string(),
            encoding_key: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_bytes()),
            public_key_jwk,
        }
    };
    let dpop_nonces = new_nonce_store();

    // Enabled in tests so instrument assertions can read the rendered output; each test
    // state gets its own registry (no global exporter state to collide on).
    let metrics = Arc::new(crate::metrics::Metrics::new("test-pds").expect("test metrics"));

    // Build the firehose before the struct literal: the `db` field below moves the pool, so the
    // sequencer needs its own clone first.
    let firehose = Arc::new({
        let mut f = crate::firehose::Firehose::new(db.clone())
            .await
            .expect("test firehose");
        f.attach_metrics(metrics.clone());
        f
    });

    AppState {
        config: Arc::new(Config {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            data_dir: PathBuf::from("/tmp"),
            database_url: "sqlite::memory:".to_string(),
            public_url: "https://test.example.com".to_string(),
            service_name: "custos".to_string(),
            server_did: None,
            available_user_domains: vec!["example.com".to_string()],
            reserved_handles: common::default_reserved_handles(),
            invite_code_required: true,
            links: common::ServerLinksConfig::default(),
            contact: common::ContactConfig::default(),
            blobs: BlobsConfig::default(),
            firehose: FirehoseConfig::default(),
            accounts: common::AccountsConfig::default(),
            admin_devices: common::AdminDevicesConfig::default(),
            oauth: OAuthConfig::default(),
            agent_auth: common::AgentAuthConfig::default(),
            iroh: IrohConfig::default(),
            appview: AppViewConfig::default(),
            chat: ChatConfig::default(),
            // Tests must never make outbound crawl notifications.
            crawlers: CrawlersConfig { urls: vec![] },
            // Rate limiting off by default in tests so unit tests are never throttled; the
            // rate-limit tests opt back in by swapping `rate_limiter` on the returned state.
            rate_limit: RateLimitConfig {
                enabled: false,
                ..RateLimitConfig::default()
            },
            telemetry: TelemetryConfig::default(),
            email: common::EmailConfig::default(),
            admin_token: None,
            signing_key_master_key: None,
            plc_directory_url,
        }),
        db,
        http_client: http_client.clone(),
        dns_provider: None,
        txt_resolver: None,
        well_known_resolver: None,
        // Real HTTP fetcher, but no test exercises it unless the test swaps in a mock fetcher
        // (the JWKS-trust tests in `routes/agent_identity.rs` do exactly that).
        jwks_cache: Arc::new(crate::auth::jwks::JwksCache::new(
            Arc::new(crate::auth::jwks::HttpJwksFetcher::new(http_client.clone())),
            Duration::from_secs(3600),
            // Cooldown disabled so a test's every lookup reaches its injected mock fetcher.
            Duration::ZERO,
        )),
        // Fixed key for tests — predictable JWTs in unit tests.
        jwt_secret: [0x42u8; 32],
        oauth_signing_keypair: test_signing_key,
        dpop_nonces,
        poll_tracker: new_claim_poll_tracker(),
        permission_set_cache: new_permission_set_cache(),
        failed_login_attempts: Arc::new(Mutex::new(HashMap::new())),
        firehose,
        crawlers: Arc::new({
            let mut c = crate::crawler::CrawlerNotifier::new(
                http_client,
                "test.example.com".to_string(),
                &[],
            );
            c.attach_metrics(metrics.clone());
            c
        }),
        iroh: None,
        rate_limiter: Arc::new(crate::rate_limit::RateLimiterState::new(&RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        })),
        // Tests never send real email: the default Log sender logs instead of delivering.
        email: Arc::new(crate::email::LogEmailSender),
        allow_loopback_proxy_targets: true,
        metrics,
        repo_write_locks: Arc::new(crate::record_write::RepoWriteLocks::new()),
        sweeps: Arc::new(crate::sweep_status::SweepStatus::default()),
        started_at: std::time::Instant::now(),
    }
}
