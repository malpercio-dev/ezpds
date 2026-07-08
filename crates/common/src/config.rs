use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// A wrapper that suppresses [`Debug`] output for sensitive values, printing `***` instead.
///
/// `T` is `pub` to allow deliberate access via `.0` at call sites. This is an explicit choice:
/// any read of the raw value is visible in source, making accidental logging harder to miss in
/// code review.
#[derive(Clone)]
pub struct Sensitive<T>(pub T);

impl<T> std::fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

/// Validated, fully-resolved pds configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_address: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub public_url: String,
    /// Human-readable display name for this instance, surfaced to end users (e.g. the
    /// `resource_name` field of the RFC 9728 protected-resource metadata). Distinct from
    /// `telemetry.service_name` (the machine-facing OTel `service.name` attribute). Defaults
    /// to `"custos"`.
    pub service_name: String,
    pub server_did: Option<String>,
    pub available_user_domains: Vec<String>,
    pub invite_code_required: bool,
    pub links: ServerLinksConfig,
    pub contact: ContactConfig,
    pub blobs: BlobsConfig,
    /// Persistent firehose event log (`repo_seq`) retention / pruning configuration.
    pub firehose: FirehoseConfig,
    /// Account-lifecycle knobs (currently the scheduled-deletion reaper interval).
    pub accounts: AccountsConfig,
    pub oauth: OAuthConfig,
    /// auth.md agent-registration knobs (per-flow enablement, issuer trust list, TTLs).
    pub agent_auth: AgentAuthConfig,
    pub iroh: IrohConfig,
    pub appview: AppViewConfig,
    pub chat: ChatConfig,
    pub crawlers: CrawlersConfig,
    /// Request rate-limiting knobs (global IP + per-endpoint IP + per-account write points).
    pub rate_limit: RateLimitConfig,
    pub telemetry: TelemetryConfig,
    /// Outbound email delivery (password reset, email confirmation, email update).
    pub email: EmailConfig,
    // Operator authentication for management endpoints (e.g., POST /v1/pds/keys). Wrapped in
    // [`Sensitive`] so this break-glass bearer token never leaks via `Debug` (`Config` derives it),
    // matching its sibling secrets `signing_key_master_key` / `email.smtp_password`.
    pub admin_token: Option<Sensitive<String>>,
    // AES-256-GCM master key for encrypting signing key private keys at rest.
    pub signing_key_master_key: Option<Sensitive<Zeroizing<[u8; 32]>>>,
    // URL of the PLC directory service (default: https://plc.directory)
    pub plc_directory_url: String,
}

impl Config {
    /// The bare hostname of the instance's public URL (scheme and path stripped).
    pub fn public_host(&self) -> &str {
        self.public_url
            .strip_prefix("https://")
            .or_else(|| self.public_url.strip_prefix("http://"))
            .unwrap_or(&self.public_url)
            .split('/')
            .next()
            .unwrap_or("")
    }

    /// The DID this server presents publicly (describeServer, the landing page).
    ///
    /// Returns the configured `server_did` verbatim when present. Otherwise derives a
    /// `did:web` DID from the hostname in `public_url` as a placeholder until the
    /// server mints a real DID. A port's `:` is percent-encoded per the did:web
    /// method spec (`did:web:host%3A8080`), since a raw colon reads as a path
    /// segment separator in DID syntax.
    pub fn resolve_server_did(&self) -> String {
        match &self.server_did {
            Some(did) => did.clone(),
            None => format!("did:web:{}", self.public_host().replace(':', "%3A")),
        }
    }
}

/// Optional privacy/ToS links surfaced by `com.atproto.server.describeServer`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerLinksConfig {
    pub privacy_policy: Option<String>,
    pub terms_of_service: Option<String>,
}

/// Optional admin contact surfaced by `com.atproto.server.describeServer`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContactConfig {
    pub email: Option<String>,
}

/// Blob storage configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BlobsConfig {
    /// Maximum blob size in bytes. Default: 50 MiB.
    #[serde(default = "default_max_blob_size")]
    pub max_blob_size: u64,
    /// Per-account storage quota in bytes. Default: 1 GiB.
    #[serde(default = "default_max_storage_per_account")]
    pub max_storage_per_account: u64,
    /// How often the blob garbage collector runs, in seconds. Default: 1800 (30 min).
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,
    /// Grace period, in seconds, before an unreferenced blob is deleted. Applies both to
    /// freshly uploaded blobs that are never referenced and to blobs that lose their last
    /// reference. Default: 21600 (6 hours).
    #[serde(default = "default_temp_ttl_secs")]
    pub temp_ttl_secs: u64,
}

impl Default for BlobsConfig {
    fn default() -> Self {
        Self {
            max_blob_size: default_max_blob_size(),
            max_storage_per_account: default_max_storage_per_account(),
            gc_interval_secs: default_gc_interval_secs(),
            temp_ttl_secs: default_temp_ttl_secs(),
        }
    }
}

/// Persistent firehose event-log (`repo_seq`) retention configuration.
///
/// The `repo_seq` table is append-only and unbounded without a sweep: every `#commit` and
/// `#account` frame (including each commit's CARv1 `blocks`) is retained forever, so on the
/// production SQLite DB it would eventually dominate storage and the Litestream backup. The
/// retention sweep periodically prunes rows below a computed low-water mark, keeping at least
/// the live frontier (`MAX(seq)`) so a reconnecting relay can always resume from the newest
/// retained event.
///
/// A row is pruned when it falls below **any** enabled cutoff (the highest watermark wins), so
/// age can delete an old prefix even when count would keep it, and count can cap a large young
/// backlog even when age would keep it. A knob set to `0` disables that policy. With both at `0`
/// the sweep is a no-op (the log stays append-only, matching the pre-retention behaviour).
#[derive(Debug, Clone, Deserialize)]
pub struct FirehoseConfig {
    /// How often the `repo_seq` retention sweep runs, in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_firehose_gc_interval_secs")]
    pub gc_interval_secs: u64,
    /// Age-based retention: rows whose `sequenced_at` is older than this many seconds are
    /// prunable. Default: 604800 (7 days). Set to `0` to disable age-based pruning.
    #[serde(default = "default_firehose_log_retention_secs")]
    pub log_retention_secs: u64,
    /// Count-based retention: keep at most this many of the newest rows. `0` disables
    /// count-based pruning. Default: `0` (age-based only).
    #[serde(default)]
    pub log_retention_count: u64,
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            gc_interval_secs: default_firehose_gc_interval_secs(),
            log_retention_secs: default_firehose_log_retention_secs(),
            log_retention_count: 0,
        }
    }
}

fn default_firehose_gc_interval_secs() -> u64 {
    60 * 60 // 1 hour
}

fn default_firehose_log_retention_secs() -> u64 {
    7 * 24 * 60 * 60 // 7 days
}

/// Account-lifecycle configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountsConfig {
    /// How often the scheduled-deletion reaper runs, in seconds. The reaper permanently deletes
    /// accounts whose `deleteAfter` instant (recorded by `com.atproto.server.deactivateAccount`)
    /// has elapsed. Default: 3600 (1 hour). Must be > 0 (like the GC intervals, a zero period
    /// would panic `tokio::time::interval`).
    #[serde(default = "default_deletion_reaper_interval_secs")]
    pub deletion_reaper_interval_secs: u64,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            deletion_reaper_interval_secs: default_deletion_reaper_interval_secs(),
        }
    }
}

fn default_deletion_reaper_interval_secs() -> u64 {
    60 * 60 // 1 hour
}

fn default_max_blob_size() -> u64 {
    50 * 1024 * 1024 // 50 MiB
}

fn default_max_storage_per_account() -> u64 {
    1024 * 1024 * 1024 // 1 GiB
}

fn default_gc_interval_secs() -> u64 {
    30 * 60 // 30 minutes
}

fn default_temp_ttl_secs() -> u64 {
    6 * 60 * 60 // 6 hours
}

/// Request rate-limiting configuration (reference-parity limiter set).
///
/// Three limiter families protect a small host from abuse/runaway clients and keep it inside the
/// relay-side host quotas:
///
/// 1. a **global per-IP** request cap (exempting sync backfill so a relay is never throttled),
/// 2. **per-endpoint per-IP** caps on the sensitive auth/account endpoints, and
/// 3. a **per-account repo-write "points"** budget (create=3, update=2, delete=1) over an hourly
///    and a daily window, applied to the four repo-write routes.
///
/// The sliding windows themselves (5 minutes / 1 hour / 1 day) are AT Protocol conventions and are
/// fixed in code; the point/request counts here are the operator-tunable knobs, defaulting to the
/// reference PDS values. A knob set to `0` disables *that specific* limiter while leaving the
/// others active. Set `enabled = false` to turn the whole subsystem off (the test harness does
/// this so unit tests are not throttled).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Master switch. When `false`, the middleware and write-point checks are pure pass-throughs.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Global requests per IP per 5 minutes (reference: 3000). `0` disables. The global limiter
    /// exempts `com.atproto.sync.getRepo` and `com.atproto.sync.subscribeRepos` so relay backfill
    /// and firehose consumption are never throttled.
    #[serde(default = "default_global_ip_per_5min")]
    pub global_ip_per_5min: u64,
    /// `com.atproto.server.createAccount` requests per IP per 5 minutes (reference: 100). `0` disables.
    #[serde(default = "default_create_account_per_5min")]
    pub create_account_per_5min: u64,
    /// `com.atproto.server.createSession` requests per IP per 5 minutes (reference: 30). `0` disables.
    /// Complements the per-identifier failed-login sliding window already applied inside the handler.
    #[serde(default = "default_create_session_per_5min")]
    pub create_session_per_5min: u64,
    /// `com.atproto.server.resetPassword` requests per IP per 5 minutes (reference: 50). `0` disables.
    #[serde(default = "default_reset_password_per_5min")]
    pub reset_password_per_5min: u64,
    /// `com.atproto.identity.updateHandle` requests per IP per 5 minutes (reference: 10). `0` disables.
    #[serde(default = "default_update_handle_per_5min")]
    pub update_handle_per_5min: u64,
    /// Repo-write points per account per hour (reference: 5000). `0` disables the hourly budget.
    #[serde(default = "default_write_points_hourly")]
    pub write_points_hourly: u64,
    /// Repo-write points per account per day (reference: 35000). `0` disables the daily budget.
    #[serde(default = "default_write_points_daily")]
    pub write_points_daily: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            global_ip_per_5min: default_global_ip_per_5min(),
            create_account_per_5min: default_create_account_per_5min(),
            create_session_per_5min: default_create_session_per_5min(),
            reset_password_per_5min: default_reset_password_per_5min(),
            update_handle_per_5min: default_update_handle_per_5min(),
            write_points_hourly: default_write_points_hourly(),
            write_points_daily: default_write_points_daily(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_global_ip_per_5min() -> u64 {
    3000
}

fn default_create_account_per_5min() -> u64 {
    100
}

fn default_create_session_per_5min() -> u64 {
    30
}

fn default_reset_password_per_5min() -> u64 {
    50
}

fn default_update_handle_per_5min() -> u64 {
    10
}

fn default_write_points_hourly() -> u64 {
    5000
}

fn default_write_points_daily() -> u64 {
    35000
}

/// Stub for future OAuth configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OAuthConfig {}

/// auth.md agent-registration configuration (`POST /agent/identity`).
///
/// Every registration flow is **off by default** — an operator opts in per flow. When a flow is
/// disabled the endpoint answers its request with the flow's `*_not_enabled` auth.md error rather
/// than acting, so a fresh install exposes the discovery surface (advertised in the AS metadata)
/// but performs no agent registration until deliberately configured.
///
/// - `service_auth_enabled` gates the `service_auth` (login-hint → claim-ceremony) flow.
/// - `anonymous_enabled` gates the `anonymous` flow (register an ownerless identity — no user
///   identity yet — and receive a pre-claim assertion plus a `claim_token` for an optional later
///   claim ceremony).
/// - `trusted_issuers` gates `identity_assertion`: an ID-JAG whose `iss` is not listed is refused
///   with `issuer_not_enabled`. Each entry carries the issuer's verification key inline (PEM). The
///   dynamic JWKS-URL form of the trust list is a separate follow-up.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentAuthConfig {
    /// Enable the `service_auth` registration flow. Default `false`.
    #[serde(default)]
    pub service_auth_enabled: bool,
    /// Enable the `anonymous` registration flow. Default `false`.
    #[serde(default)]
    pub anonymous_enabled: bool,
    /// Issuers whose ID-JAGs are accepted by the `identity_assertion` flow. Empty (the default)
    /// means every `identity_assertion` request is refused with `issuer_not_enabled`.
    #[serde(default)]
    pub trusted_issuers: Vec<TrustedIssuer>,
    /// Lifetime, in seconds, of a minted service `identity_assertion`. Default 3600 (1 hour).
    #[serde(default = "default_agent_assertion_ttl_secs")]
    pub assertion_ttl_secs: u64,
    /// Lifetime, in seconds, of a claim token returned for a pending claim ceremony. Default 600.
    #[serde(default = "default_agent_claim_token_ttl_secs")]
    pub claim_token_ttl_secs: u64,
    /// Lifetime, in seconds, of a claim ceremony's user code. Default 600.
    #[serde(default = "default_agent_user_code_ttl_secs")]
    pub user_code_ttl_secs: u64,
    /// Maximum age, in seconds, of an ID-JAG's `auth_time` before the flow returns `login_required`
    /// (the assertion is too stale to trust). Default 3600 (1 hour).
    #[serde(default = "default_agent_auth_time_max_age_secs")]
    pub auth_time_max_age_secs: u64,
    /// Scopes granted to a fully-registered agent identity. Defaults to a conservative granular
    /// profile — write-to-own-repo plus blob uploads, with AppView reads reaching the agent through
    /// the read-proxy (which any access-level token may use). See `default_agent_granted_scopes`.
    ///
    /// **Operator warning:** these are enforced through the same granular scope grammar as OAuth
    /// tokens (`auth/oauth_scopes.rs`), so an agent token can only do what these scopes permit. Do
    /// **not** add `account:*` or `identity:*` (or the legacy `com.atproto.access` full-access
    /// scope, or `transition:generic`) unless you intend agents to change account settings, rotate
    /// handles/PLC identity, or otherwise hold account-lifecycle control — that hands an agent the
    /// same reach as the account owner's own wallet.
    #[serde(default = "default_agent_granted_scopes")]
    pub granted_scopes: Vec<String>,
    /// Scopes carried by a pre-claim (anonymous) assertion. Defaults to the same conservative
    /// profile as `granted_scopes`.
    #[serde(default = "default_agent_granted_scopes")]
    pub pre_claim_scopes: Vec<String>,
    /// The human-facing URL where a user enters the claim-ceremony `user_code`. When `None` (the
    /// default) the handler derives `{public_url}/agent/claim`.
    #[serde(default)]
    pub verification_uri: Option<String>,
}

impl Default for AgentAuthConfig {
    fn default() -> Self {
        Self {
            service_auth_enabled: false,
            anonymous_enabled: false,
            trusted_issuers: Vec::new(),
            assertion_ttl_secs: default_agent_assertion_ttl_secs(),
            claim_token_ttl_secs: default_agent_claim_token_ttl_secs(),
            user_code_ttl_secs: default_agent_user_code_ttl_secs(),
            auth_time_max_age_secs: default_agent_auth_time_max_age_secs(),
            granted_scopes: default_agent_granted_scopes(),
            pre_claim_scopes: default_agent_granted_scopes(),
            verification_uri: None,
        }
    }
}

/// One entry in the `identity_assertion` issuer trust list.
///
/// `public_key_pem` is the issuer's public key (PEM) used to verify ID-JAG signatures; `algorithm`
/// names the JWS algorithm (`ES256` by default, also `RS256`/`EdDSA` and their larger cousins).
/// `audience`, when set, overrides the expected `aud` claim (which otherwise defaults to this
/// server's `public_url`).
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedIssuer {
    /// Exact `iss` claim value this entry matches.
    pub issuer: String,
    /// Expected `aud` claim. `None` → the server's `public_url`.
    #[serde(default)]
    pub audience: Option<String>,
    /// PEM-encoded public key used to verify the ID-JAG signature.
    pub public_key_pem: String,
    /// JWS algorithm of the ID-JAG. Default `ES256`.
    #[serde(default = "default_idjag_algorithm")]
    pub algorithm: String,
}

fn default_agent_assertion_ttl_secs() -> u64 {
    60 * 60 // 1 hour
}

fn default_agent_claim_token_ttl_secs() -> u64 {
    10 * 60 // 10 minutes
}

fn default_agent_user_code_ttl_secs() -> u64 {
    10 * 60 // 10 minutes
}

fn default_agent_auth_time_max_age_secs() -> u64 {
    60 * 60 // 1 hour
}

/// The conservative default scope profile for agent-derived credentials.
///
/// A valid granular atproto scope set (per `auth/oauth_scopes.rs`): the required `atproto` base
/// scope, write access to the account's own repo (create/update — deliberately not delete), and
/// blob uploads. It grants **no** `account:*`, `identity:*`, `rpc:*`, or legacy full-access scope,
/// so an agent token cannot change account settings, rotate the handle/PLC identity, manage app
/// passwords, or mint service auth. AppView reads still work: the read-proxy admits any
/// access-level token without requiring an `rpc:` grant. Operators override via
/// `[agent_auth] granted_scopes` / `EZPDS_AGENT_AUTH_GRANTED_SCOPES`.
fn default_agent_granted_scopes() -> Vec<String> {
    vec![
        "atproto".to_string(),
        "repo:*?action=create&action=update".to_string(),
        "blob:*/*".to_string(),
    ]
}

fn default_idjag_algorithm() -> String {
    "ES256".to_string()
}

/// The JWS algorithms accepted for an ID-JAG's `algorithm`. Restricting to this set at config load
/// turns a typo'd algorithm into a startup error rather than a per-request failure.
const SUPPORTED_IDJAG_ALGORITHMS: &[&str] = &["ES256", "ES384", "RS256", "RS384", "RS512", "EdDSA"];

/// Iroh networking configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IrohConfig {
    /// Whether to run the Iroh QUIC endpoint alongside the HTTP server. Off by default, so
    /// a relay (and the test suite) behaves exactly as before unless explicitly enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Optional manual override for the advertised node id. When `None` (the default), the
    /// pds advertises its live endpoint's node id (present only while the tunnel is enabled);
    /// when set, this exact string is advertised instead. The override is read straight from
    /// config by the handler, so it applies even when `enabled` is false (i.e. with no live
    /// endpoint running).
    pub endpoint: Option<String>,
}

/// Bluesky AppView proxy configuration.
///
/// `app.bsky.*` XRPC methods that the PDS does not handle locally are forwarded to this
/// AppView (the catch-all proxy behind `GET/POST /xrpc/:method`). The default targets the
/// public Bluesky AppView; `did` is the value sent as the `atproto-proxy` header so the
/// AppView knows the request is proxied on the user's behalf.
#[derive(Debug, Clone, Deserialize)]
pub struct AppViewConfig {
    /// Base URL of the AppView (scheme + authority, no trailing slash).
    #[serde(default = "default_appview_url")]
    pub url: String,
    /// Service DID (with `#fragment`) of the AppView, sent as `atproto-proxy`.
    #[serde(default = "default_appview_did")]
    pub did: String,
    /// Base URL of the AppView's image CDN (scheme + authority, no trailing slash),
    /// used to build avatar/banner/embed-image URLs for the account's own not-yet-indexed
    /// records. Defaults to Bluesky's public image CDN.
    #[serde(default = "default_appview_cdn_url")]
    pub cdn_url: String,
}

impl Default for AppViewConfig {
    fn default() -> Self {
        Self {
            url: default_appview_url(),
            did: default_appview_did(),
            cdn_url: default_appview_cdn_url(),
        }
    }
}

fn default_appview_url() -> String {
    "https://api.bsky.app".to_string()
}

fn default_appview_did() -> String {
    "did:web:api.bsky.app#bsky_appview".to_string()
}

fn default_appview_cdn_url() -> String {
    "https://cdn.bsky.app".to_string()
}

/// Bluesky chat (DM) service proxy configuration.
///
/// `chat.bsky.*` XRPC methods are not served locally — direct messages live on a dedicated
/// chat service rather than the AppView — so the catch-all proxy forwards them here. The
/// default targets the public Bluesky chat service; `did` is the value sent as the
/// `atproto-proxy` header so the chat service knows the request is proxied on the user's behalf.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatConfig {
    /// Base URL of the chat service (scheme + authority, no trailing slash).
    #[serde(default = "default_chat_url")]
    pub url: String,
    /// Service DID (with `#fragment`) of the chat service, sent as `atproto-proxy`.
    #[serde(default = "default_chat_did")]
    pub did: String,
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            url: default_chat_url(),
            did: default_chat_did(),
        }
    }
}

fn default_chat_url() -> String {
    "https://api.bsky.chat".to_string()
}

fn default_chat_did() -> String {
    "did:web:api.bsky.chat#bsky_chat".to_string()
}

/// Validate a service-proxy base URL (AppView or chat service): it must use an `http(s)` scheme
/// and carry a non-empty authority. The authority check rejects hostless values like `https://`
/// or `http:///path` that pass a bare scheme-prefix test but normalize to a useless base and
/// turn every proxied request into a runtime failure instead of a startup error.
fn validate_proxy_url(field: &str, url: &str) -> Result<(), ConfigError> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| {
            ConfigError::Invalid(format!(
                "{field} must start with http:// or https://, got: {url:?}"
            ))
        })?;
    // A base URL is scheme + authority (+ optional path). A query or fragment is meaningless on
    // a base the proxy only ever appends `/xrpc/{nsid}` to, and would silently corrupt the target,
    // so reject it at load time rather than emit malformed upstream requests.
    if rest.contains('?') || rest.contains('#') {
        return Err(ConfigError::Invalid(format!(
            "{field} must not contain a query or fragment, got: {url:?}"
        )));
    }
    // The authority runs up to the first '/'; everything after is an (optional) path.
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "{field} must include a host, got: {url:?}"
        )));
    }
    Ok(())
}

/// Crawler (relay/BGS) notification configuration for `com.atproto.sync.requestCrawl`.
///
/// After every repo commit the pds notifies each configured crawler so newly produced
/// content is pulled promptly into the wider network. Each entry is a service base URL
/// (e.g. `https://bsky.network`); the pds POSTs to
/// `<url>/xrpc/com.atproto.sync.requestCrawl`. The default is the public bsky.network BGS;
/// set `urls = []` to disable crawl notifications entirely.
#[derive(Debug, Clone, Deserialize)]
pub struct CrawlersConfig {
    #[serde(default = "default_crawler_urls")]
    pub urls: Vec<String>,
}

impl Default for CrawlersConfig {
    fn default() -> Self {
        Self {
            urls: default_crawler_urls(),
        }
    }
}

fn default_crawler_urls() -> Vec<String> {
    vec!["https://bsky.network".to_string()]
}

/// Output encoding for the stdout log stream.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line text. The default.
    #[default]
    Text,
    /// One JSON object per line, so log aggregators and `railway logs` consumers can
    /// filter by field instead of by regex.
    Json,
}

/// OpenTelemetry telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Whether to export traces via OTLP. Off by default — zero overhead when disabled.
    pub enabled: bool,
    /// OTLP gRPC endpoint for the trace exporter.
    pub otlp_endpoint: String,
    /// `service.name` resource attribute reported to the trace backend.
    pub service_name: String,
    /// Whether to register the metrics meter and serve `GET /metrics`. On by default;
    /// when off, no meter is registered and the route returns 404.
    pub metrics_enabled: bool,
    /// Require admin auth on `GET /metrics`. Off by default so a plain Prometheus
    /// scraper works; operators exposing the endpoint beyond a private network can
    /// turn it on.
    pub metrics_require_admin: bool,
    /// Encoding of the stdout log stream (independent of OTLP export).
    pub log_format: LogFormat,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "ezpds-pds".to_string(),
            metrics_enabled: true,
            metrics_require_admin: false,
            log_format: LogFormat::Text,
        }
    }
}

/// Which backend delivers outbound email.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EmailProvider {
    /// No real delivery — the message is logged. Keeps a fresh install and the test suite fully
    /// offline (the pre-outbound-email stub behaviour). The default.
    #[default]
    Log,
    /// Real delivery over SMTP (see the `smtp_*` fields of [`EmailConfig`]).
    Smtp,
}

/// Transport security mode for the SMTP sender.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    /// Implicit TLS (SMTPS) — TLS from connection open, conventionally port 465.
    Implicit,
    /// STARTTLS — upgrade a plaintext connection to TLS, conventionally port 587. The default.
    #[default]
    Starttls,
    /// No transport encryption (plaintext SMTP). For localhost test sinks (MailHog/Mailpit) only;
    /// never send credentials or real mail over this.
    None,
}

/// Outbound email configuration.
///
/// Governs the pluggable email sender behind the password-reset, email-confirmation, and
/// email-update flows. `provider = "log"` (the default) logs messages instead of sending them, so
/// a fresh install and the tests need no mail server; `provider = "smtp"` delivers over SMTP and
/// requires `from` and `smtp_host`.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub provider: EmailProvider,
    /// From address on every message (e.g. `noreply@pds.example.com`). Required for SMTP.
    pub from: Option<String>,
    /// Optional display name paired with `from` (e.g. `Custos PDS`).
    pub from_name: Option<String>,
    /// SMTP relay host. Required when `provider = "smtp"`.
    pub smtp_host: Option<String>,
    /// SMTP relay port. Default 587 (STARTTLS submission).
    pub smtp_port: u16,
    /// SMTP AUTH username. When set (with a password), the sender authenticates.
    pub smtp_username: Option<String>,
    /// SMTP AUTH password. Wrapped in [`Sensitive`] so it never appears in `Debug` output.
    pub smtp_password: Option<Sensitive<String>>,
    /// Transport security mode.
    pub smtp_tls: SmtpTls,
    /// Connect/send timeout for the SMTP transport, in seconds. `send()` is awaited on the request
    /// path, so this bounds how long a slow or unresponsive relay can stall a handler. Default 15.
    pub smtp_timeout_secs: u64,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            provider: EmailProvider::Log,
            from: None,
            from_name: None,
            smtp_host: None,
            smtp_port: default_smtp_port(),
            smtp_username: None,
            smtp_password: None,
            smtp_tls: SmtpTls::Starttls,
            smtp_timeout_secs: default_smtp_timeout_secs(),
        }
    }
}

/// The default `smtp_port` when unset: the conventional port for the default STARTTLS mode.
/// Delegates to [`default_smtp_port_for`] so the fallback lives in one place.
fn default_smtp_port() -> u16 {
    default_smtp_port_for(SmtpTls::Starttls)
}

fn default_smtp_timeout_secs() -> u64 {
    15
}

/// The conventional submission port for a TLS mode: 465 for implicit TLS (SMTPS), 587 otherwise
/// (STARTTLS submission / plaintext). Used to default `smtp_port` when the operator does not set it
/// explicitly, so the port matches the selected `smtp_tls`.
fn default_smtp_port_for(tls: SmtpTls) -> u16 {
    match tls {
        SmtpTls::Implicit => 465,
        SmtpTls::Starttls | SmtpTls::None => 587,
    }
}

/// Raw TOML form of [`EmailConfig`] — all fields optional so a partial `[email]` section (or env
/// overlay) is valid. `smtp_password` is a plain `Option<String>` here (TOML/env carry the raw
/// value); it is wrapped in [`Sensitive`] when the built [`EmailConfig`] is constructed.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct RawEmailConfig {
    pub(crate) provider: Option<EmailProvider>,
    pub(crate) from: Option<String>,
    pub(crate) from_name: Option<String>,
    pub(crate) smtp_host: Option<String>,
    pub(crate) smtp_port: Option<u16>,
    pub(crate) smtp_username: Option<String>,
    pub(crate) smtp_password: Option<String>,
    pub(crate) smtp_tls: Option<SmtpTls>,
    pub(crate) smtp_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawTelemetryConfig {
    pub(crate) enabled: Option<bool>,
    pub(crate) otlp_endpoint: Option<String>,
    pub(crate) service_name: Option<String>,
    pub(crate) metrics_enabled: Option<bool>,
    pub(crate) metrics_require_admin: Option<bool>,
    pub(crate) log_format: Option<LogFormat>,
}

/// Raw TOML-deserialized config with all fields optional to support env-var overlays.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawConfig {
    pub(crate) bind_address: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) data_dir: Option<String>,
    pub(crate) database_url: Option<String>,
    pub(crate) public_url: Option<String>,
    pub(crate) service_name: Option<String>,
    pub(crate) server_did: Option<String>,
    pub(crate) available_user_domains: Option<Vec<String>>,
    pub(crate) invite_code_required: Option<bool>,
    #[serde(default)]
    pub(crate) links: ServerLinksConfig,
    #[serde(default)]
    pub(crate) contact: ContactConfig,
    #[serde(default)]
    pub(crate) blobs: BlobsConfig,
    #[serde(default)]
    pub(crate) firehose: FirehoseConfig,
    #[serde(default)]
    pub(crate) accounts: AccountsConfig,
    #[serde(default)]
    pub(crate) oauth: OAuthConfig,
    #[serde(default)]
    pub(crate) agent_auth: AgentAuthConfig,
    #[serde(default)]
    pub(crate) iroh: IrohConfig,
    #[serde(default)]
    pub(crate) appview: AppViewConfig,
    #[serde(default)]
    pub(crate) chat: ChatConfig,
    #[serde(default)]
    pub(crate) crawlers: CrawlersConfig,
    #[serde(default)]
    pub(crate) rate_limit: RateLimitConfig,
    #[serde(default)]
    pub(crate) telemetry: RawTelemetryConfig,
    #[serde(default)]
    pub(crate) email: RawEmailConfig,
    pub(crate) admin_token: Option<String>,
    pub(crate) plc_directory_url: Option<String>,
    #[serde(skip)]
    pub(crate) signing_key_master_key: Option<[u8; 32]>,
    /// Sentinel field — only present to detect misconfiguration.
    /// signing_key_master_key must be set via env var EZPDS_SIGNING_KEY_MASTER_KEY, not TOML.
    #[serde(rename = "signing_key_master_key")]
    pub(crate) signing_key_master_key_toml_sentinel: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: missing required field '{field}'")]
    MissingField { field: &'static str },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Parse a 64-character hex string into a 32-byte array.
/// Returns a human-readable error string on failure.
fn parse_hex_32(var_name: &str, value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::Invalid(format!(
            "{var_name} must be exactly 64 hex characters (32 bytes), got {} characters",
            value.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(var_name, pair[0])?;
        let lo = hex_nibble(var_name, pair[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(bytes)
}

fn hex_nibble(var_name: &str, b: u8) -> Result<u8, ConfigError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ConfigError::Invalid(format!(
            "{var_name} contains invalid hex character: {:?}",
            char::from(b)
        ))),
    }
}

/// Apply `EZPDS_*` and selected OTel standard environment variable overrides to a [`RawConfig`],
/// returning the updated config.
///
/// Also reads `OTEL_SERVICE_NAME` (without the `EZPDS_` prefix) as a standard OpenTelemetry
/// convention for overriding the telemetry service name.
///
/// Receives the environment as a map so this function stays isolated from I/O (no `std::env`
/// access). Takes `raw` by value and returns it so callers can chain calls without mutation.
pub(crate) fn apply_env_overrides(
    mut raw: RawConfig,
    env: &HashMap<String, String>,
) -> Result<RawConfig, ConfigError> {
    if let Some(v) = env.get("EZPDS_BIND_ADDRESS") {
        raw.bind_address = Some(v.clone());
    }
    // Precedence: EZPDS_PORT → PORT → 8080 (set during validate_and_build)
    if let Some(v) = env.get("EZPDS_PORT") {
        raw.port = Some(v.parse::<u16>().map_err(|e| {
            ConfigError::Invalid(format!("EZPDS_PORT is not a valid port number: '{v}': {e}"))
        })?);
    } else if let Some(v) = env.get("PORT") {
        raw.port = Some(v.parse::<u16>().map_err(|e| {
            ConfigError::Invalid(format!("PORT is not a valid port number: '{v}': {e}"))
        })?);
    }
    if let Some(v) = env.get("EZPDS_DATA_DIR") {
        raw.data_dir = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_DATABASE_URL") {
        raw.database_url = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_PUBLIC_URL") {
        raw.public_url = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_SERVICE_NAME") {
        raw.service_name = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_SERVER_DID") {
        raw.server_did = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_INVITE_CODE_REQUIRED") {
        raw.invite_code_required = Some(v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_INVITE_CODE_REQUIRED is not a valid boolean: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_AVAILABLE_USER_DOMAINS") {
        raw.available_user_domains = Some(
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        );
    }
    if let Some(v) = env.get("EZPDS_TELEMETRY_ENABLED") {
        raw.telemetry.enabled = Some(v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_TELEMETRY_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_OTLP_ENDPOINT") {
        raw.telemetry.otlp_endpoint = Some(v.clone());
    }
    if let Some(v) = env.get("OTEL_SERVICE_NAME") {
        raw.telemetry.service_name = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_METRICS_ENABLED") {
        raw.telemetry.metrics_enabled = Some(v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_METRICS_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_METRICS_REQUIRE_ADMIN") {
        raw.telemetry.metrics_require_admin = Some(v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_METRICS_REQUIRE_ADMIN is not a valid boolean: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_LOG_FORMAT") {
        raw.telemetry.log_format = Some(match v.as_str() {
            "text" => LogFormat::Text,
            "json" => LogFormat::Json,
            other => {
                return Err(ConfigError::Invalid(format!(
                    "EZPDS_LOG_FORMAT must be 'text' or 'json', got: '{other}'"
                )))
            }
        });
    }
    if let Some(v) = env.get("EZPDS_IROH_ENABLED") {
        raw.iroh.enabled = v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_IROH_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?;
    }
    if let Some(v) = env.get("EZPDS_IROH_ENDPOINT") {
        raw.iroh.endpoint = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_APPVIEW_URL") {
        raw.appview.url = v.clone();
    }
    if let Some(v) = env.get("EZPDS_APPVIEW_DID") {
        raw.appview.did = v.clone();
    }
    if let Some(v) = env.get("EZPDS_APPVIEW_CDN_URL") {
        raw.appview.cdn_url = v.clone();
    }
    if let Some(v) = env.get("EZPDS_CHAT_URL") {
        raw.chat.url = v.clone();
    }
    if let Some(v) = env.get("EZPDS_CHAT_DID") {
        raw.chat.did = v.clone();
    }
    // Comma-separated crawler base URLs; an empty value disables crawl notifications.
    if let Some(v) = env.get("EZPDS_CRAWLERS") {
        raw.crawlers.urls = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    // Rate-limit overrides. A small local helper keeps the repetitive u64 parse+error-wrap in one
    // place; each knob is independent so a partial overlay (e.g. only the global cap) is fine.
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_ENABLED") {
        raw.rate_limit.enabled = v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_RATE_LIMIT_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?;
    }
    let parse_u64 = |name: &str, v: &str| -> Result<u64, ConfigError> {
        v.parse::<u64>().map_err(|e| {
            ConfigError::Invalid(format!(
                "{name} is not a valid non-negative integer: '{v}': {e}"
            ))
        })
    };
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN") {
        raw.rate_limit.global_ip_per_5min = parse_u64("EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_CREATE_ACCOUNT_PER_5MIN") {
        raw.rate_limit.create_account_per_5min =
            parse_u64("EZPDS_RATE_LIMIT_CREATE_ACCOUNT_PER_5MIN", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_CREATE_SESSION_PER_5MIN") {
        raw.rate_limit.create_session_per_5min =
            parse_u64("EZPDS_RATE_LIMIT_CREATE_SESSION_PER_5MIN", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_RESET_PASSWORD_PER_5MIN") {
        raw.rate_limit.reset_password_per_5min =
            parse_u64("EZPDS_RATE_LIMIT_RESET_PASSWORD_PER_5MIN", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_UPDATE_HANDLE_PER_5MIN") {
        raw.rate_limit.update_handle_per_5min =
            parse_u64("EZPDS_RATE_LIMIT_UPDATE_HANDLE_PER_5MIN", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_WRITE_POINTS_HOURLY") {
        raw.rate_limit.write_points_hourly = parse_u64("EZPDS_RATE_LIMIT_WRITE_POINTS_HOURLY", v)?;
    }
    if let Some(v) = env.get("EZPDS_RATE_LIMIT_WRITE_POINTS_DAILY") {
        raw.rate_limit.write_points_daily = parse_u64("EZPDS_RATE_LIMIT_WRITE_POINTS_DAILY", v)?;
    }
    // Periodic-sweep interval overrides (blob GC, firehose retention, deletion reaper). Only the
    // u64 parse happens here — a zero interval is rejected later by `validate_and_build`, the same
    // check the TOML path goes through (a zero period would panic `tokio::time::interval`).
    if let Some(v) = env.get("EZPDS_BLOBS_GC_INTERVAL_SECS") {
        raw.blobs.gc_interval_secs = parse_u64("EZPDS_BLOBS_GC_INTERVAL_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_FIREHOSE_GC_INTERVAL_SECS") {
        raw.firehose.gc_interval_secs = parse_u64("EZPDS_FIREHOSE_GC_INTERVAL_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS") {
        raw.accounts.deletion_reaper_interval_secs =
            parse_u64("EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS", v)?;
    }
    // Agent-auth (auth.md) scalar/bool overrides. The issuer trust list is a list of structs
    // carrying PEM keys, which does not map to a flat env var — it stays TOML-only.
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED") {
        raw.agent_auth.service_auth_enabled = v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_ANONYMOUS_ENABLED") {
        raw.agent_auth.anonymous_enabled = v.parse::<bool>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_AGENT_AUTH_ANONYMOUS_ENABLED is not a valid boolean: '{v}': {e}"
            ))
        })?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_ASSERTION_TTL_SECS") {
        raw.agent_auth.assertion_ttl_secs = parse_u64("EZPDS_AGENT_AUTH_ASSERTION_TTL_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_CLAIM_TOKEN_TTL_SECS") {
        raw.agent_auth.claim_token_ttl_secs =
            parse_u64("EZPDS_AGENT_AUTH_CLAIM_TOKEN_TTL_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_USER_CODE_TTL_SECS") {
        raw.agent_auth.user_code_ttl_secs = parse_u64("EZPDS_AGENT_AUTH_USER_CODE_TTL_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_AUTH_TIME_MAX_AGE_SECS") {
        raw.agent_auth.auth_time_max_age_secs =
            parse_u64("EZPDS_AGENT_AUTH_AUTH_TIME_MAX_AGE_SECS", v)?;
    }
    if let Some(v) = env.get("EZPDS_AGENT_AUTH_VERIFICATION_URI") {
        raw.agent_auth.verification_uri = Some(v.clone());
    }
    // Email overrides. `provider` and `smtp_tls` parse from the same lowercase tokens the TOML
    // form accepts; an unrecognised value is a hard config error rather than a silent fallback.
    if let Some(v) = env.get("EZPDS_EMAIL_PROVIDER") {
        raw.email.provider = Some(parse_email_provider(v)?);
    }
    if let Some(v) = env.get("EZPDS_EMAIL_FROM") {
        raw.email.from = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_EMAIL_FROM_NAME") {
        raw.email.from_name = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_HOST") {
        raw.email.smtp_host = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_PORT") {
        raw.email.smtp_port = Some(v.parse::<u16>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_EMAIL_SMTP_PORT is not a valid port number: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_USERNAME") {
        raw.email.smtp_username = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_PASSWORD") {
        raw.email.smtp_password = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_TLS") {
        raw.email.smtp_tls = Some(parse_smtp_tls(v)?);
    }
    if let Some(v) = env.get("EZPDS_EMAIL_SMTP_TIMEOUT_SECS") {
        raw.email.smtp_timeout_secs = Some(v.parse::<u64>().map_err(|e| {
            ConfigError::Invalid(format!(
                "EZPDS_EMAIL_SMTP_TIMEOUT_SECS is not a valid non-negative integer: '{v}': {e}"
            ))
        })?);
    }
    if let Some(v) = env.get("EZPDS_ADMIN_TOKEN") {
        raw.admin_token = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_PLC_DIRECTORY_URL") {
        raw.plc_directory_url = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_SIGNING_KEY_MASTER_KEY") {
        raw.signing_key_master_key = Some(parse_hex_32("EZPDS_SIGNING_KEY_MASTER_KEY", v)?);
    }
    Ok(raw)
}

/// Parse the `EZPDS_EMAIL_PROVIDER` env value into an [`EmailProvider`], matching the lowercase
/// tokens the TOML form uses.
fn parse_email_provider(value: &str) -> Result<EmailProvider, ConfigError> {
    match value {
        "log" => Ok(EmailProvider::Log),
        "smtp" => Ok(EmailProvider::Smtp),
        other => Err(ConfigError::Invalid(format!(
            "EZPDS_EMAIL_PROVIDER must be 'log' or 'smtp', got: {other:?}"
        ))),
    }
}

/// Parse the `EZPDS_EMAIL_SMTP_TLS` env value into an [`SmtpTls`], matching the lowercase tokens
/// the TOML form uses.
fn parse_smtp_tls(value: &str) -> Result<SmtpTls, ConfigError> {
    match value {
        "implicit" => Ok(SmtpTls::Implicit),
        "starttls" => Ok(SmtpTls::Starttls),
        "none" => Ok(SmtpTls::None),
        other => Err(ConfigError::Invalid(format!(
            "EZPDS_EMAIL_SMTP_TLS must be 'implicit', 'starttls', or 'none', got: {other:?}"
        ))),
    }
}

/// Build and validate the [`EmailConfig`] from its raw form.
///
/// When `provider = "smtp"`, both `from` and `smtp_host` are required — without them the sender
/// could not construct or route a message, so we reject at load time rather than fail every send
/// at runtime. The password is moved into a [`Sensitive`] wrapper so it never leaks via `Debug`.
fn build_email_config(raw: RawEmailConfig) -> Result<EmailConfig, ConfigError> {
    let provider = raw.provider.unwrap_or_default();
    let from = raw.from.filter(|s| !s.is_empty());
    let smtp_host = raw.smtp_host.filter(|s| !s.is_empty());
    let smtp_tls = raw.smtp_tls.unwrap_or_default();
    // Treat empty-string credentials (an empty env override or TOML value) as unset, so we don't
    // authenticate with a blank username/password. Filtering here also feeds the plaintext-TLS
    // check below.
    let smtp_username = raw.smtp_username.filter(|s| !s.is_empty());
    let smtp_password = raw.smtp_password.filter(|s| !s.is_empty());
    let smtp_timeout_secs = raw
        .smtp_timeout_secs
        .unwrap_or_else(default_smtp_timeout_secs);

    // A zero timeout is `Duration::from_secs(0)`, which lettre treats as "no timeout" (an
    // unbounded wait) — the opposite of what a timeout knob should do. Reject it rather than
    // silently disable the guard; the field has no "disable" semantics.
    if smtp_timeout_secs == 0 {
        return Err(ConfigError::Invalid(
            "email.smtp_timeout_secs must be > 0 (0 would disable the SMTP timeout entirely)"
                .to_string(),
        ));
    }

    if provider == EmailProvider::Smtp {
        if from.is_none() {
            return Err(ConfigError::Invalid(
                "email.from is required when email.provider = \"smtp\"".to_string(),
            ));
        }
        if smtp_host.is_none() {
            return Err(ConfigError::Invalid(
                "email.smtp_host is required when email.provider = \"smtp\"".to_string(),
            ));
        }
        // Refuse to attach credentials over an unencrypted connection: the sender would send the
        // SMTP password in plaintext. Reject at load time rather than rely on operator discipline.
        if smtp_tls == SmtpTls::None && (smtp_username.is_some() || smtp_password.is_some()) {
            return Err(ConfigError::Invalid(
                "email.smtp_tls = \"none\" must not be combined with smtp_username/smtp_password (credentials would be sent unencrypted)".to_string(),
            ));
        }
    }

    Ok(EmailConfig {
        provider,
        from,
        from_name: raw.from_name.filter(|s| !s.is_empty()),
        smtp_host,
        // Default the port to the convention for the chosen TLS mode (465 for implicit TLS, 587
        // otherwise) so an operator who sets `smtp_tls = "implicit"` doesn't silently get 587.
        smtp_port: raw
            .smtp_port
            .unwrap_or_else(|| default_smtp_port_for(smtp_tls)),
        smtp_username,
        smtp_password: smtp_password.map(Sensitive),
        smtp_tls,
        smtp_timeout_secs,
    })
}

/// Validate a [`RawConfig`] and build a [`Config`], applying defaults for optional fields.
///
/// Required fields: `data_dir`, `public_url`, `available_user_domains` (non-empty).
/// Defaults: `bind_address = "0.0.0.0"`, `port = 8080`, `invite_code_required = true`,
/// `database_url = "{data_dir}/relay.db"` (derived; fails if `data_dir` is non-UTF-8),
/// `telemetry.enabled = false`, `telemetry.otlp_endpoint = "http://localhost:4317"`,
/// `telemetry.service_name = "ezpds-pds"`.
/// When provided, `telemetry.otlp_endpoint` must be non-empty and start with `http://` or
/// `https://`.
pub(crate) fn validate_and_build(raw: RawConfig) -> Result<Config, ConfigError> {
    // Reject signing_key_master_key if it appears in TOML (must be env var only).
    if raw.signing_key_master_key_toml_sentinel.is_some() {
        return Err(ConfigError::Invalid(
            "signing_key_master_key must be set via env var EZPDS_SIGNING_KEY_MASTER_KEY, not pds.toml (security-sensitive field)".to_string()
        ));
    }

    let bind_address = raw.bind_address.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = raw.port.unwrap_or(8080);
    let data_dir: PathBuf = raw
        .data_dir
        .ok_or(ConfigError::MissingField { field: "data_dir" })?
        .into();
    let database_url = match raw.database_url {
        Some(url) => url,
        None => data_dir
            .join("relay.db")
            .to_str()
            .ok_or_else(|| {
                ConfigError::Invalid(
                    "data_dir contains non-UTF-8 characters, cannot derive database_url"
                        .to_string(),
                )
            })?
            .to_owned(),
    };
    let public_url = raw.public_url.ok_or(ConfigError::MissingField {
        field: "public_url",
    })?;
    if !public_url.starts_with("https://") {
        return Err(ConfigError::Invalid(format!(
            "public_url must start with https:// (RFC 8414 requires HTTPS for the OAuth issuer), got: {public_url:?}"
        )));
    }
    let available_user_domains = raw
        .available_user_domains
        .ok_or(ConfigError::MissingField {
            field: "available_user_domains",
        })?;
    if available_user_domains.is_empty() {
        return Err(ConfigError::Invalid(
            "available_user_domains must contain at least one domain".to_string(),
        ));
    }
    let service_name = raw
        .service_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "custos".to_string());
    let invite_code_required = raw.invite_code_required.unwrap_or(true);
    let plc_directory_url = raw
        .plc_directory_url
        .unwrap_or_else(|| "https://plc.directory".to_string());

    let telemetry_defaults = TelemetryConfig::default();
    let otlp_endpoint = raw
        .telemetry
        .otlp_endpoint
        .unwrap_or(telemetry_defaults.otlp_endpoint);
    if otlp_endpoint.is_empty() {
        return Err(ConfigError::Invalid(
            "telemetry.otlp_endpoint must not be empty".to_string(),
        ));
    }
    if !otlp_endpoint.starts_with("http://") && !otlp_endpoint.starts_with("https://") {
        return Err(ConfigError::Invalid(format!(
            "telemetry.otlp_endpoint must start with http:// or https://, got: {otlp_endpoint:?}"
        )));
    }
    let telemetry = TelemetryConfig {
        enabled: raw.telemetry.enabled.unwrap_or(telemetry_defaults.enabled),
        otlp_endpoint,
        service_name: raw
            .telemetry
            .service_name
            .unwrap_or(telemetry_defaults.service_name),
        metrics_enabled: raw
            .telemetry
            .metrics_enabled
            .unwrap_or(telemetry_defaults.metrics_enabled),
        metrics_require_admin: raw
            .telemetry
            .metrics_require_admin
            .unwrap_or(telemetry_defaults.metrics_require_admin),
        log_format: raw
            .telemetry
            .log_format
            .unwrap_or(telemetry_defaults.log_format),
    };

    if raw.iroh.endpoint.as_deref() == Some("") {
        return Err(ConfigError::Invalid(
            "iroh.endpoint must not be empty".to_string(),
        ));
    }

    for url in &raw.crawlers.urls {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(ConfigError::Invalid(format!(
                "crawlers.urls entries must start with http:// or https://, got: {url:?}"
            )));
        }
    }

    validate_proxy_url("appview.url", &raw.appview.url)?;
    // Trim a trailing slash so the proxy can join paths as `{url}/xrpc/...` unambiguously.
    let appview = AppViewConfig {
        url: raw.appview.url.trim_end_matches('/').to_string(),
        did: raw.appview.did,
        // Trim a trailing slash too: `cdn_url` is concatenated as `{cdn_url}/img/...` in
        // LocalViewer::image_url, so a configured `https://cdn.bsky.app/` would otherwise
        // produce `//img/...`. Matches the documented "no trailing slash" contract.
        cdn_url: raw.appview.cdn_url.trim_end_matches('/').to_string(),
    };

    validate_proxy_url("chat.url", &raw.chat.url)?;
    // Trim a trailing slash so the proxy can join paths as `{url}/xrpc/...` unambiguously.
    let chat = ChatConfig {
        url: raw.chat.url.trim_end_matches('/').to_string(),
        did: raw.chat.did,
    };

    // A zero sweep interval would panic `tokio::time::interval` at startup (it asserts a
    // non-zero period). Both GC tasks (blob + firehose) feed their interval straight from these
    // knobs, so reject zero here at config load rather than letting a bad value crash boot.
    if raw.blobs.gc_interval_secs == 0 {
        return Err(ConfigError::Invalid(
            "blobs.gc_interval_secs must be > 0 (tokio::time::interval panics on a zero period)"
                .to_string(),
        ));
    }
    if raw.firehose.gc_interval_secs == 0 {
        return Err(ConfigError::Invalid(
            "firehose.gc_interval_secs must be > 0 (tokio::time::interval panics on a zero period)"
                .to_string(),
        ));
    }
    if raw.accounts.deletion_reaper_interval_secs == 0 {
        return Err(ConfigError::Invalid(
            "accounts.deletion_reaper_interval_secs must be > 0 (tokio::time::interval panics on a zero period)"
                .to_string(),
        ));
    }

    let email = build_email_config(raw.email)?;

    // Agent-auth (auth.md) validation. The feature ships off by default, but a present-but-broken
    // config should fail loudly at load rather than surface as a per-request 500.
    if raw.agent_auth.assertion_ttl_secs == 0 {
        return Err(ConfigError::Invalid(
            "agent_auth.assertion_ttl_secs must be > 0 (a zero-lifetime assertion is born expired)"
                .to_string(),
        ));
    }
    if raw.agent_auth.claim_token_ttl_secs == 0 {
        return Err(ConfigError::Invalid(
            "agent_auth.claim_token_ttl_secs must be > 0".to_string(),
        ));
    }
    if raw.agent_auth.user_code_ttl_secs == 0 {
        return Err(ConfigError::Invalid(
            "agent_auth.user_code_ttl_secs must be > 0".to_string(),
        ));
    }
    if let Some(uri) = &raw.agent_auth.verification_uri {
        if !uri.starts_with("https://") && !uri.starts_with("http://") {
            return Err(ConfigError::Invalid(format!(
                "agent_auth.verification_uri must start with http:// or https://, got: {uri:?}"
            )));
        }
    }
    for issuer in &raw.agent_auth.trusted_issuers {
        if issuer.issuer.is_empty() {
            return Err(ConfigError::Invalid(
                "agent_auth.trusted_issuers entries must set a non-empty issuer".to_string(),
            ));
        }
        if issuer.public_key_pem.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "agent_auth trusted issuer {:?} must set a non-empty public_key_pem",
                issuer.issuer
            )));
        }
        if !SUPPORTED_IDJAG_ALGORITHMS.contains(&issuer.algorithm.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "agent_auth trusted issuer {:?} has unsupported algorithm {:?} (supported: {})",
                issuer.issuer,
                issuer.algorithm,
                SUPPORTED_IDJAG_ALGORITHMS.join(", ")
            )));
        }
    }

    Ok(Config {
        bind_address,
        port,
        data_dir,
        database_url,
        public_url,
        service_name,
        server_did: raw.server_did,
        available_user_domains,
        invite_code_required,
        links: raw.links,
        contact: raw.contact,
        blobs: raw.blobs,
        firehose: raw.firehose,
        accounts: raw.accounts,
        oauth: raw.oauth,
        agent_auth: raw.agent_auth,
        iroh: raw.iroh,
        appview,
        chat,
        crawlers: raw.crawlers,
        rate_limit: raw.rate_limit,
        telemetry,
        email,
        admin_token: raw.admin_token.map(Sensitive),
        signing_key_master_key: raw
            .signing_key_master_key
            .map(|k| Sensitive(Zeroizing::new(k))),
        plc_directory_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_raw() -> RawConfig {
        RawConfig {
            data_dir: Some("/var/pds".to_string()),
            public_url: Some("https://pds.example.com".to_string()),
            available_user_domains: Some(vec!["example.com".to_string()]),
            ..Default::default()
        }
    }

    #[test]
    fn parses_minimal_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.data_dir, PathBuf::from("/var/pds"));
        assert_eq!(config.database_url, "/var/pds/relay.db");
        assert_eq!(config.public_url, "https://pds.example.com");
    }

    #[test]
    fn parses_full_toml() {
        let toml = r#"
            bind_address = "127.0.0.1"
            port = 3000
            data_dir = "/data"
            database_url = "sqlite:///data/custom.db"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 3000);
        assert_eq!(config.data_dir, PathBuf::from("/data"));
        assert_eq!(config.database_url, "sqlite:///data/custom.db");
    }

    #[test]
    fn parses_stub_sections() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [blobs]

            [oauth]

            [iroh]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.public_url, "https://pds.example.com");
    }

    #[test]
    fn firehose_section_defaults_when_absent() {
        // No [firehose] section at all: the serde defaults must kick in (1h sweep interval, 7-day
        // age retention, count disabled).
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.firehose.gc_interval_secs, 60 * 60);
        assert_eq!(config.firehose.log_retention_secs, 7 * 24 * 60 * 60);
        assert_eq!(config.firehose.log_retention_count, 0);
    }

    #[test]
    fn firehose_section_overrides_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [firehose]
            gc_interval_secs = 300
            log_retention_secs = 0
            log_retention_count = 5000
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.firehose.gc_interval_secs, 300);
        assert_eq!(config.firehose.log_retention_secs, 0);
        assert_eq!(config.firehose.log_retention_count, 5000);
    }

    #[test]
    fn blobs_gc_interval_secs_zero_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [blobs]
            gc_interval_secs = 0
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn firehose_gc_interval_secs_zero_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [firehose]
            gc_interval_secs = 0
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn accounts_section_defaults_when_absent() {
        // No [accounts] section: the reaper interval falls back to the 1-hour default.
        let raw: RawConfig = toml::from_str(
            r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
        "#,
        )
        .unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.accounts.deletion_reaper_interval_secs, 60 * 60);
    }

    #[test]
    fn accounts_deletion_reaper_interval_secs_zero_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [accounts]
            deletion_reaper_interval_secs = 0
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_auth_defaults_when_absent() {
        // No [agent_auth] section: every flow is off, TTLs fall back to their defaults, and the
        // issuer trust list is empty.
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(!config.agent_auth.service_auth_enabled);
        assert!(!config.agent_auth.anonymous_enabled);
        assert!(config.agent_auth.trusted_issuers.is_empty());
        assert_eq!(config.agent_auth.assertion_ttl_secs, 3600);
        assert_eq!(config.agent_auth.claim_token_ttl_secs, 600);
        // The default is a conservative granular profile, not the legacy full-access scope.
        assert_eq!(
            config.agent_auth.granted_scopes,
            vec!["atproto", "repo:*?action=create&action=update", "blob:*/*"]
        );
        assert!(config.agent_auth.verification_uri.is_none());
    }

    #[test]
    fn agent_auth_parses_trusted_issuer_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [agent_auth]
            service_auth_enabled = true

            [[agent_auth.trusted_issuers]]
            issuer = "https://issuer.example.com"
            public_key_pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(config.agent_auth.service_auth_enabled);
        assert_eq!(config.agent_auth.trusted_issuers.len(), 1);
        let issuer = &config.agent_auth.trusted_issuers[0];
        assert_eq!(issuer.issuer, "https://issuer.example.com");
        assert_eq!(issuer.algorithm, "ES256"); // default
        assert!(issuer.audience.is_none());
    }

    #[test]
    fn agent_auth_zero_assertion_ttl_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [agent_auth]
            assertion_ttl_secs = 0
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_auth_unsupported_issuer_algorithm_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [[agent_auth.trusted_issuers]]
            issuer = "https://issuer.example.com"
            algorithm = "HS256"
            public_key_pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_auth_empty_issuer_pem_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [[agent_auth.trusted_issuers]]
            issuer = "https://issuer.example.com"
            public_key_pem = "   "
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn agent_auth_env_override_enables_service_auth() {
        let env = HashMap::from([(
            "EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED".to_string(),
            "true".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(config.agent_auth.service_auth_enabled);
    }

    #[test]
    fn database_url_defaults_to_data_dir() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.database_url, "/var/pds/relay.db");
    }

    #[test]
    fn env_override_port() {
        let env = HashMap::from([("EZPDS_PORT".to_string(), "9090".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 9090);
    }

    #[test]
    fn env_override_wins_over_toml_value() {
        // env always takes precedence over explicit TOML values
        let toml = r#"
            data_dir = "/var/pds"
            port = 3000
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let env = HashMap::from([("EZPDS_PORT".to_string(), "9999".to_string())]);
        let raw = apply_env_overrides(raw, &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 9999);
    }

    #[test]
    fn env_override_all_fields() {
        let env = HashMap::from([
            ("EZPDS_BIND_ADDRESS".to_string(), "127.0.0.1".to_string()),
            ("EZPDS_PORT".to_string(), "4000".to_string()),
            ("EZPDS_DATA_DIR".to_string(), "/tmp/pds".to_string()),
            (
                "EZPDS_DATABASE_URL".to_string(),
                "sqlite:///tmp/relay.db".to_string(),
            ),
            (
                "EZPDS_PUBLIC_URL".to_string(),
                "https://pds.test".to_string(),
            ),
            (
                "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
                "pds.test".to_string(),
            ),
        ]);
        let raw = apply_env_overrides(RawConfig::default(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 4000);
        assert_eq!(config.data_dir, PathBuf::from("/tmp/pds"));
        assert_eq!(config.database_url, "sqlite:///tmp/relay.db");
        assert_eq!(config.public_url, "https://pds.test");
    }

    #[test]
    fn env_override_invalid_port_returns_error() {
        let env = HashMap::from([("EZPDS_PORT".to_string(), "not_a_port".to_string())]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_PORT"));
        assert!(err.to_string().contains("not_a_port"));
    }

    #[test]
    fn env_override_blobs_gc_interval() {
        let env = HashMap::from([("EZPDS_BLOBS_GC_INTERVAL_SECS".to_string(), "5".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.blobs.gc_interval_secs, 5);
    }

    #[test]
    fn env_override_firehose_gc_interval() {
        let env = HashMap::from([(
            "EZPDS_FIREHOSE_GC_INTERVAL_SECS".to_string(),
            "7".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.firehose.gc_interval_secs, 7);
    }

    #[test]
    fn env_override_deletion_reaper_interval() {
        let env = HashMap::from([(
            "EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS".to_string(),
            "1".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.accounts.deletion_reaper_interval_secs, 1);
    }

    #[test]
    fn env_override_invalid_sweep_interval_returns_error() {
        let env = HashMap::from([(
            "EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS".to_string(),
            "soon".to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err
            .to_string()
            .contains("EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS"));
        assert!(err.to_string().contains("soon"));
    }

    #[test]
    fn env_override_zero_sweep_interval_rejected_by_validation() {
        let env = HashMap::from([("EZPDS_BLOBS_GC_INTERVAL_SECS".to_string(), "0".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("blobs.gc_interval_secs"));
    }

    #[test]
    fn missing_data_dir_returns_error() {
        let raw = RawConfig {
            public_url: Some("https://pds.example.com".to_string()),
            ..Default::default()
        };
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::MissingField { field: "data_dir" }
        ));
    }

    #[test]
    fn missing_public_url_returns_error() {
        let raw = RawConfig {
            data_dir: Some("/var/pds".to_string()),
            ..Default::default()
        };
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::MissingField {
                field: "public_url"
            }
        ));
    }

    // --- describeServer config fields ---

    #[test]
    fn parses_describe_server_fields_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            server_did = "did:plc:abc123"
            available_user_domains = ["pds.example.com", "alt.example.com"]
            invite_code_required = false

            [links]
            privacy_policy = "https://example.com/privacy"
            terms_of_service = "https://example.com/tos"

            [contact]
            email = "admin@example.com"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.server_did.as_deref(), Some("did:plc:abc123"));
        assert_eq!(
            config.available_user_domains,
            vec!["pds.example.com", "alt.example.com"]
        );
        assert!(!config.invite_code_required);
        assert_eq!(
            config.links.privacy_policy.as_deref(),
            Some("https://example.com/privacy")
        );
        assert_eq!(
            config.links.terms_of_service.as_deref(),
            Some("https://example.com/tos")
        );
        assert_eq!(config.contact.email.as_deref(), Some("admin@example.com"));
    }

    #[test]
    fn public_url_without_https_scheme_returns_error() {
        for bad_url in &[
            "pds.example.com",
            "http://pds.example.com",
            "ftp://pds.example.com",
            "",
        ] {
            let raw = RawConfig {
                data_dir: Some("/var/pds".to_string()),
                public_url: Some(bad_url.to_string()),
                available_user_domains: Some(vec!["example.com".to_string()]),
                ..Default::default()
            };
            let err = validate_and_build(raw).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid(_)),
                "expected Invalid error for public_url={bad_url:?}, got: {err}"
            );
            assert!(
                err.to_string().contains("https://"),
                "error message should mention https:// for public_url={bad_url:?}"
            );
        }
    }

    #[test]
    fn available_user_domains_missing_returns_error() {
        let raw = RawConfig {
            data_dir: Some("/var/pds".to_string()),
            public_url: Some("https://pds.example.com".to_string()),
            ..Default::default()
        };
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::MissingField {
                field: "available_user_domains"
            }
        ));
    }

    #[test]
    fn available_user_domains_empty_returns_invalid_error() {
        let raw = RawConfig {
            data_dir: Some("/var/pds".to_string()),
            public_url: Some("https://pds.example.com".to_string()),
            available_user_domains: Some(vec![]),
            ..Default::default()
        };
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err
            .to_string()
            .contains("available_user_domains must contain at least one domain"));
    }

    #[test]
    fn invite_code_required_defaults_to_true() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.invite_code_required);
    }

    #[test]
    fn server_did_is_optional() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.server_did.is_none());
    }

    #[test]
    fn public_host_strips_scheme_and_path() {
        let mut raw = minimal_raw();
        raw.public_url = Some("https://pds.example.com/some/path".to_string());
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.public_host(), "pds.example.com");
    }

    #[test]
    fn resolve_server_did_prefers_configured_did() {
        let mut raw = minimal_raw();
        raw.server_did = Some("did:plc:abc123".to_string());
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.resolve_server_did(), "did:plc:abc123");
    }

    #[test]
    fn resolve_server_did_derives_did_web_from_public_url() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.resolve_server_did(), "did:web:pds.example.com");
    }

    #[test]
    fn resolve_server_did_percent_encodes_port() {
        let mut raw = minimal_raw();
        raw.public_url = Some("https://pds.example.com:8443".to_string());
        let config = validate_and_build(raw).unwrap();
        assert_eq!(
            config.resolve_server_did(),
            "did:web:pds.example.com%3A8443"
        );
    }

    #[test]
    fn links_section_optional() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.links.privacy_policy.is_none());
        assert!(config.links.terms_of_service.is_none());
    }

    #[test]
    fn contact_section_optional() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.contact.email.is_none());
    }

    #[test]
    fn env_override_server_did() {
        let env = HashMap::from([("EZPDS_SERVER_DID".to_string(), "did:plc:xyz".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.server_did.as_deref(), Some("did:plc:xyz"));
    }

    #[test]
    fn env_override_invite_code_required_false() {
        let env = HashMap::from([(
            "EZPDS_INVITE_CODE_REQUIRED".to_string(),
            "false".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(!config.invite_code_required);
    }

    #[test]
    fn env_override_invite_code_required_invalid_returns_error() {
        let env = HashMap::from([(
            "EZPDS_INVITE_CODE_REQUIRED".to_string(),
            "maybe".to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_INVITE_CODE_REQUIRED"));
    }

    #[test]
    fn env_override_available_user_domains_comma_separated() {
        let env = HashMap::from([(
            "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
            "foo.com, bar.com".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.available_user_domains, vec!["foo.com", "bar.com"]);
    }

    // --- telemetry config tests ---

    #[test]
    fn telemetry_defaults_to_disabled() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(!config.telemetry.enabled);
        assert_eq!(config.telemetry.otlp_endpoint, "http://localhost:4317");
        assert_eq!(config.telemetry.service_name, "ezpds-pds");
    }

    #[test]
    fn parses_telemetry_section_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [telemetry]
            enabled = true
            otlp_endpoint = "http://otel-collector:4317"
            service_name = "my-pds"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(config.telemetry.enabled);
        assert_eq!(config.telemetry.otlp_endpoint, "http://otel-collector:4317");
        assert_eq!(config.telemetry.service_name, "my-pds");
    }

    #[test]
    fn env_override_telemetry_enabled() {
        let env = HashMap::from([("EZPDS_TELEMETRY_ENABLED".to_string(), "true".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(config.telemetry.enabled);
    }

    #[test]
    fn env_override_otlp_endpoint() {
        let env = HashMap::from([(
            "EZPDS_OTLP_ENDPOINT".to_string(),
            "http://custom:4317".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.telemetry.otlp_endpoint, "http://custom:4317");
    }

    #[test]
    fn env_override_otel_service_name() {
        let env = HashMap::from([("OTEL_SERVICE_NAME".to_string(), "my-service".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.telemetry.service_name, "my-service");
    }

    #[test]
    fn otel_service_name_env_overrides_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [telemetry]
            service_name = "from-toml"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let env = HashMap::from([("OTEL_SERVICE_NAME".to_string(), "from-env".to_string())]);
        let raw = apply_env_overrides(raw, &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.telemetry.service_name, "from-env");
    }

    #[test]
    fn metrics_and_log_format_defaults() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.telemetry.metrics_enabled);
        assert!(!config.telemetry.metrics_require_admin);
        assert_eq!(config.telemetry.log_format, LogFormat::Text);
    }

    #[test]
    fn parses_metrics_and_log_format_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [telemetry]
            metrics_enabled = false
            metrics_require_admin = true
            log_format = "json"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(!config.telemetry.metrics_enabled);
        assert!(config.telemetry.metrics_require_admin);
        assert_eq!(config.telemetry.log_format, LogFormat::Json);
    }

    #[test]
    fn env_override_metrics_enabled() {
        let env = HashMap::from([("EZPDS_METRICS_ENABLED".to_string(), "false".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(!config.telemetry.metrics_enabled);
    }

    #[test]
    fn env_override_metrics_require_admin() {
        let env = HashMap::from([(
            "EZPDS_METRICS_REQUIRE_ADMIN".to_string(),
            "true".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert!(config.telemetry.metrics_require_admin);
    }

    #[test]
    fn env_override_log_format() {
        let env = HashMap::from([("EZPDS_LOG_FORMAT".to_string(), "json".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.telemetry.log_format, LogFormat::Json);
    }

    #[test]
    fn env_override_log_format_invalid_returns_error() {
        let env = HashMap::from([("EZPDS_LOG_FORMAT".to_string(), "yaml".to_string())]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn env_override_metrics_enabled_invalid_returns_error() {
        let env = HashMap::from([("EZPDS_METRICS_ENABLED".to_string(), "maybe".to_string())]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn service_name_defaults_to_custos() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.service_name, "custos");
    }

    #[test]
    fn service_name_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
            service_name = "Custos Relay"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.service_name, "Custos Relay");
    }

    #[test]
    fn env_override_service_name() {
        let env = HashMap::from([("EZPDS_SERVICE_NAME".to_string(), "My Instance".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.service_name, "My Instance");
    }

    #[test]
    fn service_name_env_overrides_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
            service_name = "from-toml"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let env = HashMap::from([("EZPDS_SERVICE_NAME".to_string(), "from-env".to_string())]);
        let raw = apply_env_overrides(raw, &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.service_name, "from-env");
    }

    #[test]
    fn blank_service_name_falls_back_to_default() {
        // An empty or whitespace-only override must not produce an empty display name.
        let env = HashMap::from([("EZPDS_SERVICE_NAME".to_string(), "   ".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.service_name, "custos");
    }

    #[test]
    fn env_override_telemetry_enabled_invalid_returns_error() {
        let env = HashMap::from([("EZPDS_TELEMETRY_ENABLED".to_string(), "maybe".to_string())]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_TELEMETRY_ENABLED"));
    }

    // --- admin_token and signing_key_master_key config fields ---

    #[test]
    fn admin_token_is_optional() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.admin_token.is_none());
    }

    #[test]
    fn signing_key_master_key_is_optional() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert!(config.signing_key_master_key.is_none());
    }

    #[test]
    fn env_override_admin_token() {
        let env = HashMap::from([("EZPDS_ADMIN_TOKEN".to_string(), "secret-token".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(
            config.admin_token.as_ref().map(|s| s.0.as_str()),
            Some("secret-token")
        );
    }

    #[test]
    fn env_override_signing_key_master_key_valid_hex() {
        // 64 valid hex chars → [u8; 32]
        let hex_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let env = HashMap::from([(
            "EZPDS_SIGNING_KEY_MASTER_KEY".to_string(),
            hex_key.to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        let expected: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        assert_eq!(
            config.signing_key_master_key.as_ref().map(|s| &*s.0),
            Some(&expected)
        );
    }

    #[test]
    fn env_override_signing_key_master_key_wrong_length_returns_error() {
        // 62 hex chars (31 bytes) — wrong length
        let short_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let env = HashMap::from([(
            "EZPDS_SIGNING_KEY_MASTER_KEY".to_string(),
            short_key.to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_SIGNING_KEY_MASTER_KEY"));
    }

    #[test]
    fn env_override_signing_key_master_key_non_hex_returns_error() {
        // contains 'g' which is not a valid hex character
        let invalid_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fgg";
        let env = HashMap::from([(
            "EZPDS_SIGNING_KEY_MASTER_KEY".to_string(),
            invalid_key.to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_SIGNING_KEY_MASTER_KEY"));
    }

    #[test]
    fn iroh_endpoint_parses_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [iroh]
            endpoint = "abc123nodeid"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.iroh.endpoint, Some("abc123nodeid".to_string()));
    }

    #[test]
    fn iroh_endpoint_defaults_to_none() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.iroh.endpoint, None);
    }

    #[test]
    fn env_override_iroh_endpoint() {
        let env = HashMap::from([("EZPDS_IROH_ENDPOINT".to_string(), "nodeabc123".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.iroh.endpoint, Some("nodeabc123".to_string()));
    }

    #[test]
    fn iroh_endpoint_empty_string_returns_error() {
        let mut raw = minimal_raw();
        raw.iroh.endpoint = Some(String::new());
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(
            err.to_string().contains("iroh.endpoint"),
            "error message must mention iroh.endpoint"
        );
    }

    // --- crawlers config tests ---

    #[test]
    fn crawlers_default_to_bsky_network() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.crawlers.urls, vec!["https://bsky.network"]);
    }

    #[test]
    fn crawlers_parse_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [crawlers]
            urls = ["https://relay1.example", "https://relay2.example"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(
            config.crawlers.urls,
            vec!["https://relay1.example", "https://relay2.example"]
        );
    }

    #[test]
    fn crawlers_empty_list_disables_notifications() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [crawlers]
            urls = []
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(config.crawlers.urls.is_empty());
    }

    #[test]
    fn env_override_crawlers_comma_separated() {
        let env = HashMap::from([(
            "EZPDS_CRAWLERS".to_string(),
            "https://a.example, https://b.example".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(
            config.crawlers.urls,
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn env_override_crawlers_empty_disables() {
        let env = HashMap::from([("EZPDS_CRAWLERS".to_string(), String::new())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(config.crawlers.urls.is_empty());
    }

    // --- rate limit config tests ---

    #[test]
    fn rate_limit_defaults_to_reference_values() {
        let config = validate_and_build(minimal_raw()).unwrap();
        let rl = &config.rate_limit;
        assert!(rl.enabled);
        assert_eq!(rl.global_ip_per_5min, 3000);
        assert_eq!(rl.create_account_per_5min, 100);
        assert_eq!(rl.create_session_per_5min, 30);
        assert_eq!(rl.reset_password_per_5min, 50);
        assert_eq!(rl.update_handle_per_5min, 10);
        assert_eq!(rl.write_points_hourly, 5000);
        assert_eq!(rl.write_points_daily, 35000);
    }

    #[test]
    fn rate_limit_partial_toml_section_keeps_other_defaults() {
        // Only `enabled` and one knob are set; every other knob must fall back to its default.
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [rate_limit]
            enabled = false
            global_ip_per_5min = 10
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.global_ip_per_5min, 10);
        assert_eq!(config.rate_limit.write_points_daily, 35000);
    }

    #[test]
    fn env_override_rate_limit_fields() {
        let env = HashMap::from([
            ("EZPDS_RATE_LIMIT_ENABLED".to_string(), "false".to_string()),
            (
                "EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN".to_string(),
                "1234".to_string(),
            ),
            (
                "EZPDS_RATE_LIMIT_WRITE_POINTS_HOURLY".to_string(),
                "42".to_string(),
            ),
            (
                "EZPDS_RATE_LIMIT_WRITE_POINTS_DAILY".to_string(),
                "99".to_string(),
            ),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(!config.rate_limit.enabled);
        assert_eq!(config.rate_limit.global_ip_per_5min, 1234);
        assert_eq!(config.rate_limit.write_points_hourly, 42);
        assert_eq!(config.rate_limit.write_points_daily, 99);
    }

    #[test]
    fn env_override_rate_limit_invalid_integer_returns_error() {
        let env = HashMap::from([(
            "EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN".to_string(),
            "lots".to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err
            .to_string()
            .contains("EZPDS_RATE_LIMIT_GLOBAL_IP_PER_5MIN"));
    }

    #[test]
    fn env_override_rate_limit_invalid_bool_returns_error() {
        let env = HashMap::from([(
            "EZPDS_RATE_LIMIT_ENABLED".to_string(),
            "sometimes".to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_RATE_LIMIT_ENABLED"));
    }

    // --- appview config tests ---

    #[test]
    fn appview_defaults_to_public_bsky() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.appview.url, "https://api.bsky.app");
        assert_eq!(config.appview.did, "did:web:api.bsky.app#bsky_appview");
    }

    #[test]
    fn appview_parses_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [appview]
            url = "https://appview.example"
            did = "did:web:appview.example#bsky_appview"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.appview.url, "https://appview.example");
        assert_eq!(config.appview.did, "did:web:appview.example#bsky_appview");
    }

    #[test]
    fn appview_url_trailing_slash_is_trimmed() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [appview]
            url = "https://appview.example/"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.appview.url, "https://appview.example");
    }

    #[test]
    fn appview_rejects_non_http_scheme() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [appview]
            url = "ftp://appview.example"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("appview.url"));
    }

    #[test]
    fn env_override_appview_url_and_did() {
        let env = HashMap::from([
            (
                "EZPDS_APPVIEW_URL".to_string(),
                "https://appview.test".to_string(),
            ),
            (
                "EZPDS_APPVIEW_DID".to_string(),
                "did:web:appview.test#bsky_appview".to_string(),
            ),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.appview.url, "https://appview.test");
        assert_eq!(config.appview.did, "did:web:appview.test#bsky_appview");
    }

    // --- chat config tests ---

    #[test]
    fn chat_defaults_to_public_bsky_chat() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.chat.url, "https://api.bsky.chat");
        assert_eq!(config.chat.did, "did:web:api.bsky.chat#bsky_chat");
    }

    #[test]
    fn chat_parses_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [chat]
            url = "https://chat.example"
            did = "did:web:chat.example#bsky_chat"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.chat.url, "https://chat.example");
        assert_eq!(config.chat.did, "did:web:chat.example#bsky_chat");
    }

    #[test]
    fn chat_url_trailing_slash_is_trimmed() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [chat]
            url = "https://chat.example/"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.chat.url, "https://chat.example");
    }

    #[test]
    fn chat_rejects_non_http_scheme() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [chat]
            url = "ftp://chat.example"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("chat.url"));
    }

    #[test]
    fn proxy_urls_reject_missing_authority() {
        // Hostless values pass a bare scheme-prefix test but normalize to a useless base, so they
        // must be rejected at startup rather than 503ing every proxied request. Covers both the
        // AppView and chat proxy URLs, which share one validator.
        for (section, url) in [
            ("appview", "https://"),
            ("appview", "http:///feed"),
            ("chat", "https://"),
            ("chat", "http:///convo"),
        ] {
            let toml = format!(
                r#"
                data_dir = "/var/pds"
                public_url = "https://pds.example.com"
                available_user_domains = ["example.com"]

                [{section}]
                url = "{url}"
                "#
            );
            let raw: RawConfig = toml::from_str(&toml).unwrap();
            let err = validate_and_build(raw).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid(_)),
                "{url:?} should be rejected"
            );
            assert!(err.to_string().contains(&format!("{section}.url")));
        }
    }

    #[test]
    fn proxy_urls_reject_query_or_fragment() {
        // A base URL only ever has `/xrpc/{nsid}` appended, so a query/fragment would corrupt the
        // target; reject it at startup rather than send malformed upstream requests.
        for (section, url) in [
            ("appview", "https://api.bsky.app?foo=bar"),
            ("appview", "https://api.bsky.app#frag"),
            ("chat", "https://api.bsky.chat?foo=bar"),
            ("chat", "https://api.bsky.chat#frag"),
        ] {
            let toml = format!(
                r#"
                data_dir = "/var/pds"
                public_url = "https://pds.example.com"
                available_user_domains = ["example.com"]

                [{section}]
                url = "{url}"
                "#
            );
            let raw: RawConfig = toml::from_str(&toml).unwrap();
            let err = validate_and_build(raw).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid(_)),
                "{url:?} should be rejected"
            );
            assert!(err.to_string().contains(&format!("{section}.url")));
        }
    }

    #[test]
    fn env_override_chat_url_and_did() {
        let env = HashMap::from([
            (
                "EZPDS_CHAT_URL".to_string(),
                "https://chat.test".to_string(),
            ),
            (
                "EZPDS_CHAT_DID".to_string(),
                "did:web:chat.test#bsky_chat".to_string(),
            ),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.chat.url, "https://chat.test");
        assert_eq!(config.chat.did, "did:web:chat.test#bsky_chat");
    }

    #[test]
    fn crawlers_reject_non_http_scheme() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [crawlers]
            urls = ["ftp://relay.example"]
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("crawlers.urls"));
    }

    #[test]
    fn signing_key_master_key_in_toml_returns_error() {
        // Operator mistakenly puts signing_key_master_key in pds.toml instead of env var.
        // The sentinel field must catch this and reject the configuration.
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]
            signing_key_master_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_SIGNING_KEY_MASTER_KEY"));
    }

    // --- PORT fallback tests ---

    #[test]
    fn port_fallback_uses_port_env_when_ezpds_port_absent() {
        let env = HashMap::from([("PORT".to_string(), "3000".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 3000);
    }

    #[test]
    fn ezpds_port_takes_precedence_over_port() {
        let env = HashMap::from([
            ("EZPDS_PORT".to_string(), "5000".to_string()),
            ("PORT".to_string(), "3000".to_string()),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 5000);
    }

    #[test]
    fn port_defaults_to_8080_when_both_absent() {
        let env = HashMap::new();
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 8080);
    }

    #[test]
    fn invalid_port_env_var_returns_error() {
        let env = HashMap::from([("PORT".to_string(), "invalid_port".to_string())]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("PORT"));
    }

    // --- email config tests ---

    #[test]
    fn email_defaults_to_log_provider() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.email.provider, EmailProvider::Log);
        assert_eq!(config.email.smtp_port, 587);
        assert_eq!(config.email.smtp_tls, SmtpTls::Starttls);
        assert!(config.email.from.is_none());
    }

    #[test]
    fn parses_email_section_from_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            from_name = "Custos PDS"
            smtp_host = "smtp.example.com"
            smtp_port = 465
            smtp_username = "mailer"
            smtp_password = "secret"
            smtp_tls = "implicit"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.email.provider, EmailProvider::Smtp);
        assert_eq!(
            config.email.from.as_deref(),
            Some("noreply@pds.example.com")
        );
        assert_eq!(config.email.from_name.as_deref(), Some("Custos PDS"));
        assert_eq!(config.email.smtp_host.as_deref(), Some("smtp.example.com"));
        assert_eq!(config.email.smtp_port, 465);
        assert_eq!(config.email.smtp_username.as_deref(), Some("mailer"));
        assert_eq!(
            config.email.smtp_password.as_ref().map(|s| s.0.as_str()),
            Some("secret")
        );
        assert_eq!(config.email.smtp_tls, SmtpTls::Implicit);
    }

    #[test]
    fn smtp_provider_requires_from() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            smtp_host = "smtp.example.com"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("email.from"));
    }

    #[test]
    fn smtp_provider_requires_host() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("email.smtp_host"));
    }

    #[test]
    fn email_env_overrides() {
        let env = HashMap::from([
            ("EZPDS_EMAIL_PROVIDER".to_string(), "smtp".to_string()),
            (
                "EZPDS_EMAIL_FROM".to_string(),
                "noreply@pds.test".to_string(),
            ),
            ("EZPDS_EMAIL_SMTP_HOST".to_string(), "smtp.test".to_string()),
            ("EZPDS_EMAIL_SMTP_PORT".to_string(), "2525".to_string()),
            // implicit TLS so credentials are permitted (plaintext + creds is rejected).
            ("EZPDS_EMAIL_SMTP_TLS".to_string(), "implicit".to_string()),
            (
                "EZPDS_EMAIL_SMTP_PASSWORD".to_string(),
                "hunter2".to_string(),
            ),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.email.provider, EmailProvider::Smtp);
        assert_eq!(config.email.from.as_deref(), Some("noreply@pds.test"));
        assert_eq!(config.email.smtp_host.as_deref(), Some("smtp.test"));
        assert_eq!(config.email.smtp_port, 2525);
        assert_eq!(config.email.smtp_tls, SmtpTls::Implicit);
        assert_eq!(
            config.email.smtp_password.as_ref().map(|s| s.0.as_str()),
            Some("hunter2")
        );
    }

    #[test]
    fn email_provider_env_rejects_unknown_value() {
        let env = HashMap::from([(
            "EZPDS_EMAIL_PROVIDER".to_string(),
            "carrierpigeon".to_string(),
        )]);
        let err = apply_env_overrides(minimal_raw(), &env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_EMAIL_PROVIDER"));
    }

    #[test]
    fn email_password_is_redacted_in_debug() {
        // The Sensitive wrapper must keep the SMTP password out of Debug output (Config is Debug).
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            smtp_host = "smtp.example.com"
            smtp_password = "topsecret"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        let debug = format!("{:?}", config.email);
        assert!(
            !debug.contains("topsecret"),
            "password must not leak in Debug"
        );
        assert!(debug.contains("***"), "Sensitive should render as ***");
    }

    #[test]
    fn admin_token_is_redacted_in_debug() {
        // The break-glass admin bearer token must stay out of Debug output (Config derives Debug).
        let env = HashMap::from([(
            "EZPDS_ADMIN_TOKEN".to_string(),
            "super-secret-admin".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("super-secret-admin"),
            "admin token must not leak in Debug"
        );
        assert!(debug.contains("***"), "Sensitive should render as ***");
    }

    #[test]
    fn smtp_implicit_tls_defaults_port_to_465() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            smtp_host = "smtp.example.com"
            smtp_tls = "implicit"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.email.smtp_port, 465);
    }

    #[test]
    fn smtp_starttls_defaults_port_to_587() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            smtp_host = "smtp.example.com"
            smtp_tls = "starttls"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.email.smtp_port, 587);
    }

    #[test]
    fn explicit_smtp_port_overrides_tls_default() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            smtp_host = "smtp.example.com"
            smtp_tls = "implicit"
            smtp_port = 2525
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.email.smtp_port, 2525);
    }

    #[test]
    fn smtp_none_tls_with_credentials_is_rejected() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
            available_user_domains = ["example.com"]

            [email]
            provider = "smtp"
            from = "noreply@pds.example.com"
            smtp_host = "localhost"
            smtp_tls = "none"
            smtp_username = "mailer"
            smtp_password = "secret"
        "#;
        let raw: RawConfig = toml::from_str(toml).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("smtp_tls = \"none\""));
    }

    #[test]
    fn empty_smtp_password_is_treated_as_unset() {
        // An empty-string override must not produce Some("") — otherwise the sender would try to
        // authenticate with a blank password.
        let env = HashMap::from([
            ("EZPDS_EMAIL_PROVIDER".to_string(), "smtp".to_string()),
            (
                "EZPDS_EMAIL_FROM".to_string(),
                "noreply@pds.test".to_string(),
            ),
            ("EZPDS_EMAIL_SMTP_HOST".to_string(), "smtp.test".to_string()),
            ("EZPDS_EMAIL_SMTP_PASSWORD".to_string(), "".to_string()),
        ]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert!(config.email.smtp_password.is_none());
    }

    #[test]
    fn smtp_timeout_defaults_to_15s_and_can_be_overridden() {
        let config = validate_and_build(minimal_raw()).unwrap();
        assert_eq!(config.email.smtp_timeout_secs, 15);

        let env = HashMap::from([(
            "EZPDS_EMAIL_SMTP_TIMEOUT_SECS".to_string(),
            "45".to_string(),
        )]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let config = validate_and_build(raw).unwrap();
        assert_eq!(config.email.smtp_timeout_secs, 45);
    }

    #[test]
    fn zero_smtp_timeout_is_rejected() {
        let env = HashMap::from([("EZPDS_EMAIL_SMTP_TIMEOUT_SECS".to_string(), "0".to_string())]);
        let raw = apply_env_overrides(minimal_raw(), &env).unwrap();
        let err = validate_and_build(raw).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("smtp_timeout_secs"));
    }
}
