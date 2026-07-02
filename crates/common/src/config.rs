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
    pub server_did: Option<String>,
    pub available_user_domains: Vec<String>,
    pub invite_code_required: bool,
    pub links: ServerLinksConfig,
    pub contact: ContactConfig,
    pub blobs: BlobsConfig,
    /// Persistent firehose event log (`repo_seq`) retention / pruning configuration.
    pub firehose: FirehoseConfig,
    pub oauth: OAuthConfig,
    pub iroh: IrohConfig,
    pub appview: AppViewConfig,
    pub chat: ChatConfig,
    pub crawlers: CrawlersConfig,
    pub telemetry: TelemetryConfig,
    // Operator authentication for management endpoints (e.g., POST /v1/pds/keys).
    pub admin_token: Option<String>,
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
    /// server mints a real DID.
    pub fn resolve_server_did(&self) -> String {
        match &self.server_did {
            Some(did) => did.clone(),
            None => format!("did:web:{}", self.public_host()),
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

/// Stub for future OAuth configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OAuthConfig {}

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
}

impl Default for AppViewConfig {
    fn default() -> Self {
        Self {
            url: default_appview_url(),
            did: default_appview_did(),
        }
    }
}

fn default_appview_url() -> String {
    "https://api.bsky.app".to_string()
}

fn default_appview_did() -> String {
    "did:web:api.bsky.app#bsky_appview".to_string()
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

/// OpenTelemetry telemetry configuration.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Whether to export traces via OTLP. Off by default — zero overhead when disabled.
    pub enabled: bool,
    /// OTLP gRPC endpoint for the trace exporter.
    pub otlp_endpoint: String,
    /// `service.name` resource attribute reported to the trace backend.
    pub service_name: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "ezpds-pds".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawTelemetryConfig {
    pub(crate) enabled: Option<bool>,
    pub(crate) otlp_endpoint: Option<String>,
    pub(crate) service_name: Option<String>,
}

/// Raw TOML-deserialized config with all fields optional to support env-var overlays.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawConfig {
    pub(crate) bind_address: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) data_dir: Option<String>,
    pub(crate) database_url: Option<String>,
    pub(crate) public_url: Option<String>,
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
    pub(crate) oauth: OAuthConfig,
    #[serde(default)]
    pub(crate) iroh: IrohConfig,
    #[serde(default)]
    pub(crate) appview: AppViewConfig,
    #[serde(default)]
    pub(crate) chat: ChatConfig,
    #[serde(default)]
    pub(crate) crawlers: CrawlersConfig,
    #[serde(default)]
    pub(crate) telemetry: RawTelemetryConfig,
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

    Ok(Config {
        bind_address,
        port,
        data_dir,
        database_url,
        public_url,
        server_did: raw.server_did,
        available_user_domains,
        invite_code_required,
        links: raw.links,
        contact: raw.contact,
        blobs: raw.blobs,
        firehose: raw.firehose,
        oauth: raw.oauth,
        iroh: raw.iroh,
        appview,
        chat,
        crawlers: raw.crawlers,
        telemetry,
        admin_token: raw.admin_token,
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
        assert_eq!(config.admin_token.as_deref(), Some("secret-token"));
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
}
