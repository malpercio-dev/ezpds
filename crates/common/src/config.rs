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
    pub oauth: OAuthConfig,
    pub iroh: IrohConfig,
    pub crawlers: CrawlersConfig,
    pub telemetry: TelemetryConfig,
    // Operator authentication for management endpoints (e.g., POST /v1/pds/keys).
    pub admin_token: Option<String>,
    // AES-256-GCM master key for encrypting signing key private keys at rest.
    pub signing_key_master_key: Option<Sensitive<Zeroizing<[u8; 32]>>>,
    // URL of the PLC directory service (default: https://plc.directory)
    pub plc_directory_url: String,
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
    /// Iroh node endpoint for NAT traversal. `None` when not configured.
    pub endpoint: Option<String>,
}

/// Crawler (relay/BGS) notification configuration for `com.atproto.sync.requestCrawl`.
///
/// After every repo commit the relay notifies each configured crawler so newly produced
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
    pub(crate) oauth: OAuthConfig,
    #[serde(default)]
    pub(crate) iroh: IrohConfig,
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
    if let Some(v) = env.get("EZPDS_IROH_ENDPOINT") {
        raw.iroh.endpoint = Some(v.clone());
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
        oauth: raw.oauth,
        iroh: raw.iroh,
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
