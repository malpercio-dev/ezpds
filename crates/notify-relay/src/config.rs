// pattern: Mixed (Functional Core + I/O shell)
//
// Relay configuration: a TOML file overlaid with `EZPDS_NOTIFY_*` environment variables,
// mirroring the pds crate's `config_loader.rs` posture — parse into a `Raw*` shape whose
// fields are all optional, apply env overrides onto that shape, then validate once into
// the immutable `Config` the process runs on. The env map is passed in explicitly so tests
// never depend on the ambient environment.
//
// The APNs block is parsed and validated here but unused until the APNs pipeline lands;
// carrying it from the start means an operator's deployment config doesn't change shape
// when pushes start working.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Everything the relay needs to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// sqlx URL or plain filesystem path for the relay's own SQLite database.
    pub database_url: String,
    /// File holding the iroh node secret key (64 hex chars). Created on first run with
    /// 0600 permissions; the relay's node id — the address every instance dials — is
    /// derived from it, so losing the file re-addresses the relay.
    pub secret_key_path: PathBuf,
    /// Bind the IPv6 QUIC socket. False on a v4-only host (the `[iroh] ipv6` posture in
    /// the pds crate: without it, v6 relay probes fail `NetworkUnreachable` forever).
    pub ipv6: bool,
    /// Enroll any node that asks, with no enrollment code. Off by default: the official
    /// relay hands out codes, a self-run relay can skip the ceremony entirely.
    pub open_enrollment: bool,
    pub apns: ApnsConfig,
    pub rate_limits: RateLimitConfig,
}

/// APNs credentials and the topic allowlist. Parsed now, used by the push pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApnsConfig {
    /// Path to the `.p8` token-auth key.
    pub key_path: Option<PathBuf>,
    /// The `.p8` key's identifier (the JWT header `kid`).
    pub key_id: Option<String>,
    /// Apple developer team id (the JWT `iss`).
    pub team_id: Option<String>,
    /// Bundle ids this relay is willing to push to. Empty means "any topic" — the
    /// self-run posture, where the operator owns every app that could register.
    pub topics: Vec<String>,
    /// Use Apple's sandbox host rather than production.
    pub sandbox: bool,
    /// Endpoint override, the wiremock seam (`EZPDS_NOTIFY_APNS_URL`), mirroring
    /// `EZPDS_PLC_DIRECTORY_URL` in the pds crate.
    pub endpoint: Option<String>,
}

/// Token-bucket sizes, per node id. Zero disables that bucket entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Sustained registration RPCs (`enroll`/`registerHandle`/`dropHandle`) per hour.
    pub registrations_per_hour: u32,
    /// Burst capacity for registration RPCs.
    pub registrations_burst: u32,
    /// Sustained pushes per hour, across all of a node's handles.
    pub pushes_per_hour: u32,
    /// Burst capacity for pushes.
    pub pushes_burst: u32,
    /// Sustained pushes per hour to a **single** handle. Tighter than the node budget on
    /// purpose: the node bucket bounds what one instance costs the relay, this one bounds
    /// what one device is subjected to, and a bug that loops on one registration is the
    /// far likelier failure.
    pub handle_pushes_per_hour: u32,
    /// Burst capacity for pushes to a single handle.
    pub handle_pushes_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            registrations_per_hour: 100,
            registrations_burst: 10,
            pushes_per_hour: 1_000,
            pushes_burst: 50,
            handle_pushes_per_hour: 60,
            handle_pushes_burst: 10,
        }
    }
}

/// Configuration failures, kept separate from I/O so a missing file reads differently
/// from a malformed one.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

// ── Raw (all-optional) shapes ─────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    database_url: Option<String>,
    secret_key_path: Option<String>,
    ipv6: Option<bool>,
    open_enrollment: Option<bool>,
    #[serde(default)]
    apns: RawApns,
    #[serde(default)]
    rate_limits: RawRateLimits,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApns {
    key_path: Option<String>,
    key_id: Option<String>,
    team_id: Option<String>,
    topics: Option<Vec<String>>,
    sandbox: Option<bool>,
    endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimits {
    registrations_per_hour: Option<u32>,
    registrations_burst: Option<u32>,
    pushes_per_hour: Option<u32>,
    pushes_burst: Option<u32>,
    handle_pushes_per_hour: Option<u32>,
    handle_pushes_burst: Option<u32>,
}

// ── Env overlay + validation (Functional Core) ────────────────────────────

fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(ConfigError::Invalid(format!(
            "{key} must be true or false, got {other:?}"
        ))),
    }
}

fn parse_u32(key: &str, value: &str) -> Result<u32, ConfigError> {
    value
        .parse()
        .map_err(|_| ConfigError::Invalid(format!("{key} must be a non-negative integer")))
}

/// Overlay `EZPDS_NOTIFY_*` variables onto a parsed TOML shape. Env always wins — the
/// container deployment sets everything this way and never ships a file.
pub fn apply_env_overrides(
    mut raw: RawConfig,
    env: &HashMap<String, String>,
) -> Result<RawConfig, ConfigError> {
    if let Some(v) = env.get("EZPDS_NOTIFY_DATABASE_URL") {
        raw.database_url = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_SECRET_KEY_PATH") {
        raw.secret_key_path = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_IPV6") {
        raw.ipv6 = Some(parse_bool("EZPDS_NOTIFY_IPV6", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_OPEN_ENROLLMENT") {
        raw.open_enrollment = Some(parse_bool("EZPDS_NOTIFY_OPEN_ENROLLMENT", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_KEY_PATH") {
        raw.apns.key_path = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_KEY_ID") {
        raw.apns.key_id = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_TEAM_ID") {
        raw.apns.team_id = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_TOPICS") {
        raw.apns.topics = Some(
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        );
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_SANDBOX") {
        raw.apns.sandbox = Some(parse_bool("EZPDS_NOTIFY_APNS_SANDBOX", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_APNS_URL") {
        raw.apns.endpoint = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_REGISTRATIONS_PER_HOUR") {
        raw.rate_limits.registrations_per_hour =
            Some(parse_u32("EZPDS_NOTIFY_RATE_REGISTRATIONS_PER_HOUR", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_REGISTRATIONS_BURST") {
        raw.rate_limits.registrations_burst =
            Some(parse_u32("EZPDS_NOTIFY_RATE_REGISTRATIONS_BURST", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_PUSHES_PER_HOUR") {
        raw.rate_limits.pushes_per_hour = Some(parse_u32("EZPDS_NOTIFY_RATE_PUSHES_PER_HOUR", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_PUSHES_BURST") {
        raw.rate_limits.pushes_burst = Some(parse_u32("EZPDS_NOTIFY_RATE_PUSHES_BURST", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_PER_HOUR") {
        raw.rate_limits.handle_pushes_per_hour =
            Some(parse_u32("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_PER_HOUR", v)?);
    }
    if let Some(v) = env.get("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_BURST") {
        raw.rate_limits.handle_pushes_burst =
            Some(parse_u32("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_BURST", v)?);
    }
    Ok(raw)
}

/// Validate a raw shape into the running configuration, filling defaults.
pub fn validate_and_build(raw: RawConfig) -> Result<Config, ConfigError> {
    let defaults = RateLimitConfig::default();
    let rate_limits = RateLimitConfig {
        registrations_per_hour: raw
            .rate_limits
            .registrations_per_hour
            .unwrap_or(defaults.registrations_per_hour),
        registrations_burst: raw
            .rate_limits
            .registrations_burst
            .unwrap_or(defaults.registrations_burst),
        pushes_per_hour: raw
            .rate_limits
            .pushes_per_hour
            .unwrap_or(defaults.pushes_per_hour),
        pushes_burst: raw
            .rate_limits
            .pushes_burst
            .unwrap_or(defaults.pushes_burst),
        handle_pushes_per_hour: raw
            .rate_limits
            .handle_pushes_per_hour
            .unwrap_or(defaults.handle_pushes_per_hour),
        handle_pushes_burst: raw
            .rate_limits
            .handle_pushes_burst
            .unwrap_or(defaults.handle_pushes_burst),
    };
    // A bucket with a refill rate but no capacity would reject its very first request,
    // which reads as an outage rather than a limit. Disabling is expressed by the rate.
    for (name, per_hour, burst) in [
        (
            "registrations",
            rate_limits.registrations_per_hour,
            rate_limits.registrations_burst,
        ),
        (
            "pushes",
            rate_limits.pushes_per_hour,
            rate_limits.pushes_burst,
        ),
        (
            "handle_pushes",
            rate_limits.handle_pushes_per_hour,
            rate_limits.handle_pushes_burst,
        ),
    ] {
        if per_hour > 0 && burst == 0 {
            return Err(ConfigError::Invalid(format!(
                "rate_limits.{name}_burst must be greater than zero unless \
                 {name}_per_hour is zero (which disables the limiter)"
            )));
        }
    }

    let apns = ApnsConfig {
        key_path: raw.apns.key_path.map(PathBuf::from),
        key_id: raw.apns.key_id,
        team_id: raw.apns.team_id,
        topics: raw.apns.topics.unwrap_or_default(),
        sandbox: raw.apns.sandbox.unwrap_or(false),
        endpoint: raw.apns.endpoint,
    };
    // Credentials are all-or-nothing: a half-configured APNs block would bind fine and
    // then fail every push, so it's refused at startup instead.
    let present = [
        apns.key_path.is_some(),
        apns.key_id.is_some(),
        apns.team_id.is_some(),
    ];
    if present.iter().any(|p| *p) && !present.iter().all(|p| *p) {
        return Err(ConfigError::Invalid(
            "apns.key_path, apns.key_id and apns.team_id must be set together".into(),
        ));
    }

    Ok(Config {
        database_url: raw
            .database_url
            .unwrap_or_else(|| "notify-relay.db".to_owned()),
        secret_key_path: raw
            .secret_key_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("notify-relay-node.key")),
        ipv6: raw.ipv6.unwrap_or(true),
        open_enrollment: raw.open_enrollment.unwrap_or(false),
        apns,
        rate_limits,
    })
}

// ── I/O shell ─────────────────────────────────────────────────────────────

/// Collect the `EZPDS_NOTIFY_*` slice of the process environment, refusing non-UTF-8
/// values rather than panicking on them.
pub fn collect_env() -> Result<HashMap<String, String>, ConfigError> {
    let mut map = HashMap::new();
    for (key_os, val_os) in std::env::vars_os() {
        let key = match key_os.to_str() {
            Some(k) if k.starts_with("EZPDS_NOTIFY_") => k.to_owned(),
            _ => continue,
        };
        let val = val_os.into_string().map_err(|_| {
            ConfigError::Invalid(format!(
                "environment variable {key} contains non-UTF-8 data"
            ))
        })?;
        map.insert(key, val);
    }
    Ok(map)
}

/// Load configuration from a TOML file plus an explicit environment map.
pub fn load_with_env(path: &Path, env: &HashMap<String, String>) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&contents)?;
    validate_and_build(apply_env_overrides(raw, env)?)
}

/// Load configuration from environment variables alone — the container posture, where no
/// TOML file is shipped at all.
pub fn load_from_env_only(env: &HashMap<String, String>) -> Result<Config, ConfigError> {
    validate_and_build(apply_env_overrides(RawConfig::default(), env)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_are_the_closed_posture() {
        let config = load_from_env_only(&env(&[])).expect("defaults are valid");
        assert!(
            !config.open_enrollment,
            "enrollment must be closed unless an operator opens it"
        );
        assert!(config.apns.topics.is_empty());
        assert_eq!(config.rate_limits, RateLimitConfig::default());
    }

    #[test]
    fn env_overrides_every_knob() {
        let config = load_from_env_only(&env(&[
            ("EZPDS_NOTIFY_DATABASE_URL", "sqlite::memory:"),
            ("EZPDS_NOTIFY_SECRET_KEY_PATH", "/keys/node.key"),
            ("EZPDS_NOTIFY_IPV6", "false"),
            ("EZPDS_NOTIFY_OPEN_ENROLLMENT", "true"),
            ("EZPDS_NOTIFY_APNS_KEY_PATH", "/keys/apns.p8"),
            ("EZPDS_NOTIFY_APNS_KEY_ID", "ABC123"),
            ("EZPDS_NOTIFY_APNS_TEAM_ID", "TEAM99"),
            (
                "EZPDS_NOTIFY_APNS_TOPICS",
                "org.obsign.identitywallet, org.obsign.admin",
            ),
            ("EZPDS_NOTIFY_APNS_SANDBOX", "true"),
            ("EZPDS_NOTIFY_APNS_URL", "http://127.0.0.1:9000"),
            ("EZPDS_NOTIFY_RATE_REGISTRATIONS_PER_HOUR", "7"),
            ("EZPDS_NOTIFY_RATE_REGISTRATIONS_BURST", "3"),
            ("EZPDS_NOTIFY_RATE_PUSHES_PER_HOUR", "11"),
            ("EZPDS_NOTIFY_RATE_PUSHES_BURST", "5"),
            ("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_PER_HOUR", "13"),
            ("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_BURST", "4"),
        ]))
        .expect("env-only config is valid");

        assert_eq!(config.database_url, "sqlite::memory:");
        assert_eq!(config.secret_key_path, PathBuf::from("/keys/node.key"));
        assert!(!config.ipv6);
        assert!(config.open_enrollment);
        assert_eq!(config.apns.key_id.as_deref(), Some("ABC123"));
        assert_eq!(
            config.apns.topics,
            vec!["org.obsign.identitywallet", "org.obsign.admin"]
        );
        assert!(config.apns.sandbox);
        assert_eq!(
            config.apns.endpoint.as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert_eq!(config.rate_limits.registrations_per_hour, 7);
        assert_eq!(config.rate_limits.pushes_burst, 5);
        assert_eq!(config.rate_limits.handle_pushes_per_hour, 13);
        assert_eq!(config.rate_limits.handle_pushes_burst, 4);
    }

    /// The per-handle budget is the one an operator is least likely to set, so its default
    /// has to be right on its own: tighter than the node budget, and non-zero.
    #[test]
    fn the_per_handle_push_budget_is_tighter_than_the_node_budget_by_default() {
        let limits = load_from_env_only(&env(&[]))
            .expect("defaults are valid")
            .rate_limits;
        assert_eq!(limits.handle_pushes_per_hour, 60);
        assert!(limits.handle_pushes_per_hour < limits.pushes_per_hour);
        assert!(limits.handle_pushes_burst < limits.pushes_burst);
    }

    #[test]
    fn a_per_handle_rate_with_no_burst_is_refused_like_the_others() {
        let err = load_from_env_only(&env(&[("EZPDS_NOTIFY_RATE_HANDLE_PUSHES_BURST", "0")]))
            .expect_err("zero burst under a nonzero rate rejects the first push");
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
    }

    #[test]
    fn toml_file_is_overlaid_by_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notify-relay.toml");
        std::fs::write(
            &path,
            "database_url = \"relay.db\"\nopen_enrollment = true\n\n\
             [apns]\ntopics = [\"org.obsign.identitywallet\"]\n",
        )
        .expect("write config");

        let config = load_with_env(&path, &env(&[("EZPDS_NOTIFY_OPEN_ENROLLMENT", "false")]))
            .expect("file + env config is valid");
        assert_eq!(config.database_url, "relay.db");
        assert!(!config.open_enrollment, "env must win over the file");
        assert_eq!(config.apns.topics, vec!["org.obsign.identitywallet"]);
    }

    #[test]
    fn partial_apns_credentials_are_refused() {
        let err = load_from_env_only(&env(&[("EZPDS_NOTIFY_APNS_KEY_ID", "ABC123")]))
            .expect_err("a lone key id is not a usable APNs credential");
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
    }

    #[test]
    fn a_rate_limit_with_no_burst_is_refused() {
        let err = load_from_env_only(&env(&[("EZPDS_NOTIFY_RATE_PUSHES_BURST", "0")]))
            .expect_err("zero burst under a nonzero rate rejects the first request");
        assert!(matches!(err, ConfigError::Invalid(_)), "got {err:?}");
    }
}
