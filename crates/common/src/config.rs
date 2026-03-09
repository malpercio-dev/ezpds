// pattern: Functional Core

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Validated, fully-resolved relay configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_address: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub database_url: String,
    pub public_url: String,
    pub blobs: BlobsConfig,
    pub oauth: OAuthConfig,
    pub iroh: IrohConfig,
}

/// Stub for future blob storage configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BlobsConfig {}

/// Stub for future OAuth configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OAuthConfig {}

/// Stub for future Iroh networking configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct IrohConfig {}

/// Raw TOML-deserialized config with all fields optional to support env-var overlays.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct RawConfig {
    pub(crate) bind_address: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) data_dir: Option<String>,
    pub(crate) database_url: Option<String>,
    pub(crate) public_url: Option<String>,
    #[serde(default)]
    pub(crate) blobs: BlobsConfig,
    #[serde(default)]
    pub(crate) oauth: OAuthConfig,
    #[serde(default)]
    pub(crate) iroh: IrohConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration: missing required field '{field}'")]
    MissingField { field: &'static str },
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Apply `EZPDS_*` environment variable overrides to a `RawConfig`.
///
/// Receives the environment as a map so this function stays pure (no `std::env` access).
pub(crate) fn apply_env_overrides(
    raw: &mut RawConfig,
    env: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    if let Some(v) = env.get("EZPDS_BIND_ADDRESS") {
        raw.bind_address = Some(v.clone());
    }
    if let Some(v) = env.get("EZPDS_PORT") {
        raw.port = Some(v.parse::<u16>().map_err(|_| {
            ConfigError::Invalid(format!("EZPDS_PORT is not a valid port number: '{v}'"))
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
    Ok(())
}

/// Validate a `RawConfig` and build a `Config`, applying defaults for optional fields.
pub(crate) fn validate_and_build(raw: RawConfig) -> Result<Config, ConfigError> {
    let bind_address = raw.bind_address.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = raw.port.unwrap_or(8080);
    let data_dir: PathBuf = raw
        .data_dir
        .ok_or(ConfigError::MissingField { field: "data_dir" })?
        .into();
    let database_url = raw
        .database_url
        .unwrap_or_else(|| data_dir.join("relay.db").to_string_lossy().into_owned());
    let public_url = raw.public_url.ok_or(ConfigError::MissingField {
        field: "public_url",
    })?;

    Ok(Config {
        bind_address,
        port,
        data_dir,
        database_url,
        public_url,
        blobs: raw.blobs,
        oauth: raw.oauth,
        iroh: raw.iroh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_raw() -> RawConfig {
        RawConfig {
            data_dir: Some("/var/pds".to_string()),
            public_url: Some("https://pds.example.com".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn parses_minimal_toml() {
        let toml = r#"
            data_dir = "/var/pds"
            public_url = "https://pds.example.com"
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
        let mut raw = minimal_raw();
        let env = HashMap::from([("EZPDS_PORT".to_string(), "9090".to_string())]);
        apply_env_overrides(&mut raw, &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.port, 9090);
    }

    #[test]
    fn env_override_all_fields() {
        let mut raw = RawConfig::default();
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
        ]);
        apply_env_overrides(&mut raw, &env).unwrap();
        let config = validate_and_build(raw).unwrap();

        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 4000);
        assert_eq!(config.data_dir, PathBuf::from("/tmp/pds"));
        assert_eq!(config.database_url, "sqlite:///tmp/relay.db");
        assert_eq!(config.public_url, "https://pds.test");
    }

    #[test]
    fn env_override_invalid_port_returns_error() {
        let mut raw = minimal_raw();
        let env = HashMap::from([("EZPDS_PORT".to_string(), "not_a_port".to_string())]);
        let err = apply_env_overrides(&mut raw, &env).unwrap_err();

        assert!(matches!(err, ConfigError::Invalid(_)));
        assert!(err.to_string().contains("EZPDS_PORT"));
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
}
