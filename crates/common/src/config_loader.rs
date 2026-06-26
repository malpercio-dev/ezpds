// pattern: Mixed (Functional Core + I/O shell)

use std::collections::HashMap;
use std::path::Path;

use crate::config::{apply_env_overrides, validate_and_build, Config, ConfigError, RawConfig};

/// Standard OpenTelemetry env vars we read in addition to our `EZPDS_*` prefix.
const OTEL_ENV_KEYS: &[&str] = &["OTEL_SERVICE_NAME"];

/// Collect `EZPDS_*` env vars, `PORT`, and selected OTel standard vars from the process environment,
/// rejecting any with non-UTF-8 values rather than panicking.
pub fn collect_ezpds_env() -> Result<HashMap<String, String>, ConfigError> {
    let mut map = HashMap::new();
    for (key_os, val_os) in std::env::vars_os() {
        let key = match key_os.to_str() {
            Some(k) if k.starts_with("EZPDS_") || OTEL_ENV_KEYS.contains(&k) || k == "PORT" => {
                k.to_owned()
            }
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

/// Load [`Config`] from a TOML file with an explicit environment map.
///
/// This is a public API that accepts an explicit environment map instead of reading from
/// the process environment. Useful for tests (passing a controlled environment without
/// leaking real `EZPDS_*` vars) and for containerized deployments where the environment
/// has already been collected before calling this function.
pub fn load_config_with_env(
    path: &Path,
    env: &HashMap<String, String>,
) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    let raw: RawConfig = toml::from_str(&contents)?;
    let raw = apply_env_overrides(raw, env)?;
    validate_and_build(raw)
}

/// Load [`Config`] from a TOML file, applying `EZPDS_*` environment variable overrides.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let env = collect_ezpds_env()?;
    load_config_with_env(path, &env)
}

/// Load [`Config`] from environment variables alone, with no TOML file.
///
/// Useful for containerized deployments where all config comes from env vars.
/// Constructs a `RawConfig` from defaults (all fields `None`), then applies env overrides
/// and validates. This allows complete env-based configuration without requiring a file.
pub fn load_config_from_env_only(env: &HashMap<String, String>) -> Result<Config, ConfigError> {
    let raw = RawConfig::default();
    let raw = apply_env_overrides(raw, env)?;
    validate_and_build(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn empty_env() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn loads_config_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"data_dir = "/var/pds"
public_url = "https://pds.example.com"
available_user_domains = ["example.com"]"#
        )
        .unwrap();

        let config = load_config_with_env(tmp.path(), &empty_env()).unwrap();

        assert_eq!(config.public_url, "https://pds.example.com");
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn loads_minimal_valid_toml_produces_missing_field_error() {
        // An empty file is valid TOML but missing required fields.
        let tmp = tempfile::NamedTempFile::new().unwrap();

        let err = load_config_with_env(tmp.path(), &empty_env()).unwrap_err();

        assert!(matches!(
            err,
            ConfigError::MissingField { field: "data_dir" }
        ));
    }

    #[test]
    fn env_overrides_applied_from_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"data_dir = "/var/pds"
public_url = "https://pds.example.com"
available_user_domains = ["example.com"]"#
        )
        .unwrap();
        let env = HashMap::from([("EZPDS_PORT".to_string(), "9999".to_string())]);

        let config = load_config_with_env(tmp.path(), &env).unwrap();

        assert_eq!(config.port, 9999);
    }

    #[test]
    fn returns_error_for_missing_file() {
        let result = load_config_with_env(Path::new("/nonexistent/pds.toml"), &empty_env());

        assert!(matches!(result, Err(ConfigError::Io { .. })));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not valid toml = [[[").unwrap();

        let result = load_config_with_env(tmp.path(), &empty_env());

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    // --- Env-only config tests ---

    #[test]
    fn env_only_config_with_required_fields() {
        let env = HashMap::from([
            ("EZPDS_DATA_DIR".to_string(), "/tmp/pds".to_string()),
            (
                "EZPDS_PUBLIC_URL".to_string(),
                "https://pds.test".to_string(),
            ),
            (
                "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
                "pds.test".to_string(),
            ),
        ]);

        let config = load_config_from_env_only(&env).unwrap();

        assert_eq!(config.data_dir, std::path::PathBuf::from("/tmp/pds"));
        assert_eq!(config.public_url, "https://pds.test");
        assert_eq!(config.available_user_domains, vec!["pds.test"]);
    }

    #[test]
    fn env_only_config_missing_required_field_returns_error() {
        let env = HashMap::from([
            ("EZPDS_DATA_DIR".to_string(), "/tmp/pds".to_string()),
            // Missing EZPDS_PUBLIC_URL
            (
                "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
                "pds.test".to_string(),
            ),
        ]);

        let result = load_config_from_env_only(&env);

        assert!(matches!(
            result,
            Err(ConfigError::MissingField {
                field: "public_url"
            })
        ));
    }

    #[test]
    fn env_only_config_with_port_fallback() {
        let env = HashMap::from([
            ("PORT".to_string(), "9000".to_string()),
            ("EZPDS_DATA_DIR".to_string(), "/tmp/pds".to_string()),
            (
                "EZPDS_PUBLIC_URL".to_string(),
                "https://pds.test".to_string(),
            ),
            (
                "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
                "pds.test".to_string(),
            ),
        ]);

        let config = load_config_from_env_only(&env).unwrap();

        assert_eq!(config.port, 9000);
    }

    #[test]
    fn env_only_config_applies_all_env_overrides() {
        let env = HashMap::from([
            ("EZPDS_BIND_ADDRESS".to_string(), "127.0.0.1".to_string()),
            ("EZPDS_PORT".to_string(), "5555".to_string()),
            ("EZPDS_DATA_DIR".to_string(), "/var/pds".to_string()),
            (
                "EZPDS_PUBLIC_URL".to_string(),
                "https://pds.example.com".to_string(),
            ),
            (
                "EZPDS_AVAILABLE_USER_DOMAINS".to_string(),
                "example.com".to_string(),
            ),
        ]);

        let config = load_config_from_env_only(&env).unwrap();

        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.port, 5555);
        assert_eq!(config.data_dir, std::path::PathBuf::from("/var/pds"));
        assert_eq!(config.public_url, "https://pds.example.com");
    }
}
