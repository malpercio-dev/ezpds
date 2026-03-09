// pattern: Imperative Shell

use std::collections::HashMap;
use std::path::Path;

use crate::config::{apply_env_overrides, validate_and_build, Config, ConfigError, RawConfig};

/// Collect only `EZPDS_*` env vars from the process environment, rejecting any with non-UTF-8
/// values rather than panicking (as `std::env::vars()` would on non-UTF-8 data).
fn collect_ezpds_env() -> Result<HashMap<String, String>, ConfigError> {
    let mut map = HashMap::new();
    for (key_os, val_os) in std::env::vars_os() {
        let key = match key_os.to_str() {
            Some(k) if k.starts_with("EZPDS_") => k.to_owned(),
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
/// Prefer [`load_config`] for production use. This variant is `pub(crate)` so tests can pass a
/// controlled environment without leaking real `EZPDS_*` vars.
pub(crate) fn load_config_with_env(
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
public_url = "https://pds.example.com""#
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
public_url = "https://pds.example.com""#
        )
        .unwrap();
        let env = HashMap::from([("EZPDS_PORT".to_string(), "9999".to_string())]);

        let config = load_config_with_env(tmp.path(), &env).unwrap();

        assert_eq!(config.port, 9999);
    }

    #[test]
    fn returns_error_for_missing_file() {
        let result = load_config_with_env(Path::new("/nonexistent/relay.toml"), &empty_env());

        assert!(matches!(result, Err(ConfigError::Io { .. })));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not valid toml = [[[").unwrap();

        let result = load_config_with_env(tmp.path(), &empty_env());

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }
}
