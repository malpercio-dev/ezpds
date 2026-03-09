// pattern: Imperative Shell

use std::collections::HashMap;
use std::path::Path;

use crate::config::{apply_env_overrides, validate_and_build, Config, ConfigError, RawConfig};

/// Load [`Config`] from a TOML file with an explicit environment map.
///
/// Prefer [`load_config`] for production use. This variant is `pub(crate)` so
/// tests can pass a controlled environment without leaking real `EZPDS_*` vars.
pub(crate) fn load_config_with_env(
    path: &Path,
    env: &HashMap<String, String>,
) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let mut raw: RawConfig = toml::from_str(&contents)?;
    apply_env_overrides(&mut raw, env)?;
    validate_and_build(raw)
}

/// Load [`Config`] from a TOML file, applying `EZPDS_*` environment variable overrides.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let env: HashMap<String, String> = std::env::vars().collect();
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

        assert!(matches!(result, Err(ConfigError::Io(_))));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not valid toml = [[[").unwrap();

        let result = load_config_with_env(tmp.path(), &empty_env());

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }
}
