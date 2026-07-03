// pattern: Functional Core

use serde::Deserialize;

/// The device platform a client identifies itself as during registration.
///
/// Deserialised from the lowercase wire token (`"ios"`, `"android"`, ...); an
/// unknown value is rejected by serde. Shared by the device-registration routes
/// (`register_device`, `create_mobile_account`) so both accept and persist the
/// same closed set of platforms.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Ios,
    Android,
    Macos,
    Linux,
    Windows,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
            Platform::Macos => "macos",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_deserializes_known_values() {
        for p in ["ios", "android", "macos", "linux", "windows"] {
            let result: Result<Platform, _> = serde_json::from_str(&format!("\"{p}\""));
            assert!(result.is_ok(), "{p} must deserialize");
        }
    }

    #[test]
    fn platform_rejects_unknown_values() {
        for p in ["plan9", "", "iOS", "Windows"] {
            let result: Result<Platform, _> = serde_json::from_str(&format!("\"{p}\""));
            assert!(result.is_err(), "{p} must be rejected");
        }
    }
}
