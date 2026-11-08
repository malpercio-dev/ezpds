// pattern: Functional Core

//! The failure vocabulary every wallet ceremony shares.
//!
//! Session resolution ([`crate::session_provider`]), local identity-store reads, DID → PDS
//! discovery, and plc.directory reads fail the same handful of ways in every command. Each
//! of those lower-layer errors is classified into [`SharedFailure`] here, once. A command's
//! error enum embeds it as
//!
//! ```ignore
//! #[serde(untagged)]
//! #[error(transparent)]
//! Shared(#[from] SharedFailure),
//! ```
//!
//! so it serializes flat under its own `code` (ADR-0031's typed seam is unchanged) and a
//! command never redeclares these codes. A command that needs a different sentence for one of
//! these situations declares a new code instead of re-mapping a shared one.

use serde::Serialize;

use crate::identity_store::IdentityStoreError;
use crate::pds_client::PdsClientError;
use crate::session_provider::UnlockReason;

/// A failure every ceremony can hit. Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }`.
///
/// Every `message` field is diagnostic only (ADR-0031 rule 3): none carries server-quoted
/// text a screen may render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum SharedFailure {
    /// The identity has no usable session; the UI runs the passwordless unlock and retries.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting server or plc.directory answered 429.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    #[error("identity not found")]
    IdentityNotFound,
    /// A transport failure: no well-formed HTTP response came back.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// The hosting server answered with an HTTP failure. `status` is always a real status.
    #[error("hosting server failure ({status}): {message}")]
    ServerError { status: u16, message: String },
    /// The DID or its host could not be resolved, or the host lacks the endpoint needed.
    #[error("the identity's hosting server does not support this")]
    UnsupportedHost,
    /// A response this client could not use (malformed, or failing its own sub/aud/DID
    /// checks), or a local clock/timestamp fault. Not the server's verdict.
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },
    /// A local Keychain failure. Never the server's.
    #[error("keychain failure: {message}")]
    KeychainError { message: String },
    /// plc.directory answered a read with an HTTP failure — an outage or verdict, not
    /// connectivity.
    #[error("plc.directory error: {message}")]
    PlcDirectoryError { message: String },
}

impl From<IdentityStoreError> for SharedFailure {
    fn from(error: IdentityStoreError) -> Self {
        match error {
            IdentityStoreError::IdentityNotFound => Self::IdentityNotFound,
            IdentityStoreError::KeychainError { message } => Self::KeychainError { message },
            other => Self::KeychainError {
                message: other.to_string(),
            },
        }
    }
}

impl SharedFailure {
    /// Classify a DID → PDS discovery failure (DID document resolution plus the host's
    /// `describeServer`). Anything that is neither transport, throttle, nor an HTTP verdict
    /// means the host could not be resolved into something usable.
    pub fn from_discovery(error: PdsClientError) -> Self {
        match error {
            PdsClientError::PdsUnreachable { reason } => Self::NetworkError { message: reason },
            PdsClientError::NetworkError { message } => Self::NetworkError { message },
            PdsClientError::RateLimited { retry_after, .. } => Self::RateLimited { retry_after },
            PdsClientError::XrpcError { status, .. } => Self::ServerError {
                status,
                message: error.to_string(),
            },
            PdsClientError::Unauthorized { .. } => Self::ServerError {
                status: 401,
                message: error.to_string(),
            },
            other => {
                tracing::warn!(error = %other, "could not resolve the identity's hosting server");
                Self::UnsupportedHost
            }
        }
    }

    /// Classify a plc.directory read failure. `context` names the read for diagnostics.
    /// Only a transport failure reads as connectivity; every other failure is the directory's.
    pub fn from_plc_fetch(context: &str, error: PdsClientError) -> Self {
        match error {
            PdsClientError::RateLimited { retry_after, .. } => Self::RateLimited { retry_after },
            PdsClientError::NetworkError { .. } | PdsClientError::PdsUnreachable { .. } => {
                Self::NetworkError {
                    message: format!("{context}: {error}"),
                }
            }
            other => Self::PlcDirectoryError {
                message: format!("{context}: {other}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn xrpc(status: u16) -> PdsClientError {
        PdsClientError::XrpcError {
            status,
            error: None,
            message: "boom".into(),
        }
    }

    #[test]
    fn store_not_found_is_identity_not_found() {
        assert_eq!(
            SharedFailure::from(IdentityStoreError::IdentityNotFound),
            SharedFailure::IdentityNotFound
        );
    }

    #[test]
    fn every_other_store_failure_is_local_keychain() {
        assert_eq!(
            SharedFailure::from(IdentityStoreError::KeychainError {
                message: "locked".into()
            }),
            SharedFailure::KeychainError {
                message: "locked".into()
            }
        );
        assert!(matches!(
            SharedFailure::from(IdentityStoreError::KeyGenerationFailed),
            SharedFailure::KeychainError { .. }
        ));
    }

    #[test]
    fn discovery_transport_failures_are_network() {
        assert!(matches!(
            SharedFailure::from_discovery(PdsClientError::NetworkError {
                message: "dns".into()
            }),
            SharedFailure::NetworkError { .. }
        ));
        assert_eq!(
            SharedFailure::from_discovery(PdsClientError::PdsUnreachable {
                reason: "refused".into()
            }),
            SharedFailure::NetworkError {
                message: "refused".into()
            }
        );
    }

    #[test]
    fn discovery_resolution_failures_are_unsupported_host() {
        for e in [
            PdsClientError::DidNotFound,
            PdsClientError::InvalidResponse {
                message: "no service".into(),
            },
            PdsClientError::InsecurePdsUrl {
                url: "http://x".into(),
            },
        ] {
            assert_eq!(
                SharedFailure::from_discovery(e),
                SharedFailure::UnsupportedHost
            );
        }
    }

    #[test]
    fn discovery_http_verdicts_keep_their_status() {
        assert!(matches!(
            SharedFailure::from_discovery(xrpc(503)),
            SharedFailure::ServerError { status: 503, .. }
        ));
        assert!(matches!(
            SharedFailure::from_discovery(PdsClientError::Unauthorized {
                error: None,
                message: "no".into()
            }),
            SharedFailure::ServerError { status: 401, .. }
        ));
        assert_eq!(
            SharedFailure::from_discovery(PdsClientError::RateLimited {
                retry_after: Some("5".into()),
                message: "slow".into()
            }),
            SharedFailure::RateLimited {
                retry_after: Some("5".into())
            }
        );
    }

    #[test]
    fn plc_fetch_transport_failures_are_network() {
        assert_eq!(
            SharedFailure::from_plc_fetch(
                "fetch audit log",
                PdsClientError::NetworkError {
                    message: "dns".into()
                }
            ),
            SharedFailure::NetworkError {
                message: "fetch audit log: network error: dns".into()
            }
        );
    }

    #[test]
    fn plc_fetch_non_transport_failures_are_the_directory() {
        for e in [
            xrpc(500),
            PdsClientError::InvalidResponse {
                message: "not json".into(),
            },
            PdsClientError::DidNotFound,
        ] {
            assert!(matches!(
                SharedFailure::from_plc_fetch("fetch audit log", e),
                SharedFailure::PlcDirectoryError { .. }
            ));
        }
        assert_eq!(
            SharedFailure::from_plc_fetch(
                "ctx",
                PdsClientError::RateLimited {
                    retry_after: None,
                    message: "slow".into()
                }
            ),
            SharedFailure::RateLimited { retry_after: None }
        );
    }

    #[test]
    fn wire_codes() {
        let cases = [
            (
                SharedFailure::SessionLocked {
                    reason: UnlockReason::HostChanged,
                },
                json!({"code": "SESSION_LOCKED", "reason": "HOST_CHANGED"}),
            ),
            (
                SharedFailure::RateLimited {
                    retry_after: Some("5".into()),
                },
                json!({"code": "RATE_LIMITED", "retryAfter": "5"}),
            ),
            (
                SharedFailure::IdentityNotFound,
                json!({"code": "IDENTITY_NOT_FOUND"}),
            ),
            (
                SharedFailure::NetworkError {
                    message: "m".into(),
                },
                json!({"code": "NETWORK_ERROR", "message": "m"}),
            ),
            (
                SharedFailure::ServerError {
                    status: 502,
                    message: "m".into(),
                },
                json!({"code": "SERVER_ERROR", "status": 502, "message": "m"}),
            ),
            (
                SharedFailure::UnsupportedHost,
                json!({"code": "UNSUPPORTED_HOST"}),
            ),
            (
                SharedFailure::InvalidResponse {
                    message: "m".into(),
                },
                json!({"code": "INVALID_RESPONSE", "message": "m"}),
            ),
            (
                SharedFailure::KeychainError {
                    message: "m".into(),
                },
                json!({"code": "KEYCHAIN_ERROR", "message": "m"}),
            ),
            (
                SharedFailure::PlcDirectoryError {
                    message: "m".into(),
                },
                json!({"code": "PLC_DIRECTORY_ERROR", "message": "m"}),
            ),
        ];
        for (failure, expected) in cases {
            assert_eq!(serde_json::to_value(&failure).unwrap(), expected);
        }
    }

    /// The embedding every command enum uses serializes the shared variant flat, under its
    /// own code, beside the command's own tagged variants.
    #[test]
    fn untagged_embedding_serializes_flat() {
        #[derive(Debug, Serialize, thiserror::Error)]
        #[serde(
            tag = "code",
            rename_all = "SCREAMING_SNAKE_CASE",
            rename_all_fields = "camelCase"
        )]
        enum CommandError {
            #[error("own")]
            OwnThing { some_field: u8 },
            #[serde(untagged)]
            #[error(transparent)]
            Shared(#[from] SharedFailure),
        }
        assert_eq!(
            serde_json::to_value(CommandError::from(SharedFailure::KeychainError {
                message: "m".into()
            }))
            .unwrap(),
            json!({"code": "KEYCHAIN_ERROR", "message": "m"})
        );
        assert_eq!(
            serde_json::to_value(CommandError::OwnThing { some_field: 1 }).unwrap(),
            json!({"code": "OWN_THING", "someField": 1})
        );
    }
}
