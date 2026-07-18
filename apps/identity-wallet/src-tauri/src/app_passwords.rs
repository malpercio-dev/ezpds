// pattern: Mixed (Functional Core error mapping; Imperative Shell commands)
//
// App-password management for a wallet-custodied identity — the surface that signs
// the official Bluesky app (and other password-login clients) into a passwordless
// sovereign Custos account. Three Tauri IPC commands:
//
//   create_app_password(did, name, privileged) — mint; returns the secret ONCE
//   list_app_passwords(did)                    — metadata only, never the secret
//   revoke_app_password(did, name)             — kills the credential and its sessions
//
// A sovereign account has no main password, so the PDS's createSession app-password
// fallback (V031) makes this minted credential the only way a password-login client
// can open a session — and that session is scope-bounded (`com.atproto.appPass`):
// it can post/like/follow and proxy to the AppView, but can never touch account
// management, PLC/identity ops, agent surfaces, or app-password management itself.
// Chat (DMs) additionally requires the `privileged` flag chosen at mint time.
//
// Every command resolves a per-DID full-access session through
// `SessionProvider::full_access_client` (the mint/list/revoke routes require full
// access — an app password cannot manage app passwords). A `NeedsUnlock` maps to
// `SESSION_LOCKED`, the frontend's cue to run the biometric `sovereignLogin(did)`
// and retry, exactly like the change-handle flow. The biometric gate on minting
// lives in the frontend wrapper (`$lib/ipc/app-passwords.ts`), in front of this.

use serde::Serialize;

use crate::identity_store::IdentityStore;
use crate::pds_client::{self, AppPasswordCreated, AppPasswordEntry, PdsClient, PdsClientError};
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the app-password management commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`HandleChangeError`, `AgentsError`, `SessionError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum AppPasswordsError {
    /// The identity's session could not be resolved without a passwordless unlock —
    /// the frontend should run the biometric sovereign login and retry.
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting PDS rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// An app password with this name already exists on the account.
    #[error("an app password with this name already exists")]
    DuplicateName,
    /// The DID is not registered in this wallet.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// A server-side step failed for a non-connectivity reason: the hosting PDS refused
    /// the request (non-2xx other than the cases above, `status` carries the HTTP code),
    /// or the session could not be resolved for a reason that is not a transport failure
    /// (refresh verdict, unsupported host, malformed response, or local session storage —
    /// `status` is `None` for these).
    #[error("server error: {message}")]
    ServerError {
        status: Option<u16>,
        message: String,
    },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
}

/// Map a session-lifecycle failure into the app-password surface. Exhaustive on purpose: only
/// a genuine transport failure becomes `NetworkError` — a server verdict, unsupported host, or
/// storage failure must not surface as "check your connection", or the real cause becomes
/// undiagnosable from the screen (the same defect class `classify_xrpc_error` exists to fix).
fn map_session_error(error: SessionError) -> AppPasswordsError {
    match error {
        SessionError::NeedsUnlock { reason } => AppPasswordsError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => AppPasswordsError::RateLimited { retry_after },
        SessionError::IdentityNotFound => AppPasswordsError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => AppPasswordsError::NetworkError { message },
        SessionError::ServerFailure { status } => AppPasswordsError::ServerError {
            status: Some(status),
            message: format!("session request failed with status {status}"),
        },
        SessionError::UnsupportedHost => AppPasswordsError::ServerError {
            status: None,
            message: "the identity's hosting server does not support session refresh".to_string(),
        },
        SessionError::Keychain { message } => AppPasswordsError::ServerError {
            status: None,
            message: format!("session keychain failure: {message}"),
        },
        SessionError::InvalidResponse { message } => AppPasswordsError::ServerError {
            status: None,
            message: format!("invalid session response: {message}"),
        },
    }
}

/// Map a classified XRPC failure into the app-password surface. The one
/// status-specific case is 409 → `DuplicateName` (the createAppPassword conflict);
/// every other server refusal keeps its status + message so the UI can show the
/// real reason instead of connectivity boilerplate.
fn map_pds_error(error: PdsClientError) -> AppPasswordsError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            AppPasswordsError::RateLimited { retry_after }
        }
        PdsClientError::XrpcError { status: 409, .. } => AppPasswordsError::DuplicateName,
        PdsClientError::XrpcError {
            status, message, ..
        } => AppPasswordsError::ServerError {
            status: Some(status),
            message,
        },
        PdsClientError::Unauthorized { message, .. } => AppPasswordsError::ServerError {
            status: Some(401),
            message,
        },
        PdsClientError::NetworkError { message } => AppPasswordsError::NetworkError { message },
        other => AppPasswordsError::NetworkError {
            message: other.to_string(),
        },
    }
}

/// Resolve the DID's full-access session (restore / refresh, or `SessionLocked`).
async fn full_access_session(
    pds_client: &PdsClient,
    did: &str,
) -> Result<crate::session_provider::ActiveSession, AppPasswordsError> {
    let now = crate::sovereign_session::unix_timestamp().map_err(|_| {
        AppPasswordsError::NetworkError {
            message: "system clock is unavailable".to_string(),
        }
    })?;
    SessionProvider
        .full_access_client(pds_client, &IdentityStore, did, now)
        .await
        .map_err(map_session_error)
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: mint a named app password for the identity. Returns the generated
/// secret ONCE — it is never retrievable again. The frontend gates this behind
/// `authenticateBiometric()` (it creates a durable login credential).
#[tauri::command]
pub async fn create_app_password(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    name: String,
    privileged: bool,
) -> Result<AppPasswordCreated, AppPasswordsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    pds_client::create_app_password(&session.client, &name, privileged)
        .await
        .map_err(map_pds_error)
}

/// Tauri command: list the identity's app passwords (metadata only, never secrets).
#[tauri::command]
pub async fn list_app_passwords(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<Vec<AppPasswordEntry>, AppPasswordsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    pds_client::list_app_passwords(&session.client)
        .await
        .map_err(map_pds_error)
}

/// Tauri command: revoke a named app password. The server deletes the credential and
/// its sessions/refresh tokens atomically, so a signed-in client is cut off at once.
#[tauri::command]
pub async fn revoke_app_password(
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
    name: String,
) -> Result<(), AppPasswordsError> {
    let session = full_access_session(state.pds_client(), &did).await?;
    pds_client::revoke_app_password(&session.client, &name)
        .await
        .map_err(map_pds_error)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_unlock_maps_to_session_locked() {
        let err = map_session_error(SessionError::NeedsUnlock {
            reason: UnlockReason::NoRefreshChain,
        });
        assert!(matches!(
            err,
            AppPasswordsError::SessionLocked {
                reason: UnlockReason::NoRefreshChain
            }
        ));
    }

    #[test]
    fn session_rate_limit_is_preserved() {
        let err = map_session_error(SessionError::RateLimited {
            retry_after: Some("30".to_string()),
        });
        assert!(matches!(
            err,
            AppPasswordsError::RateLimited { retry_after: Some(ref s) } if s == "30"
        ));
    }

    #[test]
    fn session_server_failure_keeps_its_status() {
        let err = map_session_error(SessionError::ServerFailure { status: 503 });
        assert!(matches!(
            err,
            AppPasswordsError::ServerError {
                status: Some(503),
                ..
            }
        ));
    }

    /// Session failures keep their nature: a server verdict is SERVER_ERROR, not NETWORK_ERROR.
    #[test]
    fn session_errors_no_longer_flatten_to_network_error() {
        assert!(matches!(
            map_session_error(SessionError::UnsupportedHost),
            AppPasswordsError::ServerError { status: None, .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::Keychain {
                message: "no slot".to_string()
            }),
            AppPasswordsError::ServerError { status: None, .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::InvalidResponse {
                message: "bad json".to_string()
            }),
            AppPasswordsError::ServerError { status: None, .. }
        ));
        assert!(matches!(
            map_session_error(SessionError::Offline {
                message: "timeout".to_string()
            }),
            AppPasswordsError::NetworkError { .. }
        ));
    }

    #[test]
    fn conflict_409_maps_to_duplicate_name() {
        let err = map_pds_error(PdsClientError::XrpcError {
            status: 409,
            error: Some("Conflict".to_string()),
            message: "an app password with this name already exists".to_string(),
        });
        assert!(matches!(err, AppPasswordsError::DuplicateName));
    }

    #[test]
    fn other_xrpc_errors_keep_status_and_message() {
        let err = map_pds_error(PdsClientError::XrpcError {
            status: 400,
            error: Some("InvalidRequest".to_string()),
            message: "app password name must not be empty".to_string(),
        });
        match err {
            AppPasswordsError::ServerError { status, message } => {
                assert_eq!(status, Some(400));
                assert_eq!(message, "app password name must not be empty");
            }
            e => panic!("expected ServerError, got: {e:?}"),
        }
    }

    #[test]
    fn unauthorized_maps_to_server_error_401() {
        let err = map_pds_error(PdsClientError::Unauthorized {
            error: Some("ExpiredToken".to_string()),
            message: "token expired".to_string(),
        });
        assert!(matches!(
            err,
            AppPasswordsError::ServerError {
                status: Some(401),
                ..
            }
        ));
    }

    #[test]
    fn errors_serialize_as_screaming_snake_codes_with_camel_fields() {
        let json = serde_json::to_value(AppPasswordsError::SessionLocked {
            reason: UnlockReason::HostChanged,
        })
        .unwrap();
        assert_eq!(json["code"], "SESSION_LOCKED");
        assert_eq!(json["reason"], "HOST_CHANGED");

        let json = serde_json::to_value(AppPasswordsError::RateLimited {
            retry_after: Some("30".to_string()),
        })
        .unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
        assert_eq!(json["retryAfter"], "30");

        let json = serde_json::to_value(AppPasswordsError::DuplicateName).unwrap();
        assert_eq!(json["code"], "DUPLICATE_NAME");

        // A status-less server error (session verdict) serializes `status: null`, matching
        // the TS union's `status: number | null`.
        let json = serde_json::to_value(AppPasswordsError::ServerError {
            status: None,
            message: "invalid session response: bad json".to_string(),
        })
        .unwrap();
        assert_eq!(json["code"], "SERVER_ERROR");
        assert_eq!(json["status"], serde_json::Value::Null);
    }
}
