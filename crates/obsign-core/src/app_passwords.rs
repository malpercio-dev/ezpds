// pattern: Mixed (Functional Core error mapping; Imperative Shell commands)

//! App-password management for a wallet-custodied identity — the surface that signs
//! the official Bluesky app (and other password-login clients) into a passwordless
//! sovereign Custos account. Three Tauri IPC commands:
//!
//! - `create_app_password(did, name, privileged, personalDetails) -> AppPasswordCreated` —
//!   mints via `com.atproto.server.createAppPassword`. The returned secret is surfaced
//!   ONCE: displayed once, offered for copy, never persisted by the wallet. The biometric
//!   gate on minting lives in the frontend wrapper (`$lib/ipc/app-passwords.ts`).
//!   `personalDetails` is the Custos ADR-0033 grant (read/write the full-access-only
//!   preferences, e.g. the birth date age checks require); the screen offers it only when
//!   the host advertises the `appPasswordPersonalDetails` capability, and the response
//!   echoes what was actually granted.
//! - `list_app_passwords(did) -> Vec<AppPasswordEntry>` — metadata only, never the
//!   secret.
//! - `revoke_app_password(did, name)` — the server deletes the credential and its
//!   sessions/refresh tokens atomically.
//!
//! A sovereign account has no main password, so the PDS's createSession app-password
//! fallback (V031) makes this minted credential the only way a password-login client
//! can open a session — and that session is scope-bounded (`com.atproto.appPass`):
//! it can post/like/follow and proxy to the AppView, but can never touch account
//! management, PLC/identity ops, agent surfaces, or app-password management itself.
//! Chat (DMs) additionally requires the `privileged` flag chosen at mint time.
//!
//! Every command resolves a per-DID full-access session through
//! `SessionProvider::full_access_client` (the mint/list/revoke routes require full
//! access — an app password cannot manage app passwords). A
//! `SESSION_LOCKED { reason: UnlockReason }` is the frontend's cue to run
//! `unlockIdentity(did)` and retry, mirroring `handle_change.rs`. The thin XRPC
//! wrappers and response types (`AppPasswordCreated`, `AppPasswordEntry`, camelCase,
//! mirrored in `$lib/ipc`) live in `pds_client.rs`; a 409 duplicate name maps to
//! `DUPLICATE_NAME`.
//!
//! `AppPasswordsError` (DUPLICATE_NAME plus the shared codes in [`crate::failure`])
//! serializes as `{ code: "SCREAMING_SNAKE_CASE" }` with camelCase fields; the TypeScript
//! union must match exactly.

use serde::Serialize;

use crate::failure::SharedFailure;
use crate::pds_client::{self, AppPasswordCreated, AppPasswordEntry, PdsClientError};
use crate::session_provider::SessionProvider;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the app-password management commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`HandleChangeError`, `AgentsError`, `SharedFailure`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum AppPasswordsError {
    /// An app password with this name already exists on the account.
    #[error("an app password with this name already exists")]
    DuplicateName,
    /// See [`SharedFailure`].
    #[serde(untagged)]
    #[error(transparent)]
    Shared(#[from] SharedFailure),
}

/// Map a classified XRPC failure into the app-password surface. The one
/// status-specific case is 409 → `DuplicateName` (the createAppPassword conflict);
/// every other server refusal keeps its status, which the screen keys on.
fn map_pds_error(error: PdsClientError) -> AppPasswordsError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            AppPasswordsError::Shared(SharedFailure::RateLimited { retry_after })
        }
        PdsClientError::XrpcError { status: 409, .. } => AppPasswordsError::DuplicateName,
        PdsClientError::XrpcError {
            status, message, ..
        } => AppPasswordsError::Shared(SharedFailure::ServerError { status, message }),
        PdsClientError::Unauthorized { message, .. } => {
            AppPasswordsError::Shared(SharedFailure::ServerError {
                status: 401,
                message,
            })
        }
        PdsClientError::NetworkError { message } => {
            AppPasswordsError::Shared(SharedFailure::NetworkError { message })
        }
        PdsClientError::PdsUnreachable { reason } => {
            AppPasswordsError::Shared(SharedFailure::NetworkError { message: reason })
        }
        other => AppPasswordsError::Shared(SharedFailure::InvalidResponse {
            message: other.to_string(),
        }),
    }
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Tauri command: mint a named app password for the identity. Returns the generated
/// secret ONCE — it is never retrievable again. The frontend gates this behind
/// `authenticateBiometric()` (it creates a durable login credential).
pub async fn create_app_password(
    state: &crate::oauth::Core,
    did: String,
    name: String,
    privileged: bool,
    personal_details: bool,
) -> Result<AppPasswordCreated, AppPasswordsError> {
    let session = SessionProvider.full_access_client(state, &did).await?;
    pds_client::create_app_password(&session.client, &name, privileged, personal_details)
        .await
        .map_err(map_pds_error)
}

/// Tauri command: list the identity's app passwords (metadata only, never secrets).
pub async fn list_app_passwords(
    state: &crate::oauth::Core,
    did: String,
) -> Result<Vec<AppPasswordEntry>, AppPasswordsError> {
    let session = SessionProvider.full_access_client(state, &did).await?;
    pds_client::list_app_passwords(&session.client)
        .await
        .map_err(map_pds_error)
}

/// Tauri command: revoke a named app password. The server deletes the credential and
/// its sessions/refresh tokens atomically, so a signed-in client is cut off at once.
pub async fn revoke_app_password(
    state: &crate::oauth::Core,
    did: String,
    name: String,
) -> Result<(), AppPasswordsError> {
    let session = SessionProvider.full_access_client(state, &did).await?;
    pds_client::revoke_app_password(&session.client, &name)
        .await
        .map_err(map_pds_error)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_provider::UnlockReason;

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
            AppPasswordsError::Shared(SharedFailure::ServerError { status, message }) => {
                assert_eq!(status, 400);
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
            AppPasswordsError::Shared(SharedFailure::ServerError { status: 401, .. })
        ));
    }

    #[test]
    fn errors_serialize_as_screaming_snake_codes_with_camel_fields() {
        let json = serde_json::to_value(AppPasswordsError::Shared(SharedFailure::SessionLocked {
            reason: UnlockReason::HostChanged,
        }))
        .unwrap();
        assert_eq!(json["code"], "SESSION_LOCKED");
        assert_eq!(json["reason"], "HOST_CHANGED");

        let json = serde_json::to_value(AppPasswordsError::Shared(SharedFailure::RateLimited {
            retry_after: Some("30".to_string()),
        }))
        .unwrap();
        assert_eq!(json["code"], "RATE_LIMITED");
        assert_eq!(json["retryAfter"], "30");

        let json = serde_json::to_value(AppPasswordsError::DuplicateName).unwrap();
        assert_eq!(json["code"], "DUPLICATE_NAME");
    }
}
