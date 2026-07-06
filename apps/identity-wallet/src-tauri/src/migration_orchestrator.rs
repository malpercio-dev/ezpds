// pattern: Mixed (Functional Core types + Imperative Shell commands)
//
// Functional Core: MigrationPhase, OutboundMigrationState, MigrationError, PendingSourceLogin,
//                  ensure_phase_did (pure gate function, no network, no side effects)
// Imperative Shell: prepare_migration, prepare_source_auth, complete_source_auth,
//                   create_destination_account (Tauri commands; Tasks 4-6 in Phase 3)

use serde::Serialize;
use std::sync::Arc;
use crate::oauth_client::OAuthClient;

// ── Phase enum ─────────────────────────────────────────────────────────────

/// Migration phase tracking the outbound migration flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum MigrationPhase {
    Resolved,
    SourceAuthed,
    DestCreated,
    RepoTransferred,
    BlobsTransferred,
    PreferencesTransferred,
    Verified,
    IdentityArmed,
    Finalized,
}

// ── State types ────────────────────────────────────────────────────────────

/// Outbound migration state persisted in `AppState`.
///
/// Resolved by `prepare_migration` and used by subsequent migration commands
/// within the same migration session. In-memory only; an app kill restarts from
/// `prepare_migration`.
#[derive(Clone)]
pub struct OutboundMigrationState {
    /// The DID being migrated
    pub did: String,
    /// Source PDS URL (resolved by `prepare_migration` via `discover_pds`)
    pub source_pds_url: String,
    /// Destination PDS URL (provided by caller to `prepare_migration`)
    pub dest_pds_url: String,
    /// Destination server DID (from `describeServer`, used as `aud` for `getServiceAuth`)
    pub dest_did: String,
    /// Handle (preserved from source; extracted from `plc_doc.also_known_as`)
    pub handle: String,
    /// OAuth client for source PDS (set after `prepare_source_auth`/`complete_source_auth`)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub source_client: Option<Arc<OAuthClient>>,
    /// OAuth client for destination PDS (set after `create_destination_account`)
    /// Wrapped in Arc to allow cloning out of the Mutex without holding the lock
    /// across network calls.
    pub dest_client: Option<Arc<OAuthClient>>,
    /// Current phase in the migration flow
    pub phase: MigrationPhase,
}

/// State parked in `AppState.pending_source_login` between `prepare_source_auth` and
/// `complete_source_auth` while the ASWebAuthenticationSession runs. Holds the discovered
/// auth-server metadata plus the secrets the token exchange needs — none of it is serialized to
/// the webview (twin of `claim::PendingPdsLogin`).
pub struct PendingSourceLogin {
    /// The DID this auth was prepared for — re-checked against `OutboundMigrationState` in
    /// `complete_source_auth` so a concurrent `prepare_migration` can't attach this client
    /// to a different migration.
    pub did: String,
    /// Source PDS URL this auth was prepared for (re-checked alongside `did`).
    pub source_pds_url: String,
    /// PKCE code_verifier for the token exchange.
    pub pkce_verifier: String,
    /// CSRF state — validated against the callback URL's `state` param.
    pub csrf_state: String,
    /// Auth-server metadata discovered from the source PDS (needed for the token exchange).
    pub metadata: crate::pds_client::AuthServerMetadata,
    /// OAuth `client_id` for the source PDS.
    pub client_id: String,
    /// Source PDS base URL the resulting `OAuthClient` targets.
    pub oauth_client_pds_url: String,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Error returned by outbound migration commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the wallet's
/// established error contract (same pattern as `ClaimError`, `CreateAccountError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MigrationError {
    /// Migration not ready: state absent, DID mismatch, or phase too low
    #[error("migration not ready: {message}")]
    MigrationNotReady { message: String },
    /// Destination PDS is unreachable
    #[error("destination unreachable: {message}")]
    DestinationUnreachable { message: String },
    /// Source PDS OAuth authentication failed
    #[error("source auth failed: {message}")]
    SourceAuthFailed { message: String },
    /// Service authentication (getServiceAuth) failed
    #[error("service auth failed: {message}")]
    ServiceAuthFailed { message: String },
    /// Account creation (createAccount) failed
    #[error("account creation failed: {message}")]
    AccountCreationFailed { message: String },
    /// Destination account exists but session was lost (app kill; restart migration)
    #[error("destination conflict: {message}")]
    DestinationConflict { message: String },
    /// Repository transfer failed
    #[error("repo transfer failed: {message}")]
    RepoTransferFailed { message: String },
    /// Blob transfer failed
    #[error("blob transfer failed: {message}")]
    BlobTransferFailed { message: String },
    /// Preferences transfer failed
    #[error("preferences transfer failed: {message}")]
    PreferencesTransferFailed { message: String },
    /// Verification incomplete: imported entries do not match expected count
    #[error("verification incomplete")]
    VerificationIncomplete { imported: u64, expected: u64 },
    /// Identity activation failed
    #[error("activation failed: {message}")]
    ActivationFailed { message: String },
    /// Account deactivation failed
    #[error("deactivation failed: {message}")]
    DeactivationFailed { message: String },
    /// Network error during migration
    #[error("network error: {message}")]
    NetworkError { message: String },
}

// ── Pure prerequisite gate ─────────────────────────────────────────────────

/// Pure prerequisite gate: state present, DID matches, and phase is at least `required`.
/// No network, no side effects — this is what makes AC1.3/AC1.4 side-effect-free and
/// unit-testable.
pub(crate) fn ensure_phase_did<'a>(
    state: &'a Option<OutboundMigrationState>,
    did: &str,
    required: MigrationPhase,
) -> Result<&'a OutboundMigrationState, MigrationError> {
    let Some(s) = state.as_ref() else {
        return Err(MigrationError::MigrationNotReady {
            message: "no migration in progress".into(),
        });
    };
    if s.did != did {
        return Err(MigrationError::MigrationNotReady {
            message: "did does not match active migration".into(),
        });
    }
    if s.phase < required {
        return Err(MigrationError::MigrationNotReady {
            message: format!("expected phase >= {:?}, found {:?}", required, s.phase),
        });
    }
    Ok(s)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // AC1.3: Phase too low returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_phase_too_low() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::SourceAuthed,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::RepoTransferred);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // AC1.4: DID mismatch returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_did_mismatch() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::Resolved,
        });

        let result = ensure_phase_did(&state, "did:plc:different", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // None state returns MigrationNotReady
    #[test]
    fn test_ensure_phase_did_no_state() {
        let result = ensure_phase_did(&None, "did:plc:abc123", MigrationPhase::Resolved);
        assert!(matches!(
            result,
            Err(MigrationError::MigrationNotReady { .. })
        ));
    }

    // AC1.3/AC1.4: Happy path — state present, DID matches, phase sufficient
    #[test]
    fn test_ensure_phase_did_success() {
        let state = Some(OutboundMigrationState {
            did: "did:plc:abc123".into(),
            source_pds_url: "https://source.pds".into(),
            dest_pds_url: "https://dest.pds".into(),
            dest_did: "did:web:dest".into(),
            handle: "alice.test".into(),
            source_client: None,
            dest_client: None,
            phase: MigrationPhase::RepoTransferred,
        });

        let result = ensure_phase_did(&state, "did:plc:abc123", MigrationPhase::SourceAuthed);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().phase, MigrationPhase::RepoTransferred);
    }

    // AC10.1: MigrationError serialization — MigrationNotReady
    #[test]
    fn test_migration_error_serialization_not_ready() {
        let err = MigrationError::MigrationNotReady {
            message: "test message".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "MIGRATION_NOT_READY");
        assert_eq!(json["message"], "test message");
    }

    // AC10.1: MigrationError serialization — VerificationIncomplete
    #[test]
    fn test_migration_error_serialization_verification_incomplete() {
        let err = MigrationError::VerificationIncomplete {
            imported: 5,
            expected: 10,
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "VERIFICATION_INCOMPLETE");
        assert_eq!(json["imported"], 5);
        assert_eq!(json["expected"], 10);
    }

    // AC10.1: MigrationError serialization — DestinationUnreachable
    #[test]
    fn test_migration_error_serialization_destination_unreachable() {
        let err = MigrationError::DestinationUnreachable {
            message: "connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_UNREACHABLE");
        assert_eq!(json["message"], "connection refused");
    }

    // AC10.1: MigrationError serialization — SourceAuthFailed
    #[test]
    fn test_migration_error_serialization_source_auth_failed() {
        let err = MigrationError::SourceAuthFailed {
            message: "invalid grant".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "SOURCE_AUTH_FAILED");
        assert_eq!(json["message"], "invalid grant");
    }

    // AC10.1: MigrationError serialization — DestinationConflict
    #[test]
    fn test_migration_error_serialization_destination_conflict() {
        let err = MigrationError::DestinationConflict {
            message: "account exists but session was lost".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "DESTINATION_CONFLICT");
        assert_eq!(json["message"], "account exists but session was lost");
    }
}
