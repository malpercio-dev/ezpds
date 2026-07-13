// pattern: Imperative Shell

//! Shared legacy-session issuance for password, migration, and sovereign authentication.
//!
//! A session's authority is explicit at the call site: full-access sessions carry no app-password
//! identity, while app-password sessions carry both their name and privilege. The latter is
//! re-checked on the transaction connection before any credential is persisted, so a concurrent
//! revocation cannot race a previously verified password into a fresh session.

use std::time::{SystemTime, UNIX_EPOCH};

use common::{ApiError, ErrorCode};
use uuid::Uuid;

use crate::app::AppState;
use crate::auth::jwt::{app_pass_scope, issue_access_jwt, issue_refresh_jwt, SCOPE_ACCESS};

/// The authority and revocation identity of a legacy ATProto session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// A normal account-owner session with `com.atproto.access` scope.
    FullAccess,
    /// A limited session whose refresh lineage remains tied to a named app password.
    AppPassword { name: String, privileged: bool },
}

impl SessionKind {
    fn scope(&self) -> &'static str {
        match self {
            Self::FullAccess => SCOPE_ACCESS,
            Self::AppPassword { privileged, .. } => app_pass_scope(*privileged),
        }
    }

    fn app_password_name(&self) -> Option<&str> {
        match self {
            Self::FullAccess => None,
            Self::AppPassword { name, .. } => Some(name.as_str()),
        }
    }

    pub fn is_app_password(&self) -> bool {
        matches!(self, Self::AppPassword { .. })
    }
}

/// The standard response fields returned by legacy session-issuing flows.
#[derive(Debug)]
pub struct IssuedSession {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
    pub email: Option<String>,
}

/// Issue and atomically persist a complete legacy session for an existing account DID.
///
/// This is the reusable entry point for authentication flows that do not already own a broader
/// transaction. Either both the `sessions` and initial `refresh_tokens` rows commit or neither
/// does.
pub async fn issue_session(
    state: &AppState,
    did: &str,
    kind: &SessionKind,
) -> Result<IssuedSession, ApiError> {
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to begin session issuance transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    let issued = issue_session_in_transaction(&mut tx, state, did, kind).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to commit session issuance transaction");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;
    Ok(issued)
}

/// Issue a session inside a caller-owned transaction.
///
/// Account creation uses this form so the account, repo, and initial session remain one atomic
/// promotion. Other callers should use [`issue_session`], which owns the transaction boundary.
pub async fn issue_session_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    state: &AppState,
    did: &str,
    kind: &SessionKind,
) -> Result<IssuedSession, ApiError> {
    if let Some(name) = kind.app_password_name() {
        if !crate::db::app_passwords::app_password_exists(&mut **tx, did, name).await? {
            return Err(ApiError::new(
                ErrorCode::AuthenticationRequired,
                "invalid identifier or password",
            ));
        }
    }

    let subject: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT email, \
                (SELECT handle FROM handles WHERE did = accounts.did \
                 ORDER BY created_at, handle LIMIT 1) \
         FROM accounts WHERE did = ?",
    )
    .bind(did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to load session response fields");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;
    let (account_email, handle) = subject.ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "cannot issue a session for an unknown account DID",
        )
    })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| {
            tracing::error!(error = %e, "system clock is before Unix epoch");
            ApiError::new(ErrorCode::InternalError, "failed to issue token")
        })?
        .as_secs();
    let aud = state
        .config
        .server_did
        .as_deref()
        .unwrap_or(&state.config.public_url);

    let access_jwt = issue_access_jwt(&state.jwt_secret, did, aud, now, kind.scope())?;
    let refresh_jti = Uuid::new_v4().to_string();
    let refresh_jwt = issue_refresh_jwt(&state.jwt_secret, did, aud, &refresh_jti, now)?;
    let session_id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO sessions (id, did, device_id, token_hash, created_at, expires_at) \
         VALUES (?, ?, NULL, NULL, datetime('now'), datetime('now', '+90 days'))",
    )
    .bind(&session_id)
    .bind(did)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to insert session");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    sqlx::query(
        "INSERT INTO refresh_tokens \
         (jti, did, session_id, expires_at, app_password_name, created_at) \
         VALUES (?, ?, ?, datetime('now', '+90 days'), ?, datetime('now'))",
    )
    .bind(&refresh_jti)
    .bind(did)
    .bind(&session_id)
    .bind(kind.app_password_name())
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, did = %did, "failed to insert refresh token");
        ApiError::new(ErrorCode::InternalError, "failed to create session")
    })?;

    Ok(IssuedSession {
        access_jwt,
        refresh_jwt,
        handle: handle.unwrap_or_else(|| "handle.invalid".to_string()),
        did: did.to_string(),
        email: (!kind.is_app_password()).then_some(account_email),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::auth::jwt::{parse_scope, verify_hs256_access_token, AuthScope};

    async fn seed_account(state: &AppState, did: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, 'owner@example.com', NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_access_issuance_persists_complete_session() {
        let state = test_state().await;
        let did = "did:plc:issuer";
        seed_account(&state, did).await;

        let issued = issue_session(&state, did, &SessionKind::FullAccess)
            .await
            .unwrap();
        let claims = verify_hs256_access_token(&issued.access_jwt, &state).unwrap();
        assert_eq!(claims.sub, did);
        assert_eq!(parse_scope(&claims.scope).unwrap(), AuthScope::Access);
        assert_eq!(issued.did, did);
        assert_eq!(issued.handle, "handle.invalid");
        assert_eq!(issued.email.as_deref(), Some("owner@example.com"));

        let stored: (i64, i64, Option<String>) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM sessions WHERE did = ?), \
                    (SELECT COUNT(*) FROM refresh_tokens WHERE did = ?), \
                    (SELECT app_password_name FROM refresh_tokens WHERE did = ?)",
        )
        .bind(did)
        .bind(did)
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(stored, (1, 1, None));
    }

    #[tokio::test]
    async fn refresh_insert_failure_rolls_back_session_row() {
        let state = test_state().await;
        let did = "did:plc:atomic";
        seed_account(&state, did).await;
        sqlx::query(
            "CREATE TRIGGER reject_initial_refresh BEFORE INSERT ON refresh_tokens \
             BEGIN SELECT RAISE(ABORT, 'simulated refresh failure'); END",
        )
        .execute(&state.db)
        .await
        .unwrap();

        assert!(issue_session(&state, did, &SessionKind::FullAccess)
            .await
            .is_err());
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM sessions WHERE did = ?), \
                    (SELECT COUNT(*) FROM refresh_tokens WHERE did = ?)",
        )
        .bind(did)
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(counts, (0, 0));
    }

    #[tokio::test]
    async fn app_password_session_keeps_limited_scope_and_revocation_identity() {
        let state = test_state().await;
        let did = "did:plc:app-session";
        seed_account(&state, did).await;
        sqlx::query(
            "INSERT INTO app_passwords \
             (did, name, password_hash, privileged, created_at) \
             VALUES (?, 'cli', 'unused-by-issuer', 1, datetime('now'))",
        )
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();

        let issued = issue_session(
            &state,
            did,
            &SessionKind::AppPassword {
                name: "cli".to_string(),
                privileged: true,
            },
        )
        .await
        .unwrap();
        let claims = verify_hs256_access_token(&issued.access_jwt, &state).unwrap();
        assert_eq!(
            parse_scope(&claims.scope).unwrap(),
            AuthScope::AppPassPrivileged
        );
        assert_eq!(issued.email, None);
        let stored_name: Option<String> =
            sqlx::query_scalar("SELECT app_password_name FROM refresh_tokens WHERE did = ?")
                .bind(did)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stored_name.as_deref(), Some("cli"));
    }
}
