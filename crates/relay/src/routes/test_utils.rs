use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

use crate::app::{test_state, AppState};

/// Minimal test state with admin_token set to `"test-admin-token"`.
///
/// Wraps `test_state()` and overrides the single config field that most
/// admin-endpoint tests need. Defined once here rather than duplicated in
/// every route test module.
pub async fn test_state_with_admin_token() -> AppState {
    let base = test_state().await;
    let mut config = (*base.config).clone();
    config.admin_token = Some("test-admin-token".to_string());
    AppState {
        config: Arc::new(config),
        db: base.db,
        http_client: base.http_client,
        dns_provider: base.dns_provider,
        txt_resolver: base.txt_resolver,
        well_known_resolver: base.well_known_resolver,
        jwt_secret: base.jwt_secret,
        oauth_signing_keypair: base.oauth_signing_keypair,
        dpop_nonces: base.dpop_nonces,
        failed_login_attempts: base.failed_login_attempts,
    }
}

/// Insert a fully provisioned account row with an argon2id-hashed password and a handle.
///
/// Used across route tests that exercise password authentication
/// (`createSession`, `POST /v1/accounts/sessions`). Using real Argon2 with production
/// parameters means parameter drift would surface as a test failure.
pub async fn insert_account_with_password(
    db: &sqlx::SqlitePool,
    did: &str,
    handle: &str,
    email: &str,
    password: &str,
) {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(email)
    .bind(&hash)
    .execute(db)
    .await
    .unwrap();

    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(handle)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
}

/// Insert an account with NULL password_hash and a handle. Used for mobile/handle-only accounts
/// in tests that don't exercise password authentication.
pub async fn seed_handle(db: &sqlx::SqlitePool, handle: &str, did: &str) {
    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(format!("{did}@test.example.com"))
    .execute(db)
    .await
    .expect("insert account");

    sqlx::query("INSERT INTO handles (handle, did, created_at) VALUES (?, ?, datetime('now'))")
        .bind(handle)
        .bind(did)
        .execute(db)
        .await
        .expect("insert handle");
}

/// Deserialise a response body as `serde_json::Value`, consuming the response.
pub async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
