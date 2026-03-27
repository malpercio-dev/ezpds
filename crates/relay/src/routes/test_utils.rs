use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

use crate::app::{test_state, AppState};

// ── DNS provider test doubles ──────────────────────────────────────────────

/// DNS provider that succeeds on every `create_record` and `delete_record` call.
pub struct AlwaysOkDns;

/// DNS provider that fails on every `create_record` and `delete_record` call.
pub struct AlwaysErrDns;

impl crate::dns::DnsProvider for AlwaysOkDns {
    fn create_record<'a>(
        &'a self,
        _name: &'a str,
        _target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn delete_record<'a>(
        &'a self,
        _name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

impl crate::dns::DnsProvider for AlwaysErrDns {
    fn create_record<'a>(
        &'a self,
        _name: &'a str,
        _target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Err(crate::dns::DnsError("simulated provider error".to_string())) })
    }

    fn delete_record<'a>(
        &'a self,
        _name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Err(crate::dns::DnsError("simulated provider error".to_string())) })
    }
}

/// `test_state()` with an `AlwaysOkDns` provider wired in.
pub async fn state_with_ok_dns() -> AppState {
    let base = test_state().await;
    AppState {
        dns_provider: Some(Arc::new(AlwaysOkDns)),
        ..base
    }
}

/// `test_state()` with an `AlwaysErrDns` provider wired in.
pub async fn state_with_err_dns() -> AppState {
    let base = test_state().await;
    AppState {
        dns_provider: Some(Arc::new(AlwaysErrDns)),
        ..base
    }
}

// ── Admin state helper ────────────────────────────────────────────────────────

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

/// Insert a DID document row directly into `did_documents`.
///
/// `did_documents` has no FK to `accounts`, so this can be used without a corresponding
/// account row. Used in tests that exercise DID document retrieval endpoints.
pub async fn seed_did_document(db: &sqlx::SqlitePool, did: &str, document: serde_json::Value) {
    sqlx::query(
        "INSERT INTO did_documents (did, document, created_at, updated_at) \
         VALUES (?, ?, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(document.to_string())
    .execute(db)
    .await
    .expect("insert did_document");
}

/// Seed a device row with a fresh device token. Returns `(device_id, plaintext_token)`.
///
/// Creates a claim code + pending account + device row in one shot. Each call
/// generates unique IDs so the helper is safe to call multiple times on the same pool.
pub async fn seed_device(db: &sqlx::SqlitePool) -> (String, String) {
    use crate::routes::token::generate_token;
    use uuid::Uuid;

    let claim_code = format!("TEST-{}", Uuid::new_v4());
    sqlx::query(
        "INSERT INTO claim_codes (code, expires_at, created_at) \
         VALUES (?, datetime('now', '+1 hour'), datetime('now'))",
    )
    .bind(&claim_code)
    .execute(db)
    .await
    .unwrap();

    let account_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO pending_accounts \
         (id, email, handle, tier, claim_code, created_at) \
         VALUES (?, ?, ?, 'free', ?, datetime('now'))",
    )
    .bind(&account_id)
    .bind(format!("dev{}@example.com", &account_id[..8]))
    .bind(format!("dev{}.example.com", &account_id[..8]))
    .bind(&claim_code)
    .execute(db)
    .await
    .unwrap();

    let device_id = Uuid::new_v4().to_string();
    let token = generate_token();
    sqlx::query(
        "INSERT INTO devices \
         (id, account_id, platform, public_key, device_token_hash, created_at, last_seen_at) \
         VALUES (?, ?, 'ios', 'test_pubkey', ?, datetime('now'), datetime('now'))",
    )
    .bind(&device_id)
    .bind(&account_id)
    .bind(&token.hash)
    .execute(db)
    .await
    .unwrap();

    (device_id, token.plaintext)
}

/// Deserialise a response body as `serde_json::Value`, consuming the response.
pub async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
