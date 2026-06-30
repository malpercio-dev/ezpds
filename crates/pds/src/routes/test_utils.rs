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
        firehose: base.firehose,
        crawlers: base.crawlers,
        iroh: base.iroh,
    }
}

/// A fixed 32-byte signing-key master key for tests exercising commit signing.
pub fn test_master_key() -> [u8; 32] {
    [7u8; 32]
}

/// `test_state()` with the signing-key master key configured (see [`test_master_key`]).
pub async fn state_with_master_key() -> AppState {
    let base = test_state().await;
    let mut config = (*base.config).clone();
    config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
        test_master_key(),
    )));
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
        firehose: base.firehose,
        crawlers: base.crawlers,
        iroh: base.iroh,
    }
}

/// Insert a promoted account, generate + store its per-account repo signing key
/// (encrypted with [`test_master_key`]), create the genesis repo signed with that key,
/// and set `repo_root_cid`. Pair with [`state_with_master_key`] so `putRecord` can
/// reload the same key to sign subsequent commits.
pub async fn seed_account_with_repo(db: &sqlx::SqlitePool, did: &str) {
    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, 'hash', datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(format!("{did}@example.com"))
    .execute(db)
    .await
    .unwrap();

    let master = test_master_key();
    let kp = crypto::generate_p256_keypair().unwrap();
    let private_key_encrypted =
        crypto::encrypt_private_key(&kp.private_key_bytes, &master).unwrap();
    crate::db::repo_keys::insert_did_signing_key(
        db,
        did,
        &crate::db::repo_keys::RepoSigningKey {
            key_id: kp.key_id.to_string(),
            public_key: kp.public_key.clone(),
            private_key_encrypted,
        },
    )
    .await
    .unwrap();

    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let block_store = crate::db::blocks::SqliteBlockStore::new(db.clone(), did.to_string());
    let root = repo_engine::create_genesis_repo(block_store, did, &signer)
        .await
        .unwrap();
    // Persist repo_root_cid + repo_rev together, mirroring the production write paths so
    // tests exercise the stored-rev path rather than the legacy commit-block fallback.
    let reopen = crate::db::blocks::SqliteBlockStore::new(db.clone(), did.to_string());
    let rev = repo_engine::Repository::open(reopen, root)
        .await
        .unwrap()
        .commit()
        .rev()
        .as_str()
        .to_string();
    sqlx::query("UPDATE accounts SET repo_root_cid = ?, repo_rev = ? WHERE did = ?")
        .bind(root.to_string())
        .bind(&rev)
        .bind(did)
        .execute(db)
        .await
        .unwrap();
    // Tag the genesis blocks with the repo rev, mirroring the production genesis insert, so tests
    // that exercise getRepo?since see correctly-revisioned blocks. Tag the exact reachable set.
    let mut store = crate::db::blocks::SqliteBlockStore::new(db.clone(), did.to_string());
    let cids: Vec<String> = repo_engine::collect_reachable_cids(&mut store, root)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.to_string())
        .collect();
    crate::db::blocks::tag_blocks_rev(db, did, &cids, &rev)
        .await
        .unwrap();
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

/// Mint a short-lived HS256 access JWT (`com.atproto.access` scope) for `sub`,
/// signed with `secret`. Used by the repo record-write/read route tests.
pub(crate) fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({
            "scope": "com.atproto.access",
            "sub": sub,
            "iat": now,
            "exp": now + 7200_u64,
        }),
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

/// Deserialise a response body as `serde_json::Value`, consuming the response.
pub async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Build a `com.atproto.repo.putRecord` POST request with `repo`/`collection`/`rkey` merged into
/// the JSON `body` (which carries `record` and optionally `swapRecord`/`swapCommit`), per the lexicon.
pub fn put_record_request(
    did: &str,
    collection: &str,
    rkey: &str,
    mut body: serde_json::Value,
    token: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    body["repo"] = serde_json::json!(did);
    body["collection"] = serde_json::json!(collection);
    body["rkey"] = serde_json::json!(rkey);
    let mut b = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/xrpc/com.atproto.repo.putRecord")
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    b.body(axum::body::Body::from(
        serde_json::to_string(&body).unwrap(),
    ))
    .unwrap()
}

/// Build a `com.atproto.repo.deleteRecord` POST request with `repo`/`collection`/`rkey` merged into
/// the JSON `body` (which optionally carries `swapRecord`/`swapCommit`), per the lexicon.
pub fn delete_record_request(
    did: &str,
    collection: &str,
    rkey: &str,
    mut body: serde_json::Value,
    token: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    body["repo"] = serde_json::json!(did);
    body["collection"] = serde_json::json!(collection);
    body["rkey"] = serde_json::json!(rkey);
    let mut b = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/xrpc/com.atproto.repo.deleteRecord")
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        b = b.header("Authorization", format!("Bearer {t}"));
    }
    b.body(axum::body::Body::from(
        serde_json::to_string(&body).unwrap(),
    ))
    .unwrap()
}

/// Sign `message` with a P-256 keypair's private bytes, returning the base64url-encoded
/// r‖s (low-S normalised) signature. Shared by tests that exercise device signed-request auth.
pub fn sign_p256(keypair: &crypto::P256Keypair, message: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let sk =
        SigningKey::from_bytes(keypair.private_key_bytes.as_slice().into()).expect("valid scalar");
    let sig: Signature = sk.sign(message);
    URL_SAFE_NO_PAD.encode(sig.normalize_s().unwrap_or(sig).to_bytes())
}
