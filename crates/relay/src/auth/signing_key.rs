// pattern: Imperative Shell

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::pkcs8::EncodePrivateKey;
use sqlx::SqlitePool;
use uuid::Uuid;

/// The server's persistent ES256 signing keypair, held in `AppState`.
///
/// `encoding_key` is derived from the P-256 private key in PKCS#8 DER format, as required by
/// `jsonwebtoken`. `key_id` is a UUID that appears as the `kid` header in issued access tokens.
///
/// # Dead Code Lint
///
/// Axum's `State<AppState>` extractor is opaque to Rust's dead code analyzer — fields read
/// through `State<AppState>` appear unused even though they are accessed by every handler.
#[derive(Clone)]
#[allow(dead_code)]
pub struct OAuthSigningKey {
    /// UUID identifier embedded in JWT `kid` header.
    pub key_id: String,
    /// PKCS#8 DER ES256 encoding key for JWT signing.
    pub encoding_key: jsonwebtoken::EncodingKey,
    /// Public JWK for verifying ES256 AT+JWT tokens at resource endpoints.
    pub public_key_jwk: serde_json::Value,
}

/// Load the OAuth signing key from the database, or generate a new one on first boot.
///
/// If `master_key` is `None`, generates an ephemeral (non-persistent) key and logs a warning.
/// Ephemeral keys are not stored in the DB and invalidate all issued tokens on restart.
pub async fn load_or_create_oauth_signing_key(
    pool: &SqlitePool,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    use crate::db::oauth::{get_oauth_signing_key, store_oauth_signing_key};

    // Attempt to load an existing key.
    if let Some(row) = get_oauth_signing_key(pool).await? {
        let key = decode_oauth_signing_key(
            &row.id,
            &row.private_key_encrypted,
            &row.public_key_jwk,
            master_key,
        )?;
        tracing::info!(key_id = %row.id, "OAuth signing key loaded from database");
        return Ok(key);
    }

    // No key stored yet. Generate one.
    let keypair = crypto::generate_p256_keypair()
        .map_err(|e| anyhow::anyhow!("failed to generate P-256 keypair: {e}"))?;

    let key_id = Uuid::new_v4().to_string();

    // Build JWK for the public key (uncompressed EC point → x, y coordinates).
    let signing_key = p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(
        keypair.private_key_bytes.as_ref(),
    ))
    .map_err(|e| anyhow::anyhow!("invalid P-256 private key bytes: {e}"))?;

    let vk = signing_key.verifying_key();
    let point = vk.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 x coordinate"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 y coordinate"));
    let public_key_jwk = serde_json::to_string(&serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key_id,
    }))
    .map_err(|e| anyhow::anyhow!("JWK serialization failed: {e}"))?;

    match master_key {
        Some(key) => {
            let encrypted = crypto::encrypt_private_key(&keypair.private_key_bytes, key)
                .map_err(|e| anyhow::anyhow!("key encryption failed: {e}"))?;
            store_oauth_signing_key(pool, &key_id, &public_key_jwk, &encrypted).await?;
            tracing::info!(key_id = %key_id, "OAuth signing key generated and persisted");
        }
        None => {
            tracing::warn!(
                "signing_key_master_key not configured; \
                 OAuth signing key is ephemeral — tokens will be invalidated on restart"
            );
        }
    }

    let encoding_key = build_encoding_key(&signing_key)?;
    let public_key_jwk_json: serde_json::Value = serde_json::from_str(&public_key_jwk)
        .map_err(|e| anyhow::anyhow!("JWK JSON invalid after serialization: {e}"))?;
    Ok(OAuthSigningKey {
        key_id,
        encoding_key,
        public_key_jwk: public_key_jwk_json,
    })
}

/// Decode a stored OAuth signing key row into an `OAuthSigningKey`.
fn decode_oauth_signing_key(
    key_id: &str,
    private_key_encrypted: &str,
    public_key_jwk_str: &str,
    master_key: Option<&[u8; 32]>,
) -> anyhow::Result<OAuthSigningKey> {
    let master_key = master_key.ok_or_else(|| {
        anyhow::anyhow!(
            "signing_key_master_key not configured but an OAuth signing key exists in the DB; \
             cannot decrypt it — set signing_key_master_key in config"
        )
    })?;

    let raw_bytes = crypto::decrypt_private_key(private_key_encrypted, master_key)
        .map_err(|e| anyhow::anyhow!("failed to decrypt OAuth signing key: {e}"))?;

    let signing_key =
        p256::ecdsa::SigningKey::from_bytes(p256::FieldBytes::from_slice(raw_bytes.as_ref()))
            .map_err(|e| anyhow::anyhow!("invalid stored P-256 private key: {e}"))?;

    let encoding_key = build_encoding_key(&signing_key)?;
    let public_key_jwk: serde_json::Value = serde_json::from_str(public_key_jwk_str)
        .map_err(|e| anyhow::anyhow!("public JWK JSON invalid: {e}"))?;
    Ok(OAuthSigningKey {
        key_id: key_id.to_string(),
        encoding_key,
        public_key_jwk,
    })
}

/// Convert a `p256::ecdsa::SigningKey` to a `jsonwebtoken::EncodingKey` via PKCS#8 DER.
fn build_encoding_key(
    signing_key: &p256::ecdsa::SigningKey,
) -> anyhow::Result<jsonwebtoken::EncodingKey> {
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("PKCS#8 DER encoding failed: {e}"))?;
    Ok(jsonwebtoken::EncodingKey::from_ec_der(pkcs8_der.as_bytes()))
}
