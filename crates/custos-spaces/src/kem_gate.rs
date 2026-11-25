// pattern: Imperative Shell

//! The account's published KEM key, as the write gate and the read MACs see it (ADR-0043).
//!
//! A syncer reading a space record checks a MAC keyed by a secret it agrees with the writer's
//! host, using the writer's `#atproto_kem` key from its DID document. If the document does not
//! publish the key this host actually holds, no syncer can verify what the account writes, so
//! every space write route but the two migration imports (`space_migration`) calls
//! [`require_kem_key_published`] first (and
//! `policy::commit_with_published` calls [`require_kem_key_published_in`] before it publishes
//! records), refusing with `KemKeyNotPublished` until the account publishes it
//! (`POST /v1/kem-key`). Reads stay open: [`published_kem_private_key`] is `None` for such an
//! account, and `space_mac` serves the read without a MAC.
//!
//! The check reads this host's cached copy of the account's document, never plc.directory: the
//! cache is refreshed by every path that changes the document here (genesis, the KEM ceremony,
//! `submitPlcOperation`, activation), and neither a write nor a read may cost an outbound call.

use common::{ApiError, ApiResultExt, ErrorCode};
use custos_core::CoreState;
use custos_db::kem_keys::KemKey;

/// Refuse a space write by `did` unless its cached DID document publishes its active KEM key.
pub async fn require_kem_key_published(state: &CoreState, did: &str) -> Result<(), ApiError> {
    let mut conn = state
        .db
        .acquire()
        .await
        .or_internal_as("failed to acquire a connection", "internal server error")?;
    require_kem_key_published_in(&mut conn, did).await
}

/// [`require_kem_key_published`] on a connection the caller already holds, such as an open
/// transaction: the pool has one connection, so acquiring another would wait forever.
pub async fn require_kem_key_published_in(
    conn: &mut sqlx::SqliteConnection,
    did: &str,
) -> Result<(), ApiError> {
    if published_active_key(conn, did).await?.is_some() {
        return Ok(());
    }
    Err(ApiError::new(
        ErrorCode::KemKeyNotPublished,
        "your DID document does not publish this account's Spaces KEM key; \
         publish it through POST /v1/kem-key before writing to a space",
    ))
}

/// The private half of `did`'s active KEM key, if its cached DID document publishes it; `None`
/// when the account has no key or has not published it.
pub async fn published_kem_private_key(
    state: &CoreState,
    did: &str,
) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, ApiError> {
    let mut conn = state
        .db
        .acquire()
        .await
        .or_internal_as("failed to acquire a connection", "internal server error")?;
    let Some(key) = published_active_key(&mut conn, did).await? else {
        return Ok(None);
    };
    let master_key = custos_core::kem::master_key(state)?;
    crypto::decrypt_private_key(&key.private_key_encrypted, master_key)
        .map(Some)
        .or_internal_as("failed to decrypt KEM key", "failed to load KEM key")
}

async fn published_active_key(
    conn: &mut sqlx::SqliteConnection,
    did: &str,
) -> Result<Option<KemKey>, ApiError> {
    let Some(key) = custos_db::kem_keys::get_active_kem_key(&mut *conn, did)
        .await
        .or_internal_as("failed to load KEM key", "failed to load KEM key")?
    else {
        return Ok(None);
    };
    let published = custos_db::dids::get_did_document(&mut *conn, did)
        .await?
        .is_some_and(|doc| custos_core::kem::publishes(&doc, &key));
    Ok(published.then_some(key))
}
