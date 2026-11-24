// pattern: Imperative Shell

//! The write-side KEM key gate (ADR-0043).
//!
//! A syncer reading a space record checks a MAC keyed by a secret it agrees with the writer's
//! host, using the writer's `#atproto_kem` key from its DID document. If the document does not
//! publish the key this host actually holds, no syncer can verify what the account writes, so
//! every space write route calls [`require_kem_key_published`] first (and
//! `policy::commit_with_published` calls [`require_kem_key_published_in`] before it publishes
//! records), refusing with `KemKeyNotPublished` until the account publishes it
//! (`POST /v1/kem-key`). Reads stay open; they are served without a MAC.
//!
//! The check reads this host's cached copy of the account's document, never plc.directory: the
//! cache is refreshed by every path that changes the document here (genesis, the KEM ceremony,
//! `submitPlcOperation`, activation), and a write must not cost an outbound call.

use common::{ApiError, ApiResultExt, ErrorCode};
use custos_core::CoreState;

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
    let active = custos_db::kem_keys::get_active_kem_key(&mut *conn, did)
        .await
        .or_internal_as("failed to load KEM key", "failed to load KEM key")?;
    let published = match &active {
        Some(key) => custos_db::dids::get_did_document(&mut *conn, did)
            .await?
            .is_some_and(|doc| custos_core::kem::publishes(&doc, key)),
        None => false,
    };
    if published {
        return Ok(());
    }
    Err(ApiError::new(
        ErrorCode::KemKeyNotPublished,
        "your DID document does not publish this account's Spaces KEM key; \
         publish it through POST /v1/kem-key before writing to a space",
    ))
}
