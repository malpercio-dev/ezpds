// pattern: Imperative Shell

//! The PDS half of a wallet-signed PLC operation that changes one key in the account's DID
//! document: the repo signing-key rotation (ADR-0025) and the KEM key install (ADR-0043).
//!
//! The wallet's device key outranks the PDS key in `rotationKeys` (ADR-0001), so the wallet
//! builds and signs the op, and hands it to the PDS instead of to plc.directory. The PDS checks
//! it against the DID's current state, submits it, and refreshes its cached document; each route
//! then checks the one key it cares about and promotes its staged key.

use common::{ApiError, ErrorCode};
use custos_core::identity::plc::{
    build_did_document_from_op, fetch_current_plc_state, CurrentPlcState,
};
use custos_db::dids::upsert_did_document;

use crate::app::AppState;

/// A wallet-signed op, verified against the DID's current PLC state.
pub struct WalletOp {
    pub verified: crypto::VerifiedPlcOp,
    /// The DID's state before the op (or, when `already_landed`, the op's own state).
    pub current: CurrentPlcState,
    /// The op is already the PLC head: a retry after a submit whose local cutover didn't land.
    pub already_landed: bool,
    json: String,
}

/// Verify `operation` is signed by one of the DID's current rotation keys and either chains onto
/// the current head or already is it.
pub async fn verify_wallet_op(
    state: &AppState,
    did: &str,
    operation: &serde_json::Value,
) -> Result<WalletOp, ApiError> {
    let json = serde_json::to_string(operation).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize submitted operation");
        ApiError::new(ErrorCode::InvalidRequest, "operation is not valid JSON")
    })?;
    let current =
        fetch_current_plc_state(&state.http_client, &state.config.plc_directory_url, did).await?;
    let authorized_keys: Vec<crypto::DidKeyUri> = current
        .rotation_keys
        .iter()
        .cloned()
        .map(crypto::DidKeyUri)
        .collect();
    let verified = crypto::verify_plc_operation(&json, &authorized_keys).map_err(|e| {
        tracing::warn!(error = %e, did = %did, "wallet operation failed verification");
        ApiError::new(
            ErrorCode::InvalidRequest,
            "operation is not signed by a current rotation key",
        )
    })?;
    let already_landed = verified.cid == current.cid;
    if !already_landed && verified.prev.as_deref() != Some(current.cid.as_str()) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "operation does not chain onto the current PLC head (prev mismatch)",
        ));
    }
    Ok(WalletOp {
        verified,
        current,
        already_landed,
        json,
    })
}

/// Submit the op to plc.directory (skipped when it already landed) and refresh the cached DID
/// document. The directory is the source of truth, so a cache failure is logged, not returned.
pub async fn submit_and_cache(state: &AppState, did: &str, op: &WalletOp) -> Result<(), ApiError> {
    if !op.already_landed {
        custos_core::identity::genesis::post_to_plc_directory(
            &state.http_client,
            &state.config.plc_directory_url,
            did,
            &op.json,
        )
        .await?;
    }
    let verified = &op.verified;
    match build_did_document_from_op(
        did,
        &verified.verification_methods,
        &verified.also_known_as,
        &verified.services,
    ) {
        Ok(doc) => {
            if let Err(e) = upsert_did_document(&state.db, did, &doc).await {
                tracing::warn!(error = %e, did = %did, "failed to refresh cached DID document after wallet operation (non-fatal)");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, did = %did, "wallet operation had no renderable DID document; cache left unchanged");
        }
    }
    Ok(())
}

/// Announce the identity change so relays re-resolve the document. `None` handle means "the
/// identity changed, re-resolve". Best-effort: the change is already durable.
pub async fn announce_identity(state: &AppState, did: &str) {
    if let Err(e) = state.firehose.emit_identity(did.to_string(), None).await {
        tracing::warn!(error = %e, did = %did, "failed to sequence #identity firehose event (non-fatal)");
    }
}
