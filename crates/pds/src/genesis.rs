// pattern: Mixed (unavoidable)
//
// Shared did:plc genesis-op machinery used by both the device-signed ceremony
// (`routes/create_did.rs`, POST /v1/dids) and the standard XRPC onboarding path
// (`routes/create_account_xrpc.rs`, com.atproto.server.createAccount). The pure builders
// (DID-document construction, genesis/commit CAR framing, genesis-op verify + semantic
// validation) are a Functional Core; `post_to_plc_directory` is the one Imperative Shell
// function here (an outbound HTTP call), kept alongside its callers.

use common::{ApiError, ErrorCode};

/// Validate the rotation-key format, verify the genesis op signature, and check that the op
/// fields match the account handle and server config.
///
/// The op is **self-signed** by the client's rotation key (`rotationKeys[0]`) — the PDS never
/// signs it and never holds the top rotation key (ADR-0001). Returns the verified op alongside
/// the exact JSON string that was verified (for submission to plc.directory).
pub fn verify_and_validate_genesis_op(
    rotation_key_public: &str,
    signed_creation_op: &serde_json::Value,
    handle: &str,
    public_url: &str,
) -> Result<(crypto::VerifiedGenesisOp, String), ApiError> {
    // Validate rotationKeyPublic format.
    if !rotation_key_public.starts_with("did:key:z") {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "rotationKeyPublic must be a did:key: URI starting with 'did:key:z'",
        ));
    }
    let rotation_key = crypto::DidKeyUri(rotation_key_public.to_string());

    // Serialize the submitted signed op to a JSON string for crypto verification.
    let signed_op_str = serde_json::to_string(signed_creation_op).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize signedCreationOp");
        ApiError::new(ErrorCode::InternalError, "failed to process signed op")
    })?;

    // Verify the ECDSA signature and derive the DID.
    let verified = crypto::verify_genesis_op(&signed_op_str, &rotation_key).map_err(|e| {
        tracing::warn!(error = %e, "genesis op verification failed");
        ApiError::new(ErrorCode::InvalidClaim, "signed genesis op is invalid")
    })?;

    // Semantic validation — ensure op fields match account and server config.
    if verified.rotation_keys.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op rotationKeys is empty",
        ));
    }
    if verified.rotation_keys.first().map(String::as_str) != Some(rotation_key_public) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "rotationKeys[0] in op does not match rotationKeyPublic",
        ));
    }
    if verified.also_known_as.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "op alsoKnownAs is empty",
        ));
    }
    if verified.also_known_as.first().map(String::as_str) != Some(&format!("at://{handle}")) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "alsoKnownAs[0] in op does not match account handle",
        ));
    }
    if verified.atproto_pds_endpoint.as_deref() != Some(public_url) {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "services.atproto_pds.endpoint in op does not match server public URL",
        ));
    }

    Ok((verified, signed_op_str))
}

/// POST the signed genesis operation to plc.directory.
pub async fn post_to_plc_directory(
    http_client: &reqwest::Client,
    plc_directory_url: &str,
    did: &str,
    signed_op_str: &str,
) -> Result<(), ApiError> {
    let plc_url = format!("{plc_directory_url}/{did}");
    let response = http_client
        .post(&plc_url)
        .body(signed_op_str.to_string())
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, plc_url = %plc_url, "failed to contact plc.directory");
            ApiError::new(
                ErrorCode::PlcDirectoryError,
                "failed to contact plc.directory",
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        tracing::error!(
            status = %status,
            body = %body_text,
            "plc.directory rejected genesis operation"
        );
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            format!("plc.directory returned {status}"),
        ));
    }
    Ok(())
}

/// Build the CARv1 bytes for the genesis commit's `#commit` firehose frame from the in-memory
/// blocks `build_genesis_repo` returned. Every block genesis writes is reachable from `root`
/// (there is no previous commit to diff against), so — unlike `record_write::commit_repo_write`,
/// which reads blocks back from the block store — no diff computation or store round trip is
/// needed here.
pub fn build_genesis_car(
    root: repo_engine::Cid,
    blocks: &[(repo_engine::Cid, Vec<u8>)],
) -> Vec<u8> {
    let mut ordered: Vec<&(repo_engine::Cid, Vec<u8>)> = blocks.iter().collect();
    // Root-first, then CID order — mirrors `repo_engine::car_export`'s own block ordering, which
    // many streaming CAR parsers expect.
    ordered.sort_unstable_by_key(|(cid, _)| (*cid != root, *cid));
    let mut car = repo_engine::car_v1_header(root);
    for (cid, bytes) in ordered {
        car.extend_from_slice(&repo_engine::car_v1_block_frame(*cid, bytes));
    }
    car
}

/// Build the CARv1 bytes for a `#sync` frame: a single-root CAR (root = the signed `commit` CID)
/// carrying just the commit block. Sync v1.1 `#sync.blocks` asserts the current repo head, so a
/// relay only needs the signed commit block to re-anchor — not the whole repo — and the lexicon
/// caps the field at 10 KB. Returns `None` if the commit block is somehow absent from `blocks`
/// (a genesis-build invariant violation the caller reports as an internal error).
pub fn build_commit_block_car(
    commit: repo_engine::Cid,
    blocks: &[(repo_engine::Cid, Vec<u8>)],
) -> Option<Vec<u8>> {
    let bytes = blocks
        .iter()
        .find_map(|(cid, bytes)| (*cid == commit).then_some(bytes))?;
    let mut car = repo_engine::car_v1_header(commit);
    car.extend_from_slice(&repo_engine::car_v1_block_frame(commit, bytes));
    Some(car)
}

/// Construct a minimal DID Core document from a verified genesis operation.
///
/// No I/O — pure construction from [`crypto::VerifiedGenesisOp`] fields.
///
/// # Errors
/// Returns `InternalError` if `verificationMethods["atproto"]` is absent or is not a did:key: URI.
pub fn build_did_document(
    verified: &crypto::VerifiedGenesisOp,
) -> Result<serde_json::Value, ApiError> {
    let did = &verified.did;

    // Extract the multibase key from did:key URI for publicKeyMultibase.
    // did:key:zAbcDef... → publicKeyMultibase = "zAbcDef..."
    let atproto_did_key = verified
        .verification_methods
        .get("atproto")
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::InternalError,
                "atproto verification method not found in op",
            )
        })?;
    let public_key_multibase = atproto_did_key.strip_prefix("did:key:").ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "atproto key is not a did:key: URI",
        )
    })?;

    let service_endpoint = verified.atproto_pds_endpoint.as_deref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::InternalError,
            "missing service endpoint in verified op",
        )
    })?;

    Ok(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1"
        ],
        "id": did,
        "alsoKnownAs": &verified.also_known_as,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint
        }]
    }))
}
