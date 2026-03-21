pub mod device_key;
pub mod http;
pub mod keychain;

use crypto::{build_did_plc_genesis_op_with_external_signer, CryptoError, DidKeyUri};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

// ── Request / response types ────────────────────────────────────────────────

/// JSON body sent to POST /v1/accounts/mobile.
/// Field names match the relay's camelCase deserialization.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountRequest {
    email: String,
    handle: String,
    device_public_key: String,
    platform: String,
    claim_code: String,
}

/// Successful 201 response from the relay.
///
/// The relay returns additional fields (account_id, device_id) which are
/// silently ignored by serde's default behavior. This struct captures only
/// the three fields needed by the client.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountResponse {
    device_token: String,
    session_token: String,
    next_step: NextStep,
}

/// Response from GET /v1/relay/keys — the relay's active signing key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelaySigningKey {
    key_id: String,
    #[allow(dead_code)]
    public_key: String,
    #[allow(dead_code)]
    algorithm: String,
}

/// Request body for POST /v1/dids — submit the signed genesis op for DID promotion.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDidRequest {
    rotation_key_public: String,
    signed_creation_op: serde_json::Value,
}

/// Response from POST /v1/dids — the promoted DID and upgraded session token.
#[derive(Deserialize)]
struct CreateDidResponse {
    did: String,
    session_token: String,
}

/// Relay error envelope: { "error": { "code": "...", "message": "..." } }
#[derive(Deserialize)]
struct RelayErrorEnvelope {
    error: RelayErrorBody,
}

#[derive(Deserialize)]
struct RelayErrorBody {
    code: String,
}

// ── IPC result / error types (returned to the frontend) ─────────────────────

/// The next step the client should take after successful account creation.
///
/// If the relay returns an unrecognized value, serde deserialization fails and
/// `create_account` returns `CreateAccountError::Unknown` — unrecognized relay
/// protocol values are caught here rather than silently forwarded to the frontend.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NextStep {
    DidCreation,
}

/// Successful result returned to the Svelte frontend.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResult {
    pub next_step: NextStep,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "EXPIRED_CODE" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreateAccountError {
    #[error("claim code has expired")]
    ExpiredCode,
    #[error("claim code already redeemed")]
    RedeemedCode,
    #[error("email already taken")]
    EmailTaken,
    #[error("handle already taken")]
    HandleTaken,
    #[error("keychain storage failed")]
    KeychainError,
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

/// Successful result returned to the Svelte frontend after DID ceremony completes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DIDCeremonyResult {
    pub did: String,
}

/// Typed error returned to the Svelte frontend as a rejected Promise.
///
/// Serializes as `{ "code": "NO_RELAY_SIGNING_KEY" }` (SCREAMING_SNAKE_CASE) so
/// the TypeScript catch block can switch on `error.code`.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DIDCeremonyError {
    #[error("failed to get or create device key")]
    KeyNotFound,
    #[error("failed to fetch relay signing key")]
    RelayKeyFetchFailed,
    #[error("relay has no signing key provisioned")]
    NoRelaySigningKey,
    #[error("device signing failed")]
    SigningFailed,
    #[error("DID creation request failed")]
    DidCreationFailed,
    #[error("keychain operation failed")]
    KeychainError,
    #[error("network error: {message}")]
    NetworkError { message: String },
}

// ── Static relay client ─────────────────────────────────────────────────────

static RELAY_CLIENT: LazyLock<http::RelayClient> = LazyLock::new(http::RelayClient::new);

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Map a relay 409 error subcode string to a typed `CreateAccountError` variant.
fn map_409_subcode(code: &str) -> CreateAccountError {
    match code {
        "CLAIM_CODE_REDEEMED" => CreateAccountError::RedeemedCode,
        "ACCOUNT_EXISTS" => CreateAccountError::EmailTaken,
        "HANDLE_TAKEN" => CreateAccountError::HandleTaken,
        other => CreateAccountError::Unknown {
            message: format!("409: {other}"),
        },
    }
}

// ── IPC command ─────────────────────────────────────────────────────────────

#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
) -> Result<CreateAccountResult, CreateAccountError> {
    // 1. Get or create the device's SE-backed (or simulator-fallback) P-256 key.
    let device_key = device_key::get_or_create().map_err(|_| CreateAccountError::KeychainError)?;

    // 2. POST to relay.
    let req = CreateMobileAccountRequest {
        email,
        handle,
        device_public_key: device_key.multibase,
        platform: "ios".to_string(),
        claim_code,
    };

    let resp = RELAY_CLIENT
        .post("/v1/accounts/mobile", &req)
        .await
        .map_err(|e| CreateAccountError::NetworkError {
            message: e.to_string(),
        })?;

    let status = resp.status();

    if status.is_success() {
        // 4. Deserialize success body.
        let body: CreateMobileAccountResponse =
            resp.json().await.map_err(|e| CreateAccountError::Unknown {
                message: e.to_string(),
            })?;

        // 5. Store tokens in Keychain.
        // If session-token write fails, best-effort remove the already-written device-token.
        // The device key is persistent by design and is NOT cleaned up on failure.
        keychain::store_item("device-token", body.device_token.as_bytes()).map_err(|_| {
            // device-token write failed — nothing to clean up; the device key is persistent by design.
            CreateAccountError::KeychainError
        })?;

        keychain::store_item("session-token", body.session_token.as_bytes()).map_err(|_| {
            // Best-effort cleanup: remove the already-written device-token.
            let _ = keychain::delete_item("device-token");
            CreateAccountError::KeychainError
        })?;

        Ok(CreateAccountResult {
            next_step: body.next_step,
        })
    } else {
        // 6. Map relay error codes to typed variants.
        match status.as_u16() {
            // 404: Relay returns this for both invalid (never-existed) and expired claim codes.
            // The frontend cannot distinguish them, so we map both to ExpiredCode.
            404 => Err(CreateAccountError::ExpiredCode),
            409 => {
                let envelope: RelayErrorEnvelope =
                    resp.json().await.map_err(|e| CreateAccountError::Unknown {
                        message: e.to_string(),
                    })?;
                Err(map_409_subcode(&envelope.error.code))
            }
            _ => Err(CreateAccountError::NetworkError {
                message: format!("HTTP {}", status.as_u16()),
            }),
        }
    }
}

#[tauri::command]
async fn get_or_create_device_key(
) -> Result<device_key::DevicePublicKey, device_key::DeviceKeyError> {
    device_key::get_or_create()
}

#[tauri::command]
async fn sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, device_key::DeviceKeyError> {
    device_key::sign(&data)
}

#[tauri::command]
async fn perform_did_ceremony(handle: String) -> Result<DIDCeremonyResult, DIDCeremonyError> {
    // Step 1: Get or create the device's P-256 key (serves as rotation key).
    let device_key = device_key::get_or_create().map_err(|e| {
        tracing::warn!(error = %e, "device key creation failed during DID ceremony");
        DIDCeremonyError::KeyNotFound
    })?;

    // Step 2: Fetch the relay's active signing key (public, no auth required).
    let resp =
        RELAY_CLIENT
            .get("/v1/relay/keys")
            .await
            .map_err(|e| DIDCeremonyError::NetworkError {
                message: e.to_string(),
            })?;

    let status = resp.status();
    if status.as_u16() == 503 {
        return Err(DIDCeremonyError::NoRelaySigningKey);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %body, "GET /v1/relay/keys returned non-success status");
        return Err(DIDCeremonyError::RelayKeyFetchFailed);
    }

    let relay_key: RelaySigningKey = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize relay signing key response");
        DIDCeremonyError::RelayKeyFetchFailed
    })?;

    // Step 3: Build signed genesis op — device key as rotation key, relay key as signing key.
    // On device, the private key never leaves the Secure Enclave; on Simulator and macOS, a software key is used instead.
    let rotation_key = DidKeyUri(device_key.key_id.clone());
    let signing_key = DidKeyUri(relay_key.key_id.clone());

    let genesis_op = build_did_plc_genesis_op_with_external_signer(
        &rotation_key,
        &signing_key,
        &handle,
        http::RelayClient::base_url(),
        |data| {
            device_key::sign(data)
                .map_err(|e| CryptoError::PlcOperation(format!("device signing failed: {e}")))
        },
    )
    .map_err(|e| {
        tracing::error!(error = %e, "genesis op signing failed during DID ceremony");
        DIDCeremonyError::SigningFailed
    })?;

    // Step 4: Retrieve the pending session token from Keychain.
    let token_bytes = keychain::get_item("session-token").map_err(|e| {
        tracing::warn!(error = %e, "failed to retrieve session-token from keychain");
        DIDCeremonyError::KeychainError
    })?;
    let pending_token = String::from_utf8(token_bytes).map_err(|e| {
        tracing::warn!(error = %e, "session-token bytes are not valid UTF-8");
        DIDCeremonyError::KeychainError
    })?;

    // Step 5: POST the signed genesis op to the relay to promote the account to a full DID.
    let create_did_req = CreateDidRequest {
        rotation_key_public: device_key.key_id,
        signed_creation_op: serde_json::from_str(&genesis_op.signed_op_json).map_err(|e| {
            tracing::error!(error = %e, "genesis op JSON is not valid JSON");
            DIDCeremonyError::SigningFailed
        })?,
    };

    let resp = RELAY_CLIENT
        .post_with_bearer("/v1/dids", &create_did_req, &pending_token)
        .await
        .map_err(|e| DIDCeremonyError::NetworkError {
            message: e.to_string(),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %body, "POST /v1/dids returned non-success status");
        return Err(DIDCeremonyError::DidCreationFailed);
    }

    let create_did_resp: CreateDidResponse = resp.json().await.map_err(|e| {
        tracing::error!(error = %e, "failed to deserialize POST /v1/dids response");
        DIDCeremonyError::DidCreationFailed
    })?;

    // Step 6: Overwrite session-token with the upgraded full session token.
    keychain::store_item("session-token", create_did_resp.session_token.as_bytes()).map_err(
        |e| {
            tracing::error!(error = %e, "failed to persist upgraded session-token to keychain");
            DIDCeremonyError::KeychainError
        },
    )?;

    // Step 7: Persist the DID for use in subsequent app sessions.
    keychain::store_item("did", create_did_resp.did.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, did = %create_did_resp.did, "failed to persist DID to keychain");
        DIDCeremonyError::KeychainError
    })?;

    Ok(DIDCeremonyResult {
        did: create_did_resp.did,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            create_account,
            get_or_create_device_key,
            sign_with_device_key,
            perform_did_ceremony,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CreateMobileAccountRequest serialization --
    #[test]
    fn create_mobile_account_request_serializes_camel_case() {
        let req = CreateMobileAccountRequest {
            email: "test@example.com".into(),
            handle: "alice".into(),
            device_public_key: "pubkey123".into(),
            platform: "ios".into(),
            claim_code: "ABC123".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["handle"], "alice");
        assert_eq!(json["devicePublicKey"], "pubkey123");
        assert_eq!(json["platform"], "ios");
        assert_eq!(json["claimCode"], "ABC123");
    }

    // -- CreateAccountResult serialization --
    #[test]
    fn create_account_result_serializes_camel_case() {
        let result = CreateAccountResult {
            next_step: NextStep::DidCreation,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["nextStep"], "did_creation");
    }

    // -- NextStep serde round-trip --
    #[test]
    fn next_step_did_creation_deserializes_correctly() {
        let result: NextStep = serde_json::from_str(r#""did_creation""#).unwrap();
        assert_eq!(result, NextStep::DidCreation);
    }

    #[test]
    fn next_step_did_creation_serializes_correctly() {
        let json = serde_json::to_value(NextStep::DidCreation).unwrap();
        assert_eq!(json, "did_creation");
    }

    #[test]
    fn next_step_unknown_value_fails_deserialization() {
        let result: Result<NextStep, _> = serde_json::from_str(r#""email_verification""#);
        assert!(result.is_err());
    }

    // -- CreateAccountError::ExpiredCode serialization --
    #[test]
    fn error_expired_code_serializes_correctly() {
        let err = CreateAccountError::ExpiredCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EXPIRED_CODE");
    }

    // -- CreateAccountError::RedeemedCode serialization --
    #[test]
    fn error_redeemed_code_serializes_correctly() {
        let err = CreateAccountError::RedeemedCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "REDEEMED_CODE");
    }

    // -- CreateAccountError::EmailTaken serialization --
    #[test]
    fn error_email_taken_serializes_correctly() {
        let err = CreateAccountError::EmailTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EMAIL_TAKEN");
    }

    // -- CreateAccountError::HandleTaken serialization --
    #[test]
    fn error_handle_taken_serializes_correctly() {
        let err = CreateAccountError::HandleTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");
    }

    // -- CreateAccountError::NetworkError serialization --
    #[test]
    fn error_network_error_serializes_correctly() {
        let err = CreateAccountError::NetworkError {
            message: "Connection timeout".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection timeout");
    }

    // -- CreateAccountError::KeychainError serialization --
    #[test]
    fn error_keychain_error_serializes_correctly() {
        let err = CreateAccountError::KeychainError;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    // -- CreateAccountError::Unknown serialization --
    #[test]
    fn error_unknown_serializes_correctly() {
        let err = CreateAccountError::Unknown {
            message: "Unexpected relay response".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert_eq!(json["message"], "Unexpected relay response");
    }

    // -- 409 subcode dispatch table --
    #[test]
    fn error_409_dispatch_maps_subcodes_correctly() {
        let json = serde_json::to_value(map_409_subcode("CLAIM_CODE_REDEEMED")).unwrap();
        assert_eq!(json["code"], "REDEEMED_CODE");

        let json = serde_json::to_value(map_409_subcode("ACCOUNT_EXISTS")).unwrap();
        assert_eq!(json["code"], "EMAIL_TAKEN");

        let json = serde_json::to_value(map_409_subcode("HANDLE_TAKEN")).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");

        let json = serde_json::to_value(map_409_subcode("UNKNOWN_SUBCODE")).unwrap();
        assert_eq!(json["code"], "UNKNOWN");
        assert!(json["message"].as_str().unwrap().contains("409:"));
    }

    // Tests the device_key contract that create_account depends on: the returned key
    // is correctly formatted (multibase base58btc) and is idempotent (stable across calls).
    #[test]
    fn device_key_contract_satisfies_relay_format() {
        let key = crate::device_key::get_or_create()
            .expect("device_key::get_or_create must succeed — create_account depends on it");
        // The relay expects multibase: 'z' + base58btc(33-byte compressed P-256 point).
        assert!(
            key.multibase.starts_with('z'),
            "device_public_key sent to relay must be multibase base58btc ('z' prefix), got: {}",
            key.multibase
        );
        // Calling again returns the same key — create_account sends consistent device_public_key.
        let key2 = crate::device_key::get_or_create().expect("second call must also succeed");
        assert_eq!(
            key.multibase, key2.multibase,
            "device_public_key must be stable across calls (idempotent)"
        );
    }

    // -- DIDCeremonyResult serialization --
    #[test]
    fn did_ceremony_result_serializes_did_in_camel_case() {
        let result = DIDCeremonyResult {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["did"], "did:plc:abcdefghijklmnopqrstuvwx");
    }

    // -- DIDCeremonyError serialization (one test per variant) --
    #[test]
    fn did_ceremony_error_key_not_found_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeyNotFound).unwrap();
        assert_eq!(json["code"], "KEY_NOT_FOUND");
    }

    #[test]
    fn did_ceremony_error_relay_key_fetch_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::RelayKeyFetchFailed).unwrap();
        assert_eq!(json["code"], "RELAY_KEY_FETCH_FAILED");
    }

    #[test]
    fn did_ceremony_error_no_relay_signing_key_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::NoRelaySigningKey).unwrap();
        assert_eq!(json["code"], "NO_RELAY_SIGNING_KEY");
    }

    #[test]
    fn did_ceremony_error_signing_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::SigningFailed).unwrap();
        assert_eq!(json["code"], "SIGNING_FAILED");
    }

    #[test]
    fn did_ceremony_error_did_creation_failed_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::DidCreationFailed).unwrap();
        assert_eq!(json["code"], "DID_CREATION_FAILED");
    }

    #[test]
    fn did_ceremony_error_keychain_error_serializes_correctly() {
        let json = serde_json::to_value(&DIDCeremonyError::KeychainError).unwrap();
        assert_eq!(json["code"], "KEYCHAIN_ERROR");
    }

    #[test]
    fn did_ceremony_error_network_error_serializes_with_message() {
        let err = DIDCeremonyError::NetworkError {
            message: "Connection refused".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection refused");
    }
}
