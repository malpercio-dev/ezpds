pub mod http;
pub mod keychain;

use crypto::generate_p256_keypair;
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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateMobileAccountResponse {
    device_token: String,
    session_token: String,
    next_step: String,
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

/// Successful result returned to the Svelte frontend.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResult {
    pub next_step: String,
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
    #[error("network error: {message}")]
    NetworkError { message: String },
    #[error("unknown error: {message}")]
    Unknown { message: String },
}

// ── Static relay client ─────────────────────────────────────────────────────

static RELAY_CLIENT: LazyLock<http::RelayClient> = LazyLock::new(http::RelayClient::new);

// ── IPC command ─────────────────────────────────────────────────────────────

#[tauri::command]
async fn create_account(
    claim_code: String,
    email: String,
    handle: String,
) -> Result<CreateAccountResult, CreateAccountError> {
    // 1. Generate P-256 device keypair.
    let keypair = generate_p256_keypair().map_err(|e| CreateAccountError::Unknown {
        message: e.to_string(),
    })?;

    // 2. Store private key bytes in Keychain before any network call.
    //    private_key_bytes is Zeroizing<[u8; 32]>; deref to &[u8] via AsRef.
    keychain::store_item("device-private-key", keypair.private_key_bytes.as_ref()).map_err(
        |e| CreateAccountError::Unknown {
            message: e.to_string(),
        },
    )?;

    // 3. POST to relay.
    let req = CreateMobileAccountRequest {
        email,
        handle,
        device_public_key: keypair.public_key,
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
        keychain::store_item("device-token", body.device_token.as_bytes()).map_err(|e| {
            CreateAccountError::Unknown {
                message: e.to_string(),
            }
        })?;
        keychain::store_item("session-token", body.session_token.as_bytes()).map_err(|e| {
            CreateAccountError::Unknown {
                message: e.to_string(),
            }
        })?;

        Ok(CreateAccountResult {
            next_step: body.next_step,
        })
    } else {
        // 6. Map relay error codes to typed variants.
        match status.as_u16() {
            404 => Err(CreateAccountError::ExpiredCode),
            409 => {
                let envelope: RelayErrorEnvelope =
                    resp.json().await.map_err(|e| CreateAccountError::Unknown {
                        message: e.to_string(),
                    })?;
                match envelope.error.code.as_str() {
                    "CLAIM_CODE_REDEEMED" => Err(CreateAccountError::RedeemedCode),
                    "ACCOUNT_EXISTS" => Err(CreateAccountError::EmailTaken),
                    "HANDLE_TAKEN" => Err(CreateAccountError::HandleTaken),
                    other => Err(CreateAccountError::Unknown {
                        message: format!("409: {other}"),
                    }),
                }
            }
            _ => Err(CreateAccountError::NetworkError {
                message: format!("HTTP {}", status.as_u16()),
            }),
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![create_account])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- AC2.2: CreateMobileAccountRequest serialization --
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

    // -- AC2.5: CreateAccountResult serialization --
    #[test]
    fn create_account_result_serializes_camel_case() {
        let result = CreateAccountResult {
            next_step: "did_creation".into(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["nextStep"], "did_creation");
    }

    // -- AC3.1: CreateAccountError::ExpiredCode serialization --
    #[test]
    fn error_expired_code_serializes_correctly() {
        let err = CreateAccountError::ExpiredCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EXPIRED_CODE");
    }

    // -- AC3.2: CreateAccountError::RedeemedCode serialization --
    #[test]
    fn error_redeemed_code_serializes_correctly() {
        let err = CreateAccountError::RedeemedCode;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "REDEEMED_CODE");
    }

    // -- AC3.3: CreateAccountError::EmailTaken serialization --
    #[test]
    fn error_email_taken_serializes_correctly() {
        let err = CreateAccountError::EmailTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "EMAIL_TAKEN");
    }

    // -- AC3.4: CreateAccountError::HandleTaken serialization --
    #[test]
    fn error_handle_taken_serializes_correctly() {
        let err = CreateAccountError::HandleTaken;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "HANDLE_TAKEN");
    }

    // -- AC3.5: CreateAccountError::NetworkError serialization --
    #[test]
    fn error_network_error_serializes_correctly() {
        let err = CreateAccountError::NetworkError {
            message: "Connection timeout".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "NETWORK_ERROR");
        assert_eq!(json["message"], "Connection timeout");
    }
}
