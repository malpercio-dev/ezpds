pub mod http;
pub mod keychain;

use crypto::generate_p256_keypair;
use serde::{Deserialize, Serialize};

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

    let resp = http::RelayClient::new()
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

#[tauri::command]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet, create_account])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greet_formats_name() {
        assert_eq!(greet("World".to_string()), "Hello, World!");
    }

    #[test]
    fn greet_empty_name() {
        assert_eq!(greet(String::new()), "Hello, !");
    }

    #[test]
    fn greet_special_characters() {
        assert_eq!(
            greet("<script>alert(1)</script>".to_string()),
            "Hello, <script>alert(1)</script>!"
        );
    }
}
