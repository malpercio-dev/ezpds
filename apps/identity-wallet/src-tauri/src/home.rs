// pattern: Imperative Shell
//
// Gathers: AppState (oauth_session), RelayClient, OAuthClient
// Processes: concurrent _health + getSession + Keychain check
// Returns: HomeData (always Ok — partial failures encoded as fields)

use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::oauth::{AppState, OAuthError};

// ── Wire types: ATProto getSession response ────────────────────────────────

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetSessionResponse {
    did: String,
    handle: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    email_confirmed: bool,
    did_doc: Option<Value>,
}

// ── Output types: sent to frontend via Tauri IPC ──────────────────────────

/// Session info from com.atproto.server.getSession, forwarded to the frontend.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
    pub email: String,
    pub email_confirmed: bool,
    pub did_doc: Option<Value>,
}

/// Home screen data payload. Always returned as Ok — partial failures
/// (relay unreachable, session expired) are encoded as fields so the UI
/// can render whatever is available.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HomeData {
    pub relay_healthy: bool,
    /// null when getSession failed or no session exists in AppState
    pub session: Option<SessionInfo>,
    /// SCREAMING_SNAKE_CASE error code when session is null
    pub session_error: Option<String>,
    pub share1_in_keychain: bool,
}

// ── Commands ──────────────────────────────────────────────────────────────

/// Load home screen data: relay health, session info, and Keychain share status.
///
/// Fires GET /xrpc/_health and GET /xrpc/com.atproto.server.getSession
/// concurrently via tokio::join!. Always succeeds — partial failures are
/// encoded in HomeData fields rather than returned as Err.
#[tauri::command]
pub async fn load_home_data(state: tauri::State<'_, AppState>) -> Result<HomeData, String> {
    let share1_in_keychain = crate::keychain::get_item("recovery-share-1").is_ok();

    // Clone session out of AppState (drops the lock immediately).
    let session_opt = {
        let guard = state.oauth_session.lock().unwrap();
        guard.clone()
    };

    let Some(session) = session_opt else {
        let relay_healthy = check_relay_health().await;
        return Ok(HomeData {
            relay_healthy,
            session: None,
            session_error: Some("NOT_AUTHENTICATED".to_string()),
            share1_in_keychain,
        });
    };

    let session_arc = Arc::new(Mutex::new(session));

    let oauth_client = match crate::oauth_client::OAuthClient::new(session_arc.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "OAuthClient construction failed");
            return Ok(HomeData {
                relay_healthy: check_relay_health().await,
                session: None,
                session_error: Some(oauth_error_code(&e)),
                share1_in_keychain,
            });
        }
    };

    let (relay_healthy, session_result) = tokio::join!(
        check_relay_health(),
        oauth_client.get("/xrpc/com.atproto.server.getSession"),
    );

    let (session_info, session_error) = match session_result {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<GetSessionResponse>().await {
                Ok(gs) => {
                    // Write back potentially-refreshed tokens to AppState.
                    let refreshed = session_arc.lock().unwrap().clone();
                    *state.oauth_session.lock().unwrap() = Some(refreshed);
                    (
                        Some(SessionInfo {
                            did: gs.did,
                            handle: gs.handle,
                            email: gs.email,
                            email_confirmed: gs.email_confirmed,
                            did_doc: gs.did_doc,
                        }),
                        None,
                    )
                }
                Err(e) => {
                    tracing::error!(error = %e, "getSession deserialization failed");
                    (None, Some("SESSION_PARSE_ERROR".to_string()))
                }
            }
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "getSession returned non-success");
            (None, Some("NOT_AUTHENTICATED".to_string()))
        }
        Err(e) => {
            tracing::error!(error = %e, "getSession request failed");
            (None, Some(oauth_error_code(&e)))
        }
    };

    Ok(HomeData {
        relay_healthy,
        session: session_info,
        session_error,
        share1_in_keychain,
    })
}

/// Clear OAuth tokens and DID from Keychain and wipe the in-memory session.
///
/// Always succeeds — Keychain delete errors are swallowed so the frontend
/// unconditionally navigates to the welcome screen.
#[tauri::command]
pub async fn log_out(state: tauri::State<'_, AppState>) -> Result<(), String> {
    for key in &["oauth-access-token", "oauth-refresh-token", "did"] {
        if let Err(e) = crate::keychain::delete_item(key) {
            if !crate::keychain::is_not_found(&e) {
                tracing::warn!(error = %e, key = key, "Keychain delete failed during logout");
            }
        }
    }
    *state.oauth_session.lock().unwrap() = None;
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────

/// Creates a new RelayClient on each call. Acceptable because load_home_data
/// is invoked at most once per user-initiated home screen refresh; the cost is
/// not significant at this call frequency.
async fn check_relay_health() -> bool {
    crate::http::RelayClient::new()
        .get("/xrpc/_health")
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn oauth_error_code(e: &OAuthError) -> String {
    serde_json::to_value(e)
        .ok()
        .and_then(|v| v["code"].as_str().map(String::from))
        .unwrap_or_else(|| {
            tracing::warn!("OAuthError could not be serialized to a code string");
            "UNKNOWN".to_string()
        })
}

// ── Test helper: injectable base URLs ─────────────────────────────────────

#[cfg(test)]
async fn load_home_data_with_urls(
    relay_base: &str,
    oauth_base: &str,
    session: Option<crate::oauth::OAuthSession>,
    app_state: &AppState,
) -> HomeData {
    let share1_in_keychain = crate::keychain::get_item("recovery-share-1").is_ok();

    let Some(s) = session else {
        let relay_healthy = reqwest::Client::new()
            .get(format!("{}/xrpc/_health", relay_base))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        return HomeData {
            relay_healthy,
            session: None,
            session_error: Some("NOT_AUTHENTICATED".to_string()),
            share1_in_keychain,
        };
    };

    let session_arc = Arc::new(Mutex::new(s));

    let dpop = crate::oauth::DPoPKeypair::get_or_create().expect("keypair must exist");
    let oauth_client = crate::oauth_client::OAuthClient::new_for_test(
        dpop,
        session_arc.clone(),
        oauth_base.to_string(),
    );

    let relay_client = reqwest::Client::new();
    let (health_result, session_result) = tokio::join!(
        relay_client
            .get(format!("{}/xrpc/_health", relay_base))
            .send(),
        oauth_client.get("/xrpc/com.atproto.server.getSession"),
    );

    let relay_healthy = health_result
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let (session_info, session_error) = match session_result {
        Ok(resp) if resp.status().is_success() => match resp.json::<GetSessionResponse>().await {
            Ok(gs) => {
                let refreshed = session_arc.lock().unwrap().clone();
                *app_state.oauth_session.lock().unwrap() = Some(refreshed);
                (
                    Some(SessionInfo {
                        did: gs.did,
                        handle: gs.handle,
                        email: gs.email,
                        email_confirmed: gs.email_confirmed,
                        did_doc: gs.did_doc,
                    }),
                    None,
                )
            }
            Err(_) => (None, Some("SESSION_PARSE_ERROR".to_string())),
        },
        Ok(resp) => {
            let _status = resp.status().as_u16();
            (None, Some("NOT_AUTHENTICATED".to_string()))
        }
        Err(e) => (None, Some(oauth_error_code(&e))),
    };

    HomeData {
        relay_healthy,
        session: session_info,
        session_error,
        share1_in_keychain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{AppState, OAuthSession};
    use httpmock::prelude::*;

    fn make_session(access: &str) -> OAuthSession {
        OAuthSession {
            access_token: access.to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: u64::MAX, // never expires
            dpop_nonce: None,
        }
    }

    // ── Serialization ──────────────────────────────────────────────────────

    #[test]
    fn home_data_serializes_camel_case() {
        let data = HomeData {
            relay_healthy: true,
            session: Some(SessionInfo {
                did: "did:plc:abc".into(),
                handle: "alice.test".into(),
                email: "alice@example.com".into(),
                email_confirmed: true,
                did_doc: None,
            }),
            session_error: None,
            share1_in_keychain: true,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["relayHealthy"], true);
        assert_eq!(json["session"]["did"], "did:plc:abc");
        assert_eq!(json["session"]["handle"], "alice.test");
        assert_eq!(json["session"]["emailConfirmed"], true);
        assert_eq!(json["sessionError"], serde_json::Value::Null);
        assert_eq!(json["share1InKeychain"], true);
    }

    #[test]
    fn home_data_session_null_serializes_error_code() {
        let data = HomeData {
            relay_healthy: false,
            session: None,
            session_error: Some("NOT_AUTHENTICATED".to_string()),
            share1_in_keychain: false,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["session"], serde_json::Value::Null);
        assert_eq!(json["sessionError"], "NOT_AUTHENTICATED");
        assert_eq!(json["relayHealthy"], false);
    }

    // ── log_out Keychain behavior ──────────────────────────────────────────

    /// Store the three OAuth items that log_out must delete.
    fn store_oauth_keychain_items() {
        crate::keychain::store_item("oauth-access-token", b"access").unwrap();
        crate::keychain::store_item("oauth-refresh-token", b"refresh").unwrap();
        crate::keychain::store_item("did", b"did:plc:abc").unwrap();
    }

    /// Execute the same Keychain + AppState wipe that log_out performs.
    /// Used in tests because Tauri commands can't be called without an app handle.
    fn simulate_log_out(state: &AppState) {
        let _ = crate::keychain::delete_item("oauth-access-token");
        let _ = crate::keychain::delete_item("oauth-refresh-token");
        let _ = crate::keychain::delete_item("did");
        *state.oauth_session.lock().unwrap() = None;
    }

    #[tokio::test]
    async fn log_out_deletes_oauth_and_did_from_keychain() {
        store_oauth_keychain_items();
        let state = AppState::new();
        *state.oauth_session.lock().unwrap() = Some(make_session("access"));
        simulate_log_out(&state);
        assert!(crate::keychain::get_item("oauth-access-token").is_err());
        assert!(crate::keychain::get_item("oauth-refresh-token").is_err());
        assert!(crate::keychain::get_item("did").is_err());
        assert!(state.oauth_session.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn log_out_succeeds_when_keychain_items_absent() {
        // Items may not exist — log_out must not panic.
        let state = AppState::new();
        simulate_log_out(&state);
    }

    #[tokio::test]
    async fn log_out_preserves_device_and_dpop_keys() {
        // Store OAuth items AND keys that must survive logout.
        store_oauth_keychain_items();
        crate::keychain::store_item("oauth-dpop-key-priv", b"dpop-key-bytes").unwrap();
        crate::keychain::store_item("device-rotation-key-priv", b"device-key-bytes").unwrap();

        let state = AppState::new();
        simulate_log_out(&state);

        // OAuth items gone.
        assert!(crate::keychain::get_item("oauth-access-token").is_err());
        // Device and DPoP keys must NOT have been deleted.
        assert!(
            crate::keychain::get_item("oauth-dpop-key-priv").is_ok(),
            "DPoP key must remain after logout"
        );
        assert!(
            crate::keychain::get_item("device-rotation-key-priv").is_ok(),
            "device key must remain after logout"
        );

        // Cleanup so other tests are not affected.
        let _ = crate::keychain::delete_item("oauth-dpop-key-priv");
        let _ = crate::keychain::delete_item("device-rotation-key-priv");
    }

    // ── load_home_data: unauthenticated path ───────────────────────────────

    #[tokio::test]
    async fn load_home_data_no_session_returns_not_authenticated() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/_health");
            then.status(200).body(r#"{"version":"0.1.0"}"#);
        });

        let state = AppState::new(); // no oauth_session
        let data =
            load_home_data_with_urls(&server.base_url(), &server.base_url(), None, &state).await;

        assert!(data.relay_healthy);
        assert!(data.session.is_none());
        assert_eq!(data.session_error.as_deref(), Some("NOT_AUTHENTICATED"));
    }

    // ── load_home_data: relay health ──────────────────────────────────────

    #[tokio::test]
    async fn load_home_data_relay_healthy_true_when_health_returns_200() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/_health");
            then.status(200).body(r#"{"version":"0.1.0"}"#);
        });
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/com.atproto.server.getSession");
            then.status(200).json_body(serde_json::json!({
                "did": "did:plc:abc",
                "handle": "alice.test",
                "email": "alice@example.com",
                "emailConfirmed": true,
                "didDoc": null
            }));
        });

        let state = AppState::new();
        let data = load_home_data_with_urls(
            &server.base_url(),
            &server.base_url(),
            Some(make_session("access")),
            &state,
        )
        .await;

        assert!(
            data.relay_healthy,
            "relay_healthy must be true when _health returns 200"
        );
    }

    #[tokio::test]
    async fn load_home_data_relay_healthy_false_when_health_fails() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/_health");
            then.status(503);
        });
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/com.atproto.server.getSession");
            then.status(200).json_body(serde_json::json!({
                "did": "did:plc:abc",
                "handle": "alice.test",
                "email": "",
                "emailConfirmed": false,
                "didDoc": null
            }));
        });

        let state = AppState::new();
        let data = load_home_data_with_urls(
            &server.base_url(),
            &server.base_url(),
            Some(make_session("access")),
            &state,
        )
        .await;

        assert!(
            !data.relay_healthy,
            "relay_healthy must be false when _health returns 503"
        );
        // Session can still be populated when relay fails; statuses are independent.
        assert!(
            data.session.is_some(),
            "session should still be populated when relay fails"
        );
    }

    // ── load_home_data: session ────────────────────────────────────────────

    #[tokio::test]
    async fn load_home_data_session_populated_when_get_session_succeeds() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/_health");
            then.status(200).body(r#"{"version":"0.1.0"}"#);
        });
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/com.atproto.server.getSession");
            then.status(200).json_body(serde_json::json!({
                "did": "did:plc:xyz123",
                "handle": "bob.test",
                "email": "bob@example.com",
                "emailConfirmed": false,
                "didDoc": null
            }));
        });

        let state = AppState::new();
        let data = load_home_data_with_urls(
            &server.base_url(),
            &server.base_url(),
            Some(make_session("access")),
            &state,
        )
        .await;

        let session = data.session.expect("session must be populated");
        assert_eq!(session.did, "did:plc:xyz123");
        assert_eq!(session.handle, "bob.test");
        assert_eq!(session.email, "bob@example.com");
        assert_eq!(session.email_confirmed, false);
        assert!(data.session_error.is_none());
    }

    #[tokio::test]
    async fn load_home_data_session_null_when_get_session_fails() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/_health");
            then.status(200).body(r#"{"version":"0.1.0"}"#);
        });
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/com.atproto.server.getSession");
            then.status(401);
        });

        let state = AppState::new();
        let data = load_home_data_with_urls(
            &server.base_url(),
            &server.base_url(),
            Some(make_session("access")),
            &state,
        )
        .await;

        assert!(data.session.is_none());
        assert!(
            data.session_error.is_some(),
            "sessionError must be set when getSession fails"
        );
        // relay is still healthy; statuses are independent
        assert!(data.relay_healthy);
    }
}
