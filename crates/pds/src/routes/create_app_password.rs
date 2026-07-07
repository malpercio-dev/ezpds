// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (full access required), DB pool, JSON body {name, privileged?}
// Processes: scope gate → validate name → generate + argon2id-hash a secret → store keyed (did, name)
// Returns: JSON {name, password, createdAt, privileged} — the secret is surfaced once, never again
//
// Implements: POST /xrpc/com.atproto.server.createAppPassword

use axum::{extract::State, response::Json};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::auth::password::hash_password;
use crate::db::app_passwords::{insert_app_password, InsertOutcome};

/// Maximum accepted app-password name length (characters). A generous bound that rejects
/// obviously abusive input without constraining normal use.
const MAX_NAME_LEN: usize = 255;

/// Characters an app-password secret is drawn from — lowercase RFC 4648 base32 (unambiguous,
/// case-insensitive to type). The secret is surfaced once; its exact charset is not part of any
/// wire contract (createSession treats it as an opaque password).
const SECRET_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

#[derive(Deserialize)]
pub struct CreateAppPasswordRequest {
    name: String,
    #[serde(default)]
    privileged: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAppPasswordResponse {
    name: String,
    /// The generated secret, formatted `xxxx-xxxx-xxxx-xxxx`. Returned once at creation and
    /// never retrievable again (only its hash is stored).
    password: String,
    created_at: String,
    privileged: bool,
}

/// Generate an app-password secret: 16 random charset characters grouped as `xxxx-xxxx-xxxx-xxxx`
/// (the familiar atproto app-password shape).
fn generate_app_password() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let chars: Vec<char> = bytes
        .iter()
        .map(|&b| SECRET_CHARSET[(b as usize) % SECRET_CHARSET.len()] as char)
        .collect();
    let group = |range: std::ops::Range<usize>| chars[range].iter().collect::<String>();
    format!(
        "{}-{}-{}-{}",
        group(0..4),
        group(4..8),
        group(8..12),
        group(12..16)
    )
}

/// POST /xrpc/com.atproto.server.createAppPassword
///
/// Mints a named app password for the authenticated account and returns the generated secret
/// once. The secret can then be used as the `password` in `createSession` to open a
/// (limited-scope) app-password session. Requires a full access-scope token — an app password
/// cannot mint more app passwords.
pub async fn create_app_password(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    Json(payload): Json<CreateAppPasswordRequest>,
) -> Result<Json<CreateAppPasswordResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    // Agent-derived tokens map to AuthScope::Access but must never manage app passwords.
    user.require_not_agent()?;

    let name = payload.name;
    if name.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "app password name must not be empty",
        ));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "app password name is too long",
        ));
    }

    let password = generate_app_password();
    let password_hash = hash_password(&password)?;
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    match insert_app_password(
        &state.db,
        &user.did,
        &name,
        &password_hash,
        payload.privileged,
        &created_at,
    )
    .await?
    {
        InsertOutcome::Created => Ok(Json(CreateAppPasswordResponse {
            name,
            password,
            created_at,
            privileged: payload.privileged,
        })),
        InsertOutcome::DuplicateName => Err(ApiError::new(
            ErrorCode::Conflict,
            "an app password with this name already exists",
        )),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{
        access_jwt, app_pass_jwt, body_json, insert_account_with_password,
    };

    fn post_create(token: Option<&str>, json: serde_json::Value) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.server.createAppPassword")
            .header("Content-Type", "application/json");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::from(json.to_string())).unwrap()
    }

    #[tokio::test]
    async fn creates_and_returns_secret_once() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "hunter2",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state)
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "my-cli"}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["name"], "my-cli");
        assert_eq!(json["privileged"], false);
        let password = json["password"].as_str().expect("password surfaced");
        // Shape: xxxx-xxxx-xxxx-xxxx
        assert_eq!(password.len(), 19);
        assert_eq!(password.matches('-').count(), 3);
        assert!(json["createdAt"].as_str().is_some());
    }

    #[tokio::test]
    async fn privileged_flag_is_persisted_in_response() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:priv",
            "priv.test.example.com",
            "priv@example.com",
            "hunter2",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:priv");

        let response = app(state)
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "dm-bot", "privileged": true}),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["privileged"], true);
    }

    #[tokio::test]
    async fn duplicate_name_returns_409() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:dup",
            "dup.test.example.com",
            "dup@example.com",
            "hunter2",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:dup");

        let first = app(state.clone())
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "same"}),
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app(state)
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "same"}),
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn empty_name_returns_400() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:empty",
            "empty.test.example.com",
            "empty@example.com",
            "hunter2",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:empty");

        let response = app(state)
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "   "}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn app_pass_token_is_rejected() {
        // An app-password session must not be able to create more app passwords.
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:nest",
            "nest.test.example.com",
            "nest@example.com",
            "hunter2",
        )
        .await;
        let token = app_pass_jwt(&state.jwt_secret, "did:plc:nest", false);

        let response = app(state)
            .oneshot(post_create(
                Some(&token),
                serde_json::json!({"name": "nope"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_auth_returns_401() {
        let state = test_state().await;
        let response = app(state)
            .oneshot(post_create(None, serde_json::json!({"name": "x"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn generated_secret_has_expected_shape() {
        for _ in 0..20 {
            let p = super::generate_app_password();
            assert_eq!(p.len(), 19, "secret {p} must be 19 chars");
            let groups: Vec<&str> = p.split('-').collect();
            assert_eq!(groups.len(), 4);
            for g in groups {
                assert_eq!(g.len(), 4);
                assert!(g.bytes().all(|b| super::SECRET_CHARSET.contains(&b)));
            }
        }
    }
}
