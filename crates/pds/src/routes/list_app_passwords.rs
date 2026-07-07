// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (full access required), DB pool
// Processes: scope gate → read the account's app passwords (public metadata only)
// Returns: JSON {passwords: [{name, createdAt, privileged}]}; ApiError on failure
//
// Implements: GET /xrpc/com.atproto.server.listAppPasswords

use axum::{extract::State, response::Json};
use serde::Serialize;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::app_passwords::list_app_passwords;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppPasswordItem {
    name: String,
    created_at: String,
    privileged: bool,
}

#[derive(Serialize)]
pub struct ListAppPasswordsResponse {
    passwords: Vec<AppPasswordItem>,
}

/// GET /xrpc/com.atproto.server.listAppPasswords
///
/// Lists the authenticated account's app passwords — names, creation times, and privilege
/// only. The secrets are never returned (only their hashes are stored). Requires a full
/// access-scope token.
pub async fn list_app_passwords_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<ListAppPasswordsResponse>, ApiError> {
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "full access token required",
        ));
    }
    // Agent-derived tokens map to AuthScope::Access but must never see app-password metadata.
    user.require_not_agent()?;

    let passwords = list_app_passwords(&state.db, &user.did)
        .await?
        .into_iter()
        .map(|p| AppPasswordItem {
            name: p.name,
            created_at: p.created_at,
            privileged: p.privileged,
        })
        .collect();

    Ok(Json(ListAppPasswordsResponse { passwords }))
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
        access_jwt, app_pass_jwt, body_json, insert_account_with_password, seed_app_password,
    };

    fn get_list(token: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("GET")
            .uri("/xrpc/com.atproto.server.listAppPasswords");
        if let Some(t) = token {
            b = b.header("Authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn lists_names_without_secrets() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:alice",
            "alice.test.example.com",
            "alice@example.com",
            "hunter2",
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "cli-one",
            "aaaa-bbbb-cccc-dddd",
            false,
        )
        .await;
        seed_app_password(
            &state.db,
            "did:plc:alice",
            "dm-bot",
            "eeee-ffff-gggg-hhhh",
            true,
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");

        let response = app(state).oneshot(get_list(Some(&token))).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let passwords = json["passwords"].as_array().expect("passwords array");
        assert_eq!(passwords.len(), 2);
        for p in passwords {
            assert!(p["name"].as_str().is_some());
            assert!(p["createdAt"].as_str().is_some());
            assert!(p.get("password").is_none(), "secret must never be listed");
            assert!(p.get("passwordHash").is_none());
        }
        let names: Vec<&str> = passwords
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"cli-one"));
        assert!(names.contains(&"dm-bot"));
    }

    #[tokio::test]
    async fn empty_when_no_app_passwords() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:none",
            "none.test.example.com",
            "none@example.com",
            "hunter2",
        )
        .await;
        let token = access_jwt(&state.jwt_secret, "did:plc:none");

        let response = app(state).oneshot(get_list(Some(&token))).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["passwords"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn app_pass_token_is_rejected() {
        let state = test_state().await;
        insert_account_with_password(
            &state.db,
            "did:plc:appp",
            "appp.test.example.com",
            "appp@example.com",
            "hunter2",
        )
        .await;
        let token = app_pass_jwt(&state.jwt_secret, "did:plc:appp", false);

        let response = app(state).oneshot(get_list(Some(&token))).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
