// pattern: Imperative Shell
//
// GET /xrpc/com.atproto.identity.getRecommendedDidCredentials
//
// Returns the DID-document fields this PDS recommends a (new or migrating) account's
// PLC operation contain: the PDS-held rotation key, the account's atproto verification
// method, its handle(s), and this server's PDS service endpoint. A migrating wallet /
// client fetches these from the destination PDS and folds them into the operation it
// then signs — putting its own device key ahead of the recommended rotation key.
//
// Gather:  AuthenticatedUser (any access-level token) → DID
// Process: load the account's PDS-held signing key + handles
// Respond: { rotationKeys, alsoKnownAs, verificationMethods, services }

use axum::{extract::State, response::Json};
use serde::Serialize;
use std::collections::BTreeMap;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::db::dids::fetch_also_known_as;
use crate::db::repo_keys::get_signing_key_by_did;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedDidCredentials {
    rotation_keys: Vec<String>,
    also_known_as: Vec<String>,
    verification_methods: BTreeMap<String, String>,
    services: BTreeMap<String, RecommendedService>,
}

#[derive(Serialize)]
pub struct RecommendedService {
    #[serde(rename = "type")]
    service_type: String,
    endpoint: String,
}

pub async fn get_recommended_did_credentials(
    user: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<RecommendedDidCredentials>, ApiError> {
    let did = &user.did;

    // The account's PDS-held signing key is both its `#atproto` verification method and the
    // rotation key this PDS can sign operations with — so it is what we recommend for both.
    let signing_key = get_signing_key_by_did(&state.db, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, did = %did, "failed to load signing key");
            ApiError::new(ErrorCode::InternalError, "failed to load account keys")
        })?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::NotFound,
                "no signing key is registered for this account",
            )
        })?;

    let also_known_as = fetch_also_known_as(&state.db, did).await?;

    let mut verification_methods = BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_key.key_id.clone());

    let mut services = BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        RecommendedService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: state.config.public_url.clone(),
        },
    );

    Ok(Json(RecommendedDidCredentials {
        rotation_keys: vec![signing_key.key_id],
        also_known_as,
        verification_methods,
        services,
    }))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::app::{app, test_state};
    use crate::routes::test_utils::{access_jwt, seed_account_with_signing_key};

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn get_req(jwt: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/xrpc/com.atproto.identity.getRecommendedDidCredentials");
        if let Some(jwt) = jwt {
            builder = builder.header("Authorization", format!("Bearer {jwt}"));
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn returns_recommended_credentials() {
        let state = test_state().await;
        let did = "did:plc:reccreds1111111111111111";
        let key_id = seed_account_with_signing_key(&state.db, did, "alice.example.com").await;
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state).oneshot(get_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        assert_eq!(json["rotationKeys"][0], key_id);
        assert_eq!(json["verificationMethods"]["atproto"], key_id);
        assert_eq!(json["alsoKnownAs"][0], "at://alice.example.com");
        assert_eq!(
            json["services"]["atproto_pds"]["type"],
            "AtprotoPersonalDataServer"
        );
        assert!(json["services"]["atproto_pds"]["endpoint"]
            .as_str()
            .unwrap()
            .starts_with("https://"));
    }

    #[tokio::test]
    async fn requires_auth() {
        let state = test_state().await;
        let response = app(state).oneshot(get_req(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_signing_key_returns_404() {
        let state = test_state().await;
        let did = "did:plc:nosigningkey11111111111111";
        // Seed the account (and a session-authenticating JWT) but no signing_keys row.
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(&state.db)
        .await
        .unwrap();
        let jwt = access_jwt(&[0x42u8; 32], did);

        let response = app(state).oneshot(get_req(Some(&jwt))).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
