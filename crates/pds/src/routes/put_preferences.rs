// pattern: Imperative Shell
//
// Gathers: AuthenticatedUser (JWT extractor), DB pool via AppState, raw JSON body
// Processes: scope validation → account-active check → parse + validate the preferences
//            array (each entry an object with an `app.bsky`-namespaced `$type`, none of them
//            full-access-only unless the caller has full access) → merge with any
//            full-access-only entries the caller can't manage → overwrite the account's
//            locally-stored blob
// Returns: 200 (empty body) on success; 400 for a malformed request; 401 for a bad token
//
// Implements: POST /xrpc/app.bsky.actor.putPreferences

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use common::{ApiError, ErrorCode};

use crate::app::AppState;
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::jwt::AuthScope;
use crate::db::accounts::account_is_active;
use crate::db::preferences::{get_preferences, put_preferences};
use crate::routes::preference_scope::is_full_access_only_pref;

#[derive(Deserialize)]
struct PutPreferencesRequest {
    preferences: Vec<Value>,
}

/// Whether a preference `$type` falls within the `app.bsky` lexicon namespace — either the
/// bare namespace or any NSID/union member beneath it (`app.bsky.actor.defs#adultContentPref`,
/// etc.). The reference PDS only stores preferences in this namespace and rejects the rest.
fn is_app_bsky_namespace(ty: &str) -> bool {
    ty == "app.bsky"
        || ty
            .strip_prefix("app.bsky.")
            .is_some_and(|suffix| !suffix.is_empty())
}

/// POST /xrpc/app.bsky.actor.putPreferences
///
/// The write companion to `getPreferences`. Preferences live on the PDS for user data
/// sovereignty rather than being proxied to the AppView, so this route is registered ahead
/// of the `app.bsky.*` catch-all. Like `getPreferences`, any access-level token is accepted
/// (full access or an app password), and a token whose account has since been deactivated or
/// removed is rejected even though the JWT is still cryptographically valid. The body must be
/// `{ "preferences": [ {…}, … ] }`; a malformed body — not an object, missing the field, a
/// non-object entry, or an entry whose `$type` is missing or outside the `app.bsky` namespace
/// — returns 400, as does an app-password caller submitting a full-access-only type (e.g.
/// `personalDetailsPref`).
///
/// The write is a *scope-limited partial replace*, not a blind overwrite: it deletes only the
/// preference types the caller's scope is allowed to manage and replaces those with the
/// request's array, leaving any full-access-only entries the caller can't touch untouched. A
/// full-access token can manage every type, so for it this is still a full overwrite; an
/// app-password caller instead layers its write on top of whatever full-access-only
/// preferences (e.g. `personalDetailsPref`) are already stored, rather than erasing them.
pub async fn put_preferences_handler(
    user: AuthenticatedUser,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if !user.scope.is_access() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }
    let has_access_full = user.scope == AuthScope::Access;

    // A valid JWT is not enough: reject tokens whose account has been deactivated or removed,
    // mirroring `getPreferences`. Without this an unexpired token would keep writing
    // preferences after the account is gone.
    if !account_is_active(&state.db, &user.did).await? {
        tracing::warn!(did = %user.did, "putPreferences: account not found or deactivated");
        return Err(ApiError::new(ErrorCode::InvalidToken, "account not found"));
    }

    // Parse the body ourselves rather than via the `Json` extractor so a malformed request
    // returns our 400 ApiError shape (the extractor's rejection is a 422 with a plain body).
    let request: PutPreferencesRequest = serde_json::from_slice(&body).map_err(|e| {
        tracing::debug!(did = %user.did, error = %e, "putPreferences: malformed request body");
        ApiError::new(ErrorCode::InvalidRequest, "invalid preferences format")
    })?;

    // Each preference is a typed union member in the `app.bsky` lexicon, so every entry must
    // be a JSON object carrying a string `$type` within the `app.bsky` namespace. The
    // reference PDS rejects anything else with InvalidRequest; matching it keeps a malformed
    // or out-of-namespace write from corrupting later reads (an empty array is valid and
    // clears the stored preferences). An app-password caller additionally cannot submit a
    // full-access-only type — it may not see those entries, so it must not be able to set
    // them either.
    for pref in &request.preferences {
        let ty = pref
            .as_object()
            .and_then(|obj| obj.get("$type"))
            .and_then(Value::as_str);
        match ty {
            Some(ty) if !is_app_bsky_namespace(ty) => {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "preference $type must be in the app.bsky namespace",
                ));
            }
            Some(ty) if !has_access_full && is_full_access_only_pref(ty) => {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!("do not have authorization to set preference type {ty}"),
                ));
            }
            Some(_) => {}
            None => {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "each preference must be an object with a string $type",
                ));
            }
        }
    }

    // Read-merge-write inside one transaction: the single-connection pool serializes any
    // concurrent request for this account behind the transaction, so the merge below can't
    // race a concurrent write from another session.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!(did = %user.did, error = %e, "putPreferences: failed to open transaction");
        ApiError::new(ErrorCode::InternalError, "failed to store preferences")
    })?;

    // Preserve whichever stored entries this caller's scope can't manage — an app-password
    // caller's write must not erase a full-access-only preference (e.g. `personalDetailsPref`)
    // that a full-access session stored earlier. A full-access caller can manage everything, so
    // nothing is preserved and this is a full overwrite, matching the previous behavior.
    let preserved: Vec<Value> = if has_access_full {
        Vec::new()
    } else {
        match get_preferences(&mut *tx, &user.did).await? {
            Some(blob) => serde_json::from_str::<Vec<Value>>(&blob)
                .map_err(|e| {
                    tracing::error!(did = %user.did, error = %e, "stored preferences blob is not valid JSON");
                    ApiError::new(ErrorCode::InternalError, "stored preferences are corrupt")
                })?
                .into_iter()
                .filter(|pref| {
                    let ty = pref.as_object().and_then(|obj| obj.get("$type")).and_then(Value::as_str);
                    ty.is_some_and(is_full_access_only_pref)
                })
                .collect(),
            None => Vec::new(),
        }
    };

    let mut merged = preserved;
    merged.extend(request.preferences);
    // `Value`'s Display impl is infallible, so serializing the array cannot fail here —
    // unlike the generic `serde_json::to_string`, which would force a dead error branch.
    let blob = Value::Array(merged).to_string();

    put_preferences(&mut *tx, &user.did, &blob).await?;

    tx.commit().await.map_err(|e| {
        tracing::error!(did = %user.did, error = %e, "putPreferences: failed to commit transaction");
        ApiError::new(ErrorCode::InternalError, "failed to store preferences")
    })?;

    Ok(StatusCode::OK)
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

    /// Issue a valid HS256 access JWT for a DID using the test state's fixed secret.
    fn access_jwt(secret: &[u8; 32], sub: &str) -> String {
        scoped_jwt(secret, sub, "com.atproto.access")
    }

    /// Issue a scoped HS256 JWT (used to exercise wrong-scope rejection paths).
    fn scoped_jwt(secret: &[u8; 32], sub: &str, scope: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({
                "scope": scope,
                "sub": sub,
                "iat": now,
                "exp": now + 7200_u64,
            }),
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn put_request(token: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/xrpc/app.bsky.actor.putPreferences")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/xrpc/app.bsky.actor.getPreferences")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn insert_account(db: &sqlx::SqlitePool, did: &str, email: &str) {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(email)
        .execute(db)
        .await
        .unwrap();
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:alice", "alice@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:alice");
        let prefs = serde_json::json!([
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true },
            { "$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": [] }
        ]);

        let router = app(state);
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": prefs }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The stored value must be retrievable verbatim via getPreferences.
        let response = router.oneshot(get_request(&token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["preferences"], prefs);
    }

    #[tokio::test]
    async fn put_overwrites_previous_preferences_entirely() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:bob", "bob@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:bob");
        let router = app(state);

        let first = serde_json::json!([
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true },
            { "$type": "app.bsky.actor.defs#savedFeedsPrefV2" }
        ]);
        let second =
            serde_json::json!([{ "$type": "app.bsky.actor.defs#hiddenPostsPref", "items": [] }]);

        for prefs in [&first, &second] {
            let response = router
                .clone()
                .oneshot(put_request(
                    &token,
                    serde_json::json!({ "preferences": prefs }),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(
            json["preferences"], second,
            "the second write must replace the first entirely, not merge"
        );
    }

    #[tokio::test]
    async fn empty_array_clears_preferences() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:clear", "clear@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:clear");
        let router = app(state);

        // Store something, then overwrite with an empty array.
        router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "app.bsky.actor.defs#adultContentPref" }] }),
            ))
            .await
            .unwrap();
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(json["preferences"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn missing_preferences_field_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:nofield", "nofield@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:nofield");

        let response = app(state)
            .oneshot(put_request(&token, serde_json::json!({ "wrong": [] })))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn non_object_preference_entry_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:scalar", "scalar@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:scalar");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "app.bsky.actor.defs#adultContentPref" }, "not-an-object"] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn preference_missing_type_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:notype", "notype@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:notype");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "enabled": true }] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn preference_non_string_type_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:numtype", "numtype@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:numtype");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": 42 }] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn preference_outside_app_bsky_namespace_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:wrongns", "wrongns@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:wrongns");

        // A well-formed object whose $type lives outside the app.bsky namespace must be
        // rejected — a foreign-namespace preference cannot be stored here.
        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "com.example.actor.pref" }] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn type_named_app_bsky_lookalike_is_rejected() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:lookalike", "lookalike@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:lookalike");

        // `app.bskything` shares the `app.bsky` prefix but is a different namespace; the
        // dot-boundary check must not treat it as in-namespace.
        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "app.bskything.pref" }] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn type_bare_app_bsky_prefix_is_rejected() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:bareprefix", "bareprefix@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:bareprefix");

        // `app.bsky.` has the namespace prefix but no member after the dot — neither the bare
        // namespace nor a real type, so it must not be persisted.
        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [{ "$type": "app.bsky." }] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn malformed_json_body_returns_400() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:malformed", "malformed@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:malformed");

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.actor.putPreferences")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .body(Body::from("not json {{{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn preferences_are_not_proxied_to_appview() {
        // putPreferences must be served locally. Point the AppView at an unroutable address:
        // if the request escaped to the proxy it would fail, so a clean 200 proves the local
        // handler matched ahead of the `app.bsky.*` catch-all.
        use std::sync::Arc;
        let base = test_state().await;
        let mut config = (*base.config).clone();
        config.appview.url = "http://127.0.0.1:1".to_string();
        let state = crate::app::AppState {
            config: Arc::new(config),
            ..base
        };
        insert_account(&state.db, "did:plc:carol", "carol@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:carol");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/app.bsky.actor.putPreferences")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "preferences": [] }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn app_pass_token_can_write_non_privileged_preferences() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:apppass", "apppass@example.com").await;
        let token = scoped_jwt(&state.jwt_secret, "did:plc:apppass", "com.atproto.appPass");
        let prefs = serde_json::json!([
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true }
        ]);

        let router = app(state);
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": prefs }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(json["preferences"], prefs);
    }

    #[tokio::test]
    async fn app_pass_token_cannot_set_personal_details_pref() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:setprivate", "setprivate@example.com").await;
        let token = scoped_jwt(
            &state.jwt_secret,
            "did:plc:setprivate",
            "com.atproto.appPass",
        );

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [
                    { "$type": "app.bsky.actor.defs#personalDetailsPref", "birthDate": "1990-01-01" }
                ] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "InvalidRequest");
    }

    #[tokio::test]
    async fn app_pass_write_preserves_existing_personal_details_pref() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:preserve", "preserve@example.com").await;
        let full_token = access_jwt(&state.jwt_secret, "did:plc:preserve");
        let app_pass_token =
            scoped_jwt(&state.jwt_secret, "did:plc:preserve", "com.atproto.appPass");
        let router = app(state);

        // A full-access session stores a personalDetailsPref.
        let personal = serde_json::json!(
            { "$type": "app.bsky.actor.defs#personalDetailsPref", "birthDate": "1990-01-01" }
        );
        let response = router
            .clone()
            .oneshot(put_request(
                &full_token,
                serde_json::json!({ "preferences": [personal] }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // An app-password session writes an unrelated preference.
        let adult_content = serde_json::json!(
            { "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true }
        );
        let response = router
            .clone()
            .oneshot(put_request(
                &app_pass_token,
                serde_json::json!({ "preferences": [adult_content] }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The full-access view must still see both: its own overwrite scope covers everything,
        // but the app-password write only replaced what it could manage.
        let response = router.oneshot(get_request(&full_token)).await.unwrap();
        let json = body_json(response).await;
        let prefs = json["preferences"].as_array().unwrap();
        assert_eq!(
            prefs.len(),
            2,
            "the app-password write must not erase personalDetailsPref"
        );
        assert!(prefs.contains(&personal));
        assert!(prefs.contains(&adult_content));
    }

    #[tokio::test]
    async fn full_access_write_still_overwrites_personal_details_pref() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:overwrite", "overwrite@example.com").await;
        let token = access_jwt(&state.jwt_secret, "did:plc:overwrite");
        let router = app(state);

        let first = serde_json::json!([
            { "$type": "app.bsky.actor.defs#personalDetailsPref", "birthDate": "1990-01-01" }
        ]);
        router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": first }),
            ))
            .await
            .unwrap();

        let second = serde_json::json!([{ "$type": "app.bsky.actor.defs#adultContentPref", "enabled": true }]);
        let response = router
            .clone()
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": second }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = router.oneshot(get_request(&token)).await.unwrap();
        let json = body_json(response).await;
        assert_eq!(
            json["preferences"], second,
            "a full-access write must still fully overwrite, including personalDetailsPref"
        );
    }

    #[tokio::test]
    async fn refresh_token_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:refresh", "refresh@example.com").await;
        let token = scoped_jwt(&state.jwt_secret, "did:plc:refresh", "com.atproto.refresh");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn deactivated_account_returns_401() {
        let state = test_state().await;
        insert_account(&state.db, "did:plc:deact", "deact@example.com").await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind("did:plc:deact")
            .execute(&state.db)
            .await
            .unwrap();
        let token = access_jwt(&state.jwt_secret, "did:plc:deact");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn token_for_nonexistent_account_returns_401() {
        let state = test_state().await;
        // No account inserted — the DID exists only inside the JWT.
        let token = access_jwt(&state.jwt_secret, "did:plc:ghost");

        let response = app(state)
            .oneshot(put_request(
                &token,
                serde_json::json!({ "preferences": [] }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "INVALID_TOKEN");
    }
}
