// pattern: Imperative Shell
//
// Gathers: public_url from AppState config
// Processes: canonical-vs-loopback client_id selection (pure)
// Returns: OAuth client metadata JSON per AT Protocol spec

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;

use crate::app::AppState;

/// The identity wallet's canonical OAuth client_id: this document's HTTPS URL on the
/// production host. The atproto OAuth spec requires a native client's private-use
/// redirect scheme to be the client_id host's FQDN in reverse order, so the wallet's
/// `org.obsign.identitywallet:` callback scheme pins the client_id host to
/// `identitywallet.obsign.org` (served by the production `*.obsign.org` wildcard).
/// The OAuth client is the wallet app — not whichever Custos instance the user
/// configured — so its identity must not vary with `public_url`: every instance
/// serves this same document, and third-party authorization servers fetch it from
/// the canonical host. Must stay in sync with the V042-seeded `oauth_clients` row
/// and the wallet's constants in `apps/identity-wallet/src-tauri/src/pds_client.rs`.
pub const CANONICAL_WALLET_CLIENT_ID: &str =
    "https://identitywallet.obsign.org/oauth/client-metadata.json";

/// The wallet's redirect URI — the private-use scheme is the canonical client_id
/// host reversed, the pairing third-party authorization servers enforce.
pub const WALLET_REDIRECT_URI: &str = "org.obsign.identitywallet:/oauth/callback";

/// The client-metadata document's path. Shared by the loopback-derived client_id and the
/// `client_uri` trim so the two can't drift (a stale trim would leave `client_uri`
/// ending in the metadata path — no longer same-origin with `client_id`).
const CLIENT_METADATA_PATH: &str = "/oauth/client-metadata.json";

#[derive(Serialize)]
struct ClientMetadata {
    client_id: String,
    client_name: &'static str,
    client_uri: String,
    application_type: &'static str,
    grant_types: Vec<&'static str>,
    response_types: Vec<&'static str>,
    redirect_uris: Vec<&'static str>,
    scope: &'static str,
    dpop_bound_access_tokens: bool,
    token_endpoint_auth_method: &'static str,
}

/// Select the client_id this instance serves: the canonical URL everywhere except a
/// loopback `public_url` (local development), where the document must self-reference
/// the URL it is actually fetched from or client resolution fails on the
/// client_id-mismatch check.
fn wallet_client_id(public_url: &str) -> String {
    let base = public_url.trim_end_matches('/');
    if crate::oauth_client_resolution::url_is_loopback(base) {
        format!("{base}{CLIENT_METADATA_PATH}")
    } else {
        CANONICAL_WALLET_CLIENT_ID.to_string()
    }
}

pub async fn oauth_client_metadata(State(state): State<AppState>) -> impl IntoResponse {
    let client_id = wallet_client_id(&state.config.public_url);
    // client_uri must stay same-origin with client_id.
    let client_uri = client_id.trim_end_matches(CLIENT_METADATA_PATH).to_string();

    Json(ClientMetadata {
        client_id,
        client_name: "Obsign Identity Wallet",
        client_uri,
        application_type: "native",
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        redirect_uris: vec![WALLET_REDIRECT_URI],
        scope: "atproto transition:generic",
        dpop_bound_access_tokens: true,
        token_endpoint_auth_method: "none",
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{wallet_client_id, CANONICAL_WALLET_CLIENT_ID, WALLET_REDIRECT_URI};
    use crate::app::{app, test_state};

    /// The V042 SQL seed and this route serve the same client_id/redirect literals but can't
    /// share a Rust const (a migration is raw SQL). Tie the in-crate pair here so a rename of
    /// the route consts that forgets the seed fails the build rather than silently shipping a
    /// server whose served document disagrees with its own seeded row.
    #[test]
    fn v042_seed_matches_canonical_consts() {
        let sql = include_str!("../db/migrations/V042__canonical_wallet_oauth_client.sql");
        assert!(
            sql.contains(CANONICAL_WALLET_CLIENT_ID),
            "V042 seed must reference the canonical client_id {CANONICAL_WALLET_CLIENT_ID}"
        );
        assert!(
            sql.contains(WALLET_REDIRECT_URI),
            "V042 seed must reference the wallet redirect URI {WALLET_REDIRECT_URI}"
        );
    }

    #[test]
    fn client_id_is_canonical_for_public_hosts() {
        assert_eq!(
            wallet_client_id("https://obsign.org"),
            CANONICAL_WALLET_CLIENT_ID
        );
        assert_eq!(
            wallet_client_id("https://ezpds-staging.up.railway.app/"),
            CANONICAL_WALLET_CLIENT_ID
        );
    }

    #[test]
    fn client_id_derives_from_loopback_public_url() {
        assert_eq!(
            wallet_client_id("http://localhost:8080"),
            "http://localhost:8080/oauth/client-metadata.json"
        );
        assert_eq!(
            wallet_client_id("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/oauth/client-metadata.json"
        );
    }

    #[test]
    fn redirect_scheme_is_reverse_fqdn_of_canonical_host() {
        let host = url::Url::parse(CANONICAL_WALLET_CLIENT_ID)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        let reversed = host.split('.').rev().collect::<Vec<_>>().join(".");
        let scheme = WALLET_REDIRECT_URI.split(':').next().unwrap().to_string();
        assert_eq!(
            scheme, reversed,
            "the private-use redirect scheme must be the canonical client_id host in reverse order"
        );
    }

    #[tokio::test]
    async fn client_metadata_returns_200_with_canonical_client_id() {
        // test_state's public_url is a non-loopback host, so the canonical branch applies.
        let state = test_state().await;
        let response = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The client_id is the wallet's fixed canonical URL — it must NOT derive from
        // this instance's public_url (the OAuth client is the wallet, not the server).
        assert_eq!(json["client_id"], CANONICAL_WALLET_CLIENT_ID);
        assert_eq!(json["client_uri"], "https://identitywallet.obsign.org");
        assert_eq!(json["application_type"], "native");
        assert_eq!(json["dpop_bound_access_tokens"], true);
        assert_eq!(json["token_endpoint_auth_method"], "none");
    }

    #[tokio::test]
    async fn client_metadata_has_json_content_type() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn client_metadata_redirect_uri_matches_wallet() {
        let response = app(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/oauth/client-metadata.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let uris = json["redirect_uris"].as_array().unwrap();
        assert!(uris.iter().any(|u| u == WALLET_REDIRECT_URI));
    }
}
