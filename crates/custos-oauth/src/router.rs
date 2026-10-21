// pattern: Imperative Shell

//! The OAuth route table. `pds` merges it into its public (CORS'd) group before the shared layer
//! stack. Always on: there is no switch for the authorization server.

use axum::{
    extract::FromRef,
    routing::{get, post},
    Router,
};
use custos_core::CoreState;

use crate::routes::*;

/// Every OAuth route: the two discovery documents, the authorization and consent endpoints, the
/// server's client metadata and JWKS, PAR, token, and revocation.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CoreState: FromRef<S>,
{
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_server_metadata),
        )
        .route(
            "/oauth/authorize",
            get(get_authorization).post(post_authorization),
        )
        .route("/oauth/authorize/consent-request", get(get_consent_request))
        .route("/oauth/authorize/status", get(get_authorization_status))
        .route("/oauth/authorize/approve", post(post_authorization_approve))
        .route(
            "/oauth/authorize/complete",
            post(post_authorization_complete),
        )
        .route("/oauth/client-metadata.json", get(oauth_client_metadata))
        .route("/oauth/jwks", get(oauth_jwks))
        .route("/oauth/par", post(post_par))
        .route("/oauth/token", post(post_token))
        .route("/oauth/revoke", post(post_revoke))
}
