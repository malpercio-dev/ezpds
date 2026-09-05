// pattern: Imperative Shell
//
// The generic HTTP contracts — the answers a route owes because of the *kind* of route it is,
// not because of what it does: a missing Authorization header is 401, a body sent to a no-input
// procedure is 400, a malformed DID in a query string is 400, a closed pool is 500.
//
// Each contract is asserted once here, over a table of every route it binds. Routes may not
// import one another, so before this module each route's own test file carried its own copy of
// the same five-line body and the copies drifted: some pinned the error name, some did not, and
// a route added later simply had no copy at all. A row in a table here cannot be forgotten.
//
// A route keeps a test of its own only where it answers *more* than the contract — a side effect
// that must not happen, a richer set of rejected inputs, or a request shape no table can build
// (a computed CID, a signed envelope). Those tests say so where they sit.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::app::{app, test_state, AppState};
use crate::routes::test_utils::{
    access_jwt, app_pass_jwt, body_json, scoped_access_jwt, seed_account_with_signing_key,
    state_with_failing_email, test_state_with_admin_token,
};

/// The admin token [`test_state_with_admin_token`] configures.
const ADMIN_TOKEN: &str = "test-admin-token";

/// A DID with the 24-character `did:plc` suffix the identifier validators require. Every row runs
/// against its own freshly built state, so one literal serves all of them.
const DID: &str = "did:plc:contracttest000000000000";

/// The error name from either response envelope: XRPC's `{"error": "Name"}` or the `/v1` API's
/// `{"error": {"code": "NAME"}}`.
fn error_name(body: &serde_json::Value) -> Option<&str> {
    body["error"]
        .as_str()
        .or_else(|| body["error"]["code"].as_str())
}

// ── Routes that require a caller identity ─────────────────────────────────────

/// What a route accepts as proof of who is calling.
#[derive(Clone, Copy, PartialEq)]
enum Guard {
    /// A session access token (`com.atproto.access`); a refresh-scoped token is refused.
    Access,
    /// The refresh token itself — `refreshSession` and `deleteSession`, which exist to spend one.
    Refresh,
    /// The operator admin token from `EZPDS_ADMIN_TOKEN`.
    Admin,
}

struct AuthedRoute {
    method: &'static str,
    path: &'static str,
    /// `(content-type, payload)`, or `None` for an empty body. Most rows need none: a route whose
    /// handler takes `AuthenticatedUser` authenticates in a `FromRequestParts` extractor, which
    /// runs before the body is ever read. A row carries one where the route would answer something
    /// other than 401 without it — a `Json<T>` extractor rejecting an absent body, or an admin
    /// route answering 415 to a missing content type.
    body: Option<(&'static str, &'static str)>,
    guard: Guard,
    /// The error name the route pins when the header is absent, where it pins one.
    missing_auth_error: Option<&'static str>,
    /// The error name a `Guard::Access` route pins when handed a refresh-scoped token, where it
    /// pins one. The 401 itself is asserted for every such row; only the name is optional,
    /// because the two response envelopes name the same refusal differently.
    refresh_scope_error: Option<&'static str>,
}

const JSON: &str = "application/json";

/// The shape a row falls back to: an authenticated POST with no body, pinning no error name.
/// Every row states only where it differs, so what is distinctive about a route is what shows.
const AUTHED: AuthedRoute = AuthedRoute {
    method: "POST",
    path: "",
    body: None,
    guard: Guard::Access,
    missing_auth_error: None,
    refresh_scope_error: None,
};

/// Every route that refuses an anonymous caller, ordered by path.
const AUTHED_ROUTES: &[AuthedRoute] = &[
    AuthedRoute {
        method: "GET",
        path: "/xrpc/app.bsky.actor.getPreferences",
        refresh_scope_error: Some("InvalidToken"),
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/app.bsky.actor.putPreferences",
        refresh_scope_error: Some("InvalidToken"),
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.identity.submitPlcOperation",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.identity.updateHandle",
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/xrpc/com.atproto.repo.listMissingBlobs",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.repo.uploadBlob",
        body: Some(("application/octet-stream", "hello")),
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.activateAccount",
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/xrpc/com.atproto.server.checkAccountStatus",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.confirmEmail",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.createAppPassword",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.deactivateAccount",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.deleteSession",
        guard: Guard::Refresh,
        missing_auth_error: Some("AuthMissing"),
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/xrpc/com.atproto.server.getSession",
        refresh_scope_error: Some("InvalidToken"),
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.refreshSession",
        guard: Guard::Refresh,
        missing_auth_error: Some("AuthMissing"),
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.requestAccountDelete",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.requestEmailConfirmation",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.requestEmailUpdate",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.revokeAppPassword",
        ..AUTHED
    },
    AuthedRoute {
        path: "/xrpc/com.atproto.server.updateEmail",
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/did-web/hosting",
        body: Some((JSON, r#"{"enabled":true}"#)),
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/dids",
        body: Some((
            JSON,
            r#"{"rotationKeyPublic":"did:key:z123","signedCreationOp":{},"password":"pw"}"#,
        )),
        missing_auth_error: Some("UNAUTHORIZED"),
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/handles",
        body: Some((
            JSON,
            r#"{"accountId":"did:plc:contracttest000000000000","handle":"alice.example.com"}"#,
        )),
        ..AUTHED
    },
    AuthedRoute {
        method: "DELETE",
        path: "/v1/handles/alice.example.com",
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/accounts",
        body: Some((
            JSON,
            r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
        )),
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/accounts/claim-codes",
        body: Some((JSON, r#"{"count":1}"#)),
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/v1/accounts/did:plc:whoever/storage",
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/v1/accounts/did:plc:whoever/usage",
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/v1/admin/accounts",
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        method: "GET",
        path: "/v1/admin/audit",
        guard: Guard::Admin,
        ..AUTHED
    },
    AuthedRoute {
        path: "/v1/pds/keys",
        body: Some((JSON, r#"{"algorithm":"p256"}"#)),
        guard: Guard::Admin,
        ..AUTHED
    },
];

impl AuthedRoute {
    /// A request to this route carrying `authorization` verbatim (`None` omits the header).
    fn request(&self, authorization: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(self.path);
        if let Some(value) = authorization {
            builder = builder.header("Authorization", value);
        }
        match self.body {
            Some((content_type, payload)) => builder
                .header("Content-Type", content_type)
                .body(Body::from(payload))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    fn label(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

async fn state_for(route: &AuthedRoute) -> AppState {
    if route.guard == Guard::Admin {
        test_state_with_admin_token().await
    } else {
        test_state().await
    }
}

/// No Authorization header at all: every guarded route answers 401, whatever it guards with.
#[tokio::test]
async fn missing_authorization_header_returns_401() {
    for route in AUTHED_ROUTES {
        let response = app(state_for(route).await)
            .oneshot(route.request(None))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.label()
        );
        if let Some(expected) = route.missing_auth_error {
            let json = body_json(response).await;
            assert_eq!(error_name(&json), Some(expected), "{}", route.label());
        }
    }
}

/// A refresh-scoped token on a route that wants an access token is refused — the scope is checked,
/// not merely the signature.
#[tokio::test]
async fn refresh_scoped_token_returns_401() {
    for route in AUTHED_ROUTES.iter().filter(|r| r.guard == Guard::Access) {
        let state = test_state().await;
        seed_account_with_signing_key(&state.db, DID, "alice.example.com").await;
        let token = scoped_access_jwt(&state.jwt_secret, DID, "com.atproto.refresh");

        let response = app(state)
            .oneshot(route.request(Some(&format!("Bearer {token}"))))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.label()
        );
        if let Some(expected) = route.refresh_scope_error {
            let json = body_json(response).await;
            assert_eq!(error_name(&json), Some(expected), "{}", route.label());
        }
    }
}

/// A bearer token that is not the configured admin token is refused.
#[tokio::test]
async fn wrong_admin_bearer_token_returns_401() {
    for route in AUTHED_ROUTES.iter().filter(|r| r.guard == Guard::Admin) {
        let response = app(test_state_with_admin_token().await)
            .oneshot(route.request(Some("Bearer wrong-token")))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.label()
        );
    }
}

/// The right token without the `Bearer ` prefix is still refused — the scheme is part of the
/// credential, so a client that sends a bare token must fail loudly rather than be accommodated.
#[tokio::test]
async fn bare_admin_token_without_bearer_prefix_returns_401() {
    for route in AUTHED_ROUTES.iter().filter(|r| r.guard == Guard::Admin) {
        let response = app(test_state_with_admin_token().await)
            .oneshot(route.request(Some(ADMIN_TOKEN)))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.label()
        );
    }
}

/// An operator who never set `EZPDS_ADMIN_TOKEN` has closed the admin surface, not opened it:
/// no token a caller can present unlocks it.
#[tokio::test]
async fn admin_token_not_configured_returns_401() {
    for route in AUTHED_ROUTES.iter().filter(|r| r.guard == Guard::Admin) {
        // `test_state()` leaves `admin_token` as `None`.
        let response = app(test_state().await)
            .oneshot(route.request(Some(&format!("Bearer {ADMIN_TOKEN}"))))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.label()
        );
    }
}

// ── Procedures whose lexicon defines no input ─────────────────────────────────

/// A procedure guarded by `crate::no_input::NoInputBody`.
struct NoInputRoute {
    path: &'static str,
    /// The table this route mints a single-use token into, for the routes that mail one. A
    /// rejected request must leave it empty, and the same routes share the mail-failure and
    /// app-password contracts below.
    token_table: Option<&'static str>,
    /// The route only mails (and so only mints) once the address is confirmed.
    needs_confirmed_email: bool,
}

const NO_INPUT_ROUTES: &[NoInputRoute] = &[
    NoInputRoute {
        path: "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        token_table: Some("plc_operation_tokens"),
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.activateAccount",
        token_table: None,
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.deleteSession",
        token_table: None,
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.refreshSession",
        token_table: None,
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.requestAccountDelete",
        token_table: Some("account_deletion_tokens"),
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.requestEmailConfirmation",
        token_table: Some("email_tokens"),
        needs_confirmed_email: false,
    },
    NoInputRoute {
        path: "/xrpc/com.atproto.server.requestEmailUpdate",
        token_table: Some("email_tokens"),
        needs_confirmed_email: true,
    },
];

/// Seed the account these procedures authenticate as, confirming its address where the route
/// needs that to reach its mail step.
async fn seed_caller(state: &AppState, route: &NoInputRoute) {
    seed_account_with_signing_key(&state.db, DID, "alice.example.com").await;
    if route.needs_confirmed_email {
        sqlx::query("UPDATE accounts SET email_confirmed_at = datetime('now') WHERE did = ?")
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
    }
}

fn post(path: &str, token: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("Authorization", format!("Bearer {token}"))
        .body(body)
        .unwrap()
}

/// The lexicon defines no input, so a spurious body is a 400 (reference-PDS parity) — the empty
/// `{}` the wallet used to send. A rejected request must also mint nothing.
#[tokio::test]
async fn non_empty_body_returns_400() {
    for route in NO_INPUT_ROUTES {
        let state = test_state().await;
        seed_caller(&state, route).await;
        let token = access_jwt(&state.jwt_secret, DID);
        let db = state.db.clone();

        let mut request = post(route.path, &token, Body::from("{}"));
        request
            .headers_mut()
            .insert("Content-Type", JSON.parse().unwrap());
        let response = app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{}", route.path);

        if let Some(table) = route.token_table {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(count, 0, "{} must not mint a token", route.path);
        }
    }
}

/// A mail server that will not take the message is a 503, not a silent success: the caller is
/// waiting for a link that is never going to arrive.
#[tokio::test]
async fn email_delivery_failure_returns_503() {
    for route in NO_INPUT_ROUTES.iter().filter(|r| r.token_table.is_some()) {
        let state = state_with_failing_email().await;
        seed_caller(&state, route).await;
        let token = access_jwt(&state.jwt_secret, DID);

        let response = app(state)
            .oneshot(post(route.path, &token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            route.path
        );
    }
}

/// These procedures start an account-level ceremony, so an app password is refused even with the
/// privileged flag — only a full session may begin one.
#[tokio::test]
async fn app_password_scope_rejected() {
    for route in NO_INPUT_ROUTES.iter().filter(|r| r.token_table.is_some()) {
        let state = test_state().await;
        seed_caller(&state, route).await;
        let token = app_pass_jwt(&state.jwt_secret, DID, true);

        let response = app(state)
            .oneshot(post(route.path, &token, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{}",
            route.path
        );
    }
}

// ── Read routes that name a repo by DID ───────────────────────────────────────

/// Builds a request for a URI template whose `{did}` placeholder names the repo, adding the admin
/// bearer when the route sits behind the admin guard.
fn did_lookup_request(uri: &str, did: &str, admin: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri.replace("{did}", did));
    if admin {
        builder = builder.header("Authorization", format!("Bearer {ADMIN_TOKEN}"));
    }
    builder.body(Body::empty()).unwrap()
}

/// `(uri template, behind the admin guard)`. `com.atproto.sync.getBlocks` validates the DID before
/// it parses `cids`, which is why a placeholder CID is enough here.
const INVALID_DID_ROUTES: &[(&str, bool)] = &[
    ("/xrpc/com.atproto.admin.getSubjectStatus?did={did}", true),
    (
        "/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post",
        false,
    ),
    (
        "/xrpc/com.atproto.sync.getBlocks?did={did}&cids=bafkreifake",
        false,
    ),
    ("/xrpc/com.atproto.sync.getLatestCommit?did={did}", false),
    (
        "/xrpc/com.atproto.sync.getRecord?did={did}&collection=app.bsky.feed.post&rkey=rec1",
        false,
    ),
    ("/xrpc/com.atproto.sync.getRepoStatus?did={did}", false),
];

/// A syntactically invalid DID is the caller's mistake (400), never a missing repo (404) — the
/// distinction is what tells a client to fix its request rather than retry it.
#[tokio::test]
async fn invalid_did_returns_400() {
    for (uri, admin) in INVALID_DID_ROUTES {
        let state = if *admin {
            test_state_with_admin_token().await
        } else {
            test_state().await
        };
        let response = app(state)
            .oneshot(did_lookup_request(uri, "not-a-did", *admin))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

/// `(uri template, behind the admin guard, error name the 404 envelope pins)`.
const UNKNOWN_DID_ROUTES: &[(&str, bool, Option<&str>)] = &[
    ("/v1/accounts/{did}/storage", true, Some("NOT_FOUND")),
    ("/v1/accounts/{did}/usage", true, Some("NOT_FOUND")),
    // An XRPC path, unlike /v1/accounts/*: the flat XRPC error shape names this "NotFound"
    // (see xrpc_error_shape.rs), not the nested envelope's "NOT_FOUND".
    (
        "/xrpc/com.atproto.admin.getSubjectStatus?did={did}",
        true,
        Some("NotFound"),
    ),
    (
        "/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post",
        false,
        None,
    ),
    (
        "/xrpc/com.atproto.sync.getRecord?did={did}&collection=app.bsky.feed.post&rkey=rec1",
        false,
        None,
    ),
];

/// A well-formed DID this PDS has never heard of is a 404.
#[tokio::test]
async fn unknown_did_returns_404() {
    for (uri, admin, expected_error) in UNKNOWN_DID_ROUTES {
        let state = if *admin {
            test_state_with_admin_token().await
        } else {
            test_state().await
        };
        let response = app(state)
            .oneshot(did_lookup_request(
                uri,
                "did:plc:ghost0000000000000000000",
                *admin,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        if let Some(expected) = expected_error {
            let json = body_json(response).await;
            assert_eq!(error_name(&json), Some(*expected), "{uri}");
        }
    }
}

// ── Constant public documents ─────────────────────────────────────────────────

/// The documents an OAuth client fetches before it can talk to this PDS at all. Their contents are
/// asserted whole in each route's own module; what is shared is only that they are reachable
/// anonymously and self-describe as JSON.
const PUBLIC_JSON_DOCUMENTS: &[&str] = &[
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/jwks",
];

#[tokio::test]
async fn public_documents_return_200_with_json_content_type() {
    for path in PUBLIC_JSON_DOCUMENTS {
        let response = app(test_state().await)
            .oneshot(Request::builder().uri(*path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            JSON,
            "{path}"
        );
    }
}

// ── Database failure ──────────────────────────────────────────────────────────

/// `(method, path, JSON body, behind the admin guard)`. A closed pool stands in for any storage
/// failure the handler cannot do anything about.
const CLOSED_POOL_ROUTES: &[(&str, &str, &str, bool)] = &[
    (
        "POST",
        "/v1/accounts",
        r#"{"email":"x@example.com","handle":"x.example.com","tier":"free"}"#,
        true,
    ),
    (
        "POST",
        "/v1/accounts/mobile",
        r#"{"email":"a@example.com","handle":"a.example.com","devicePublicKey":"dGVzdC1rZXk=","platform":"ios","claimCode":"ABC123"}"#,
        false,
    ),
    (
        "POST",
        "/v1/devices",
        r#"{"claimCode":"ABC123","devicePublicKey":"dGVzdC1rZXk=","platform":"ios"}"#,
        false,
    ),
];

/// A storage failure is reported as a 500 carrying the opaque `INTERNAL_ERROR` code — never as a
/// 4xx that would tell the caller to change a request that was fine.
#[tokio::test]
async fn closed_db_pool_returns_500() {
    for (method, path, body, admin) in CLOSED_POOL_ROUTES {
        let state = if *admin {
            test_state_with_admin_token().await
        } else {
            test_state().await
        };
        state.db.close().await;

        let mut builder = Request::builder()
            .method(*method)
            .uri(*path)
            .header("Content-Type", JSON);
        if *admin {
            builder = builder.header("Authorization", format!("Bearer {ADMIN_TOKEN}"));
        }
        let response = app(state)
            .oneshot(builder.body(Body::from(*body)).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{method} {path}"
        );
        let json = body_json(response).await;
        assert_eq!(error_name(&json), Some("INTERNAL_ERROR"), "{method} {path}");
    }
}
