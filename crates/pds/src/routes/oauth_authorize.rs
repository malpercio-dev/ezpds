// pattern: Imperative Shell
//
// Gathers: query params (client_id + PAR request_uri) on GET; form body (action +
//          the consent fields) on POST
// Processes:
//   GET:  resolves the PAR request → looks up client → validates redirect_uri → renders HTML
//   POST: validates client + redirect_uri first → handles deny/approve → generates auth code
// Returns:
//   GET:  HTML consent page (200) or HTML error page (400) when redirect is unsafe
//   POST: 303 redirect to redirect_uri?code=...&state=... or redirect_uri?error=...

//! `GET`/`POST /oauth/authorize` — the authorization endpoint and its consent page.
//!
//! **PAR only.** The server metadata advertises `require_pushed_authorization_requests: true`
//! (the atproto OAuth profile mandates PAR), and this endpoint enforces it: a GET without a
//! PAR-issued `request_uri` gets the no-redirect error page, as does one carrying a JAR
//! (RFC 9101) `request` object — advertised unsupported via
//! `request_parameter_supported: false` and rejected rather than silently ignored. Client
//! registration therefore happens at `/oauth/par`; this endpoint only reads the cached row.
//! The reverse-FQDN private-use-redirect rule is enforced here as well as at PAR.
//!
//! **`response_mode`.** Honored on every success and error redirect: `query` (the default) or
//! `fragment` (the `@atproto/oauth-client-browser` default).
//!
//! **Push dispatch (Phase C).** The GET's wallet path owns `dispatch_login_approval_push`: a
//! `login_hint` naming a hosted account gets a sealed `login-approval` push via
//! `notifications::notify_device`. The hint is resolved with local lookups only — never outbound
//! resolution, because it is attacker-suppliable on an unauthenticated surface — and the
//! two-digit match code (the V060 `match_code` column) is latched and shown on the page only
//! when a device was actually enqueued.

use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_response_mode::ResponseMode;
use crate::auth::password::{verify_password, VerifyResult, TIMING_DUMMY_HASH};
use crate::auth::rate_limit::{clear_failures, is_rate_limited, record_failure};
use crate::auth::token::generate_token;
use crate::code_gen::{generate_login_code, generate_match_code};
use crate::db::accounts::{active_local_account_exists, resolve_identifier};
use crate::db::oauth::{
    consume_par_request, get_oauth_client, store_authorization_code, ClientMetadata,
    StoredPARParams,
};
use crate::db::pending_oauth_authorizations::{
    cleanup_expired_pending_authorizations, insert_oauth_consent_audit_event,
    insert_pending_authorization, set_push_dispatched, NewPendingOAuthAuthorization,
    OAuthConsentAuditEventType,
};
use crate::notifications::{notify_device, NotificationPayload};
use crate::routes::oauth_templates::{
    build_code_redirect, error_page, error_redirect, render_consent_page, WalletConsentPath,
};

/// Time-to-live of a pending wallet-consent request (~5 minutes, per the design).
const PENDING_REQUEST_TTL_SECS: i64 = 300;
/// How long an expired pending row lingers before opportunistic cleanup reclaims it, so the status
/// poll can still report `expired` for a while after the window closes.
const PENDING_REQUEST_CLEANUP_GRACE_SECS: i64 = 3600;

/// Reduce an `Origin`/`Referer` header to just scheme + host (+ port), discarding any path, query,
/// or fragment. The wallet only ever shows the requesting origin, and a full referring URL has no
/// business landing in the pending row or the audit log.
fn sanitize_origin(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    let host = parsed.host_str()?;
    let scheme = parsed.scheme();
    Some(match parsed.port() {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

/// Fully-resolved parameters for the authorization consent page.
///
/// Constructed by looking up the stored PAR request named by `request_uri` and
/// deserializing its JSON — the only way in, since this endpoint is PAR-only.
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub response_type: String,
    /// How the authorization response is delivered to `redirect_uri` (query vs fragment).
    /// Parsed/validated at resolution so every later redirect answers in the mode the
    /// client asked for — a fragment-mode browser client never reads the query string.
    pub response_mode: ResponseMode,
    pub scope: String,
    /// ATProto extension: the client's hint about which account is authorizing.
    /// Pre-populates the identifier field on the consent page.
    pub login_hint: Option<String>,
    /// The DPoP key thumbprint bound at PAR time (RFC 9449 §10), when the pushing
    /// client proved a key. `None` when it pushed without one.
    pub dpop_jkt: Option<String>,
}

/// Raw query parameters for `GET /oauth/authorize`.
///
/// A conformant request carries exactly `client_id` and `request_uri` (PAR-only).
/// `request` exists only to be rejected: serde drops unknown query fields silently,
/// and a JAR request object we advertise as unsupported must fail loudly rather
/// than have its inner parameters ignored.
#[derive(Deserialize)]
pub struct GetAuthorizationQuery {
    pub client_id: String,
    /// PAR reference. All authorization parameters come from the stored request.
    pub request_uri: Option<String>,
    /// JAR (RFC 9101) request object — not supported, present only for rejection.
    pub request: Option<String>,
}

/// Form body for `POST /oauth/authorize`.
#[derive(Deserialize)]
pub struct ConsentForm {
    pub action: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub scope: String,
    pub response_type: String,
    /// Round-tripped hidden field. Defaulted (→ "query") rather than required so a form
    /// predating this field still parses; validated like every other hidden field, since
    /// they are all attacker-controllable.
    #[serde(default)]
    pub response_mode: String,
    /// Handle or DID entered by the user to identify the account being authorized.
    /// `None` when the field is absent (e.g. deny submissions don't send credentials).
    pub identifier: Option<String>,
    /// Password for the identified account. `None` when absent (same as above).
    pub password: Option<String>,
    /// The subset of non-`atproto` permissions the user left checked on the consent page.
    /// One `granted_scope` form field per checked box; absent entirely if every box was
    /// unchecked. `atproto` is never a checkbox — it's always granted, unconditionally.
    ///
    /// `deserialize_with` is required, not cosmetic: the urlencoded-form deserializer
    /// represents a single repeated-key occurrence as a bare string rather than a
    /// one-element sequence, so a plain `Vec<String>` fails to deserialize with exactly one
    /// checkbox checked (the common case) while working fine with zero or two-plus.
    #[serde(
        default,
        deserialize_with = "crate::auth::permission_sets::string_or_vec"
    )]
    pub granted_scope: Vec<String>,
}

/// Distinguishes client-caused failures from server-caused failures in PAR resolution.
///
/// Callers use this to pick the right error page title: client errors get the
/// request-didn't-work page, infrastructure failures (which should trigger alerts)
/// get the server-error page. Both variants carry finished user-register copy; the
/// mechanical detail lives in the tracing at the failure site.
enum ResolveError {
    /// The client sent an invalid or expired `request_uri`, or a mismatched `client_id`.
    Client(&'static str),
    /// A database or deserialization failure prevented resolution.
    Server(&'static str),
}

/// Shared error-page copy for infrastructure failures. The mechanical cause is already
/// traced at the failure site, so the user's sentence carries none of it.
const SERVER_ERROR_PAGE_MSG: &str = "This server hit a problem before it could finish. \
     Nothing was granted. Wait a moment, then start the sign-in again from the app.";

/// Shared error-page copy for a request naming a response delivery mode this server
/// doesn't support. The `response_mode` detail goes to the log, not the user's sentence.
const UNSUPPORTED_RESPONSE_MODE_MSG: &str = "The app asked for a kind of sign-in response \
     this server doesn't support, so the request stopped here. Nothing was granted. If \
     this keeps happening, the problem is on the app's side.";

/// Resolve `GetAuthorizationQuery` into a fully-populated `AuthorizeQuery`.
///
/// PAR-only: atomically consumes the stored request named by `request_uri` (single-use
/// per RFC 9126 §4), deserializes the params JSON, and validates `client_id` matches.
/// A request carrying a JAR `request` object or arriving without a `request_uri` is
/// rejected before anything is consumed — neither names a redirect target this server
/// has validated, so both get the no-redirect error page.
async fn resolve_authorize_params(
    state: &AppState,
    raw: GetAuthorizationQuery,
) -> Result<AuthorizeQuery, ResolveError> {
    // Checked before the PAR row is touched, so a request that mixes a valid
    // `request_uri` with a `request` object fails without burning the single-use row.
    if raw.request.is_some() {
        tracing::info!(
            client_id = %raw.client_id,
            "authorize request rejected: JAR request objects are not supported"
        );
        return Err(ResolveError::Client(
            "The app sent its sign-in request in a format this server doesn't \
             support, so the request stopped here. Nothing was granted. If this \
             keeps happening, the problem is on the app's side.",
        ));
    }

    let Some(uri) = raw.request_uri else {
        // The metadata advertises `require_pushed_authorization_requests: true`; a
        // client sending inline authorization parameters skipped PAR and is refused
        // at flow start rather than allowed down a path the metadata says is closed.
        tracing::info!(
            client_id = %raw.client_id,
            "authorize request rejected: no PAR request_uri (this server is PAR-only)"
        );
        return Err(ResolveError::Client(
            "The app started sign-in without the preliminary step this server \
             requires, so the request stopped here. Nothing was granted. If this \
             keeps happening, the problem is on the app's side.",
        ));
    };

    let row = match consume_par_request(&state.db, &uri).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(ResolveError::Client(
                "This sign-in link has expired or was already used. Nothing was \
                 granted. Go back to the app and start the sign-in again.",
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "db error consuming PAR request");
            return Err(ResolveError::Server(SERVER_ERROR_PAGE_MSG));
        }
    };

    if row.client_id != raw.client_id {
        tracing::info!(
            client_id = %raw.client_id,
            "authorize request rejected: client_id does not match the pushed authorization request"
        );
        return Err(ResolveError::Client(
            "This sign-in request doesn't match the app that started it, so it \
             stopped here. Nothing was granted. Go back to the app and start the \
             sign-in again.",
        ));
    }

    let stored: StoredPARParams = match serde_json::from_str(&row.request_parameters) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(
                client_id = %raw.client_id,
                error = %e,
                "failed to deserialize stored PAR request parameters; possible schema drift or DB corruption"
            );
            return Err(ResolveError::Server(SERVER_ERROR_PAGE_MSG));
        }
    };

    // The PAR endpoint validated the mode before storing it, so a parse failure here
    // means the stored row was hand-edited or the schema drifted — a client error is
    // still the safer framing (nothing redirects yet).
    let response_mode =
        ResponseMode::parse(Some(stored.response_mode.as_str())).map_err(|desc| {
            tracing::info!(desc, "authorize request rejected: bad stored response_mode");
            ResolveError::Client(UNSUPPORTED_RESPONSE_MODE_MSG)
        })?;

    Ok(AuthorizeQuery {
        client_id: raw.client_id,
        redirect_uri: stored.redirect_uri,
        code_challenge: stored.code_challenge,
        code_challenge_method: stored.code_challenge_method,
        state: stored.state,
        response_type: stored.response_type,
        response_mode,
        scope: stored.scope,
        login_hint: stored.login_hint,
        dpop_jkt: stored.dpop_jkt,
    })
}

/// Failure modes of [`lookup_and_validate_client`].
///
/// Each variant maps to a distinct error page in the caller. The caller picks the
/// title and message so the GET and POST handlers can keep their existing wording.
enum ClientValidationError {
    /// No client is registered under the supplied `client_id`.
    UnknownClient,
    /// A database error occurred while looking up the client.
    DbError,
    /// The stored client metadata could not be deserialized.
    MalformedMetadata,
    /// The supplied `redirect_uri` is not among the client's registered URIs.
    InvalidRedirectUri,
    /// A private-use-scheme `redirect_uri` whose scheme is not the client_id host's
    /// reverse-FQDN. Carries the rule text naming the required scheme.
    PrivateUseRedirectMismatch(String),
}

impl ClientValidationError {
    /// Render the no-redirect error page for this failure. Shared by the GET and POST
    /// handlers, which show identical copy for each variant since neither has a
    /// validated `redirect_uri` to send the user back to yet.
    fn into_error_page(self) -> Response {
        match self {
            Self::UnknownClient => error_page(
                "This app isn't recognized",
                "This server doesn't recognize the app asking to sign you in, so the \
                 request stopped here. Nothing was granted. If this keeps happening, \
                 the problem is on the app's side.",
            ),
            Self::PrivateUseRedirectMismatch(desc) => error_page(
                "Can't return you to the app",
                &format!(
                    "The app asked to send you to an address it hasn't registered, so \
                     you weren't sent anywhere and nothing was granted. Details for the \
                     app's developer: {desc}"
                ),
            ),
            Self::DbError => {
                error_page("Something went wrong on this server", SERVER_ERROR_PAGE_MSG)
            }
            Self::MalformedMetadata => error_page(
                "This app is set up incorrectly",
                "The app's registration on this server isn't valid, so sign-in can't \
                 continue. Nothing was granted. The app's developer needs to fix its \
                 registration.",
            ),
            Self::InvalidRedirectUri => error_page(
                "Can't return you to the app",
                "The app asked to send you to an address it hasn't registered, so you \
                 weren't sent anywhere and nothing was granted. If this keeps happening, \
                 tell the app's developer.",
            ),
        }
        .into_response()
    }
}

/// Look up the registered client, parse its metadata, and validate `redirect_uri`.
///
/// Shared by both the GET and POST authorization handlers, which must confirm the
/// client and redirect target are safe before issuing any redirect. Returns the
/// parsed [`ClientMetadata`] on success, or a [`ClientValidationError`] the caller
/// renders as its own error page.
///
/// Lookup is cache-only: the PAR endpoint resolves and caches the client's metadata
/// document before it issues a `request_uri`, and this endpoint refuses requests
/// that didn't come through PAR, so an unknown `client_id` here means the request
/// never pushed (a forged POST, or a row lost between PAR and now) — not a real
/// client this server should go fetch on demand.
async fn lookup_and_validate_client(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
) -> Result<ClientMetadata, ClientValidationError> {
    let client_metadata_json = match get_oauth_client(&state.db, client_id).await {
        Ok(Some(row)) => row.client_metadata,
        Ok(None) => return Err(ClientValidationError::UnknownClient),
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client");
            return Err(ClientValidationError::DbError);
        }
    };

    let metadata: ClientMetadata = match serde_json::from_str(&client_metadata_json) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                client_id = %client_id,
                error = %e,
                "failed to parse OAuth client metadata"
            );
            return Err(ClientValidationError::MalformedMetadata);
        }
    };

    if !metadata.redirect_uris.contains(&redirect_uri.to_string()) {
        return Err(ClientValidationError::InvalidRedirectUri);
    }

    // The reverse-FQDN rule for private-use-scheme redirects, enforced here as well as
    // at PAR so a forged consent POST (hidden fields are attacker-controllable) can't
    // sidestep it.
    if let Err(desc) =
        crate::auth::oauth_client_resolution::validate_private_use_redirect(client_id, redirect_uri)
    {
        return Err(ClientValidationError::PrivateUseRedirectMismatch(desc));
    }

    Ok(metadata)
}

/// `GET /oauth/authorize` — validate request parameters and render the consent page.
///
/// Accepts only a PAR `request_uri` (RFC 9126); direct parameters and JAR `request`
/// objects are rejected in `resolve_authorize_params`. Returns an HTML error page
/// (400) for errors that make a redirect unsafe: no resolvable pushed request,
/// unknown `client_id`, or mismatched `redirect_uri`. All other parameter errors
/// redirect to `redirect_uri` with an `error` query parameter per RFC 6749 §4.1.2.1.
pub async fn get_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(raw): Query<GetAuthorizationQuery>,
) -> Response {
    // RFC 9207 issuer identifier, emitted as `iss` on every authorization response.
    // Trailing slash trimmed to match the AS-metadata `issuer` value exactly.
    let issuer = state.config.issuer().to_string();
    let params = match resolve_authorize_params(&state, raw).await {
        Ok(p) => p,
        Err(ResolveError::Client(msg)) => {
            return error_page("This sign-in request didn't work", msg).into_response()
        }
        Err(ResolveError::Server(msg)) => {
            return error_page("Something went wrong on this server", msg).into_response()
        }
    };

    // Client and redirect_uri must be validated before any redirect is issued.
    let metadata =
        match lookup_and_validate_client(&state, &params.client_id, &params.redirect_uri).await {
            Ok(m) => m,
            Err(e) => return e.into_error_page(),
        };

    // From here on redirect_uri is validated — errors redirect there, not to an error page.
    // Captures the fields every error redirect on this request needs, so each call site
    // names only what's specific to it.
    let redirect_err = |error: &str, description: &str| -> Response {
        error_redirect(
            &params.redirect_uri,
            error,
            description,
            &params.state,
            &issuer,
            params.response_mode,
        )
        .into_response()
    };

    if params.response_type != "code" {
        return redirect_err(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }

    if params.code_challenge_method != "S256" {
        return redirect_err("invalid_request", "code_challenge_method must be S256");
    }

    let client_name = metadata
        .client_name
        .unwrap_or_else(|| params.client_id.clone());

    // Render-only expansion: shows the user real permissions instead of an opaque `include:`
    // reference. `post_authorization` re-runs expansion authoritatively regardless of what's
    // rendered here (hidden form fields are attacker-controllable), but a resolution failure
    // still redirects with an error rather than falling back to the raw unexpanded scope: if the
    // page fell back and a transient failure then cleared before the user submits,
    // `post_authorization`'s authoritative expansion would produce granular tokens that don't
    // match the raw `include:<nsid>` checkbox value the page rendered, and the grant-reduction
    // filter would silently drop everything from that set — a real (if narrow) desync between
    // what the user saw/approved and what gets granted. Failing the page outright avoids that
    // class of bug entirely, at the cost of requiring a retry on a transient blip.
    let display_scope = match crate::auth::permission_sets::expand_include_scopes(
        &state,
        &state.permission_set_cache,
        &params.scope,
    )
    .await
    {
        Ok(s) => s,
        Err(desc) => return redirect_err("invalid_scope", &desc),
    };

    // User-legible text for any `space:` tokens. Best-effort by design: unlike the `include:`
    // expansion above, this changes only the labels — the checkbox values stay the raw tokens —
    // so a failed lookup degrades to the raw NSID instead of failing the page.
    let spaces = crate::auth::space_consent::resolve_space_displays(
        &state,
        &state.space_type_cache,
        &display_scope,
        &crate::auth::space_consent::preferred_languages(
            headers
                .get(axum::http::header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok()),
        ),
    )
    .await;

    // Wallet-confirmed consent path: create a single-use pending request that a sovereign /
    // passwordless account approves out-of-band from its wallet. This is best-effort — a creation
    // failure (rate limit, DB error) simply degrades to the legacy password-only page rather than
    // breaking consent for passworded accounts.
    let wallet_codes = create_pending_request(
        &state,
        &headers,
        &params,
        client_name.as_str(),
        &display_scope,
    )
    .await;
    let wallet = wallet_codes.as_ref().map(|pending| WalletConsentPath {
        user_code: &pending.user_code,
        request_id: &pending.request_id,
        origin: pending.origin.as_deref(),
        match_code: pending.match_code.as_deref(),
    });

    Html(render_consent_page(
        &client_name,
        &params.client_id,
        &params.redirect_uri,
        &params.code_challenge,
        &params.code_challenge_method,
        &params.state,
        &display_scope,
        &params.response_type,
        params.response_mode,
        &state.config.public_url,
        params.login_hint.as_deref(),
        None,
        wallet.as_ref(),
        &spaces,
    ))
    .into_response()
}

/// What `create_pending_request` hands the consent page to render: the typed code, the poll /
/// handoff key, the snapshotted origin, and — when a `login-approval` push went out — the
/// number-match code the page must display (V060).
struct PendingWalletRequest {
    user_code: String,
    request_id: String,
    origin: Option<String>,
    match_code: Option<String>,
}

/// Create a single-use pending wallet-consent request, returning what the page renders (the
/// origin is snapshotted into the scan QR alongside the request_id), or `None` if creation should
/// be skipped (rate limited or a DB error) — the caller degrades to the password-only page.
/// Snapshots the client metadata and requesting context so the wallet preview and later
/// completion never re-resolve the client document, and audits the creation. When the request's
/// `login_hint` names a local account, a sealed `login-approval` push is dispatched to that
/// account's registered wallet devices (Phase C).
async fn create_pending_request(
    state: &AppState,
    headers: &HeaderMap,
    params: &AuthorizeQuery,
    client_name: &str,
    display_scope: &str,
) -> Option<PendingWalletRequest> {
    let client_ip = crate::rate_limit::client_ip_from_headers(headers);
    if state
        .rate_limiter
        .check_oauth_consent_creation(&params.client_id, &client_ip)
        .is_err()
    {
        tracing::debug!(client_id = %params.client_id, "wallet-consent request creation rate-limited");
        return None;
    }

    let header_str = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    // Keep only scheme + host (+ port) from Origin/Referer — never a full referring URL's path or
    // query — in the pending row and audit log.
    let origin = header_str("origin")
        .or_else(|| header_str("referer"))
        .and_then(|raw| sanitize_origin(&raw));
    let user_agent = header_str("user-agent");

    let request_id = format!("poauth_{}", generate_token().plaintext);
    let user_code = generate_login_code();

    // Reclaim long-expired rows before inserting (the oauth_par_requests / transfers precedent),
    // so the table stays bounded without a background sweep.
    if cleanup_expired_pending_authorizations(&state.db, PENDING_REQUEST_CLEANUP_GRACE_SECS)
        .await
        .is_err()
    {
        return None;
    }

    let new = NewPendingOAuthAuthorization {
        request_id: &request_id,
        user_code: &user_code,
        client_id: &params.client_id,
        client_name: Some(client_name),
        redirect_uri: &params.redirect_uri,
        code_challenge: &params.code_challenge,
        code_challenge_method: &params.code_challenge_method,
        state: &params.state,
        response_type: &params.response_type,
        response_mode: params.response_mode.as_str(),
        requested_scope: display_scope,
        login_hint: params.login_hint.as_deref(),
        origin: origin.as_deref(),
        ip: Some(client_ip.as_str()),
        user_agent: user_agent.as_deref(),
        dpop_jkt: params.dpop_jkt.as_deref(),
        ttl_secs: PENDING_REQUEST_TTL_SECS,
    };
    if insert_pending_authorization(&state.db, &new).await.is_err() {
        return None;
    }

    // Audit the creation (best-effort — a failed audit must not deny the consent page). The
    // account_did is left NULL here: the client-supplied login_hint is unverified (it can be a
    // handle or an attacker-chosen DID), so it is recorded as a mechanical `login_hint` fact in the
    // detail rather than attributed as the approving account — that binding is only established at
    // approval, against authoritative PLC state.
    let detail = serde_json::json!({
        "client_id": params.client_id,
        "requested_scope": display_scope,
        "origin": origin,
        "login_hint": params.login_hint,
    })
    .to_string();
    if let Err(e) = insert_oauth_consent_audit_event(
        &state.db,
        &uuid::Uuid::new_v4().to_string(),
        &request_id,
        None,
        &params.client_id,
        OAuthConsentAuditEventType::RequestCreated,
        Some(&detail),
    )
    .await
    {
        tracing::warn!(error = %e, "failed to audit wallet-consent request creation");
    }

    // Phase C: push-to-approve. Best-effort — a push is a convenience layer on the same pending
    // request, and every failure here degrades to the Phase A/B channels (typed code, QR,
    // handoff) already rendered on the page.
    let match_code = dispatch_login_approval_push(
        state,
        &request_id,
        &params.client_id,
        client_name,
        origin.as_deref(),
        params.login_hint.as_deref(),
    )
    .await;

    Some(PendingWalletRequest {
        user_code,
        request_id,
        origin,
        match_code,
    })
}

/// Resolve a client-supplied `login_hint` to a local, active account DID — **local lookups
/// only**. This runs on an unauthenticated surface with an attacker-suppliable hint, so it must
/// never drive outbound handle resolution (the SSRF/amplification posture); an account not on
/// this instance has no registered wallet devices to push to anyway.
async fn resolve_login_hint_to_local_did(state: &AppState, hint: &str) -> Option<String> {
    let did = match crate::identity::handle::normalize_login_hint(hint)? {
        crate::identity::handle::LoginHint::Did(did) => did,
        crate::identity::handle::LoginHint::Handle(handle) => {
            crate::db::handles::resolve_handle(&state.db, &handle)
                .await
                .ok()??
        }
    };
    match active_local_account_exists(&state.db, &did).await {
        Ok(true) => Some(did),
        _ => None,
    }
}

/// Seal and enqueue a `login-approval` push toward the hinted account's registered wallet
/// devices, then latch the number-match requirement onto the pending row. Returns the two-digit
/// match code for the page to display, or `None` when no push went out.
///
/// Anyone can type a victim's handle into a consent page, so this channel is exactly where
/// MFA-fatigue / blind-tap attacks live. Two mitigations gate it: creation is rate-limited per
/// client and per IP (`check_oauth_consent_creation`, upstream of this call), and once a push is
/// dispatched approval REQUIRES the number displayed on the login surface — a victim who is not
/// looking at any sign-in page has nothing to type. The payload is HPKE-sealed to each device and
/// the relay sees only an opaque push handle, so the relay never learns a login is happening.
async fn dispatch_login_approval_push(
    state: &AppState,
    request_id: &str,
    client_id: &str,
    client_name: &str,
    origin: Option<&str>,
    login_hint: Option<&str>,
) -> Option<String> {
    // Cheap outs before any lookup: no relay configured, or no hint to name a recipient.
    state.notify_sender.as_ref()?;
    let did = resolve_login_hint_to_local_did(state, login_hint?).await?;

    // The number is deliberately absent from the payload: it is the proof the approver can see
    // the login surface, so handing it to the wallet would defeat the channel binding. The wallet
    // re-fetches everything it displays from the server's record by `request_id` (the QR-path
    // discipline); `clientName`/`origin` ride along only for the banner the NSE renders.
    let body = match origin {
        Some(origin) => format!(
            "{client_name} at {origin} is asking to sign in as you. If this is you, open the \
             request and enter the number shown on the sign-in screen."
        ),
        None => format!(
            "{client_name} is asking to sign in as you. If this is you, open the request and \
             enter the number shown on the sign-in screen."
        ),
    };
    let payload = NotificationPayload::new("login-approval", "Sign-in request", body).with_data(
        serde_json::json!({
            "requestId": request_id,
            "did": did,
            "clientName": client_name,
            "origin": origin,
        }),
    );
    let enqueued = notify_device(state, &did, payload).await;
    if enqueued == 0 {
        // Worth one line: the hint named a real local account, notifications are configured,
        // and yet nothing could be sent — the account has no registration with a live relay
        // handle. Every earlier exit on this path is either deliberate silence (no relay, no
        // hint) or already logged by `notify_device`; this is the one outcome that otherwise
        // leaves no trace anywhere while the user waits for a push that cannot arrive.
        tracing::info!(
            account_did = %did,
            "login-approval push not sent: the account has no reachable registered device"
        );
        return None;
    }

    // Latch the requirement only after at least one sealed payload was enqueued: matching is
    // mandatory on the push channel, and requiring a number no push ever announced would add
    // friction to the wallet-initiated channels for nothing.
    let match_code = generate_match_code();
    match set_push_dispatched(&state.db, request_id, &match_code).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(request_id = %request_id, "push dispatched but the match code did not latch");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, request_id = %request_id, "failed to record push dispatch");
            return None;
        }
    }

    // `account_did` stays NULL like the creation event — that column means "the approving
    // account", a binding only established at approval. The push target is a mechanical fact.
    let detail = serde_json::json!({ "devices": enqueued, "pushed_to": did }).to_string();
    if let Err(e) = insert_oauth_consent_audit_event(
        &state.db,
        &uuid::Uuid::new_v4().to_string(),
        request_id,
        None,
        client_id,
        OAuthConsentAuditEventType::PushDispatched,
        Some(&detail),
    )
    .await
    {
        tracing::warn!(error = %e, "failed to audit login-approval push dispatch");
    }

    Some(match_code)
}

/// `POST /oauth/authorize` — handle the user's approval or denial of the consent request.
///
/// Re-validates client_id and redirect_uri against the database, and enforces
/// code_challenge_method=S256, before issuing an authorization code or redirect.
/// Hidden form fields could be tampered with by a malicious browser.
pub async fn post_authorization(
    State(state): State<AppState>,
    Form(form): Form<ConsentForm>,
) -> Response {
    // RFC 9207 issuer identifier, emitted as `iss` on every authorization response.
    // Trailing slash trimmed to match the AS-metadata `issuer` value exactly.
    let issuer = state.config.issuer().to_string();
    // Validate client and redirect_uri first — deny/approve both redirect there,
    // so we must confirm it is safe before using it as a redirect target.
    let metadata =
        match lookup_and_validate_client(&state, &form.client_id, &form.redirect_uri).await {
            Ok(m) => m,
            Err(e) => return e.into_error_page(),
        };

    // The hidden response_mode field is attacker-controllable like every other hidden
    // field. An unknown value gets the no-redirect error page: guessing a delivery mode
    // the client never asked for would hand the response to a place it isn't looking.
    let mode = match ResponseMode::parse(Some(form.response_mode.as_str())) {
        Ok(m) => m,
        Err(desc) => {
            tracing::info!(desc, "consent form rejected: bad response_mode");
            return error_page(
                "This sign-in request didn't work",
                UNSUPPORTED_RESPONSE_MODE_MSG,
            )
            .into_response();
        }
    };

    // redirect_uri is now validated — denial and all subsequent errors redirect there.
    // Captures the fields every error redirect on this request needs, so each call site
    // names only what's specific to it.
    let redirect_err = |error: &str, description: &str| -> Response {
        error_redirect(
            &form.redirect_uri,
            error,
            description,
            &form.state,
            &issuer,
            mode,
        )
        .into_response()
    };

    if form.action == "deny" {
        return redirect_err("access_denied", "User denied access");
    }

    if form.action != "approve" {
        return redirect_err("invalid_request", "invalid action");
    }

    if form.response_type != "code" {
        return redirect_err(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }

    if form.code_challenge_method != "S256" {
        return redirect_err("invalid_request", "code_challenge_method must be S256");
    }

    // Resolve the identifier and check the login rate limit *before* any expensive work —
    // scope normalization/expansion below can perform real DNS/HTTP network calls for
    // `include:<nsid>` references, so this cheap, local, identifier-keyed gate must run first
    // to avoid giving an unauthenticated caller a way to trigger unthrottled network I/O by
    // varying the scope on repeated submissions for the same identifier.
    let client_name_str = metadata
        .client_name
        .clone()
        .unwrap_or_else(|| form.client_id.clone());

    // Token-only space display: the broad-grant warning and everything else derivable without
    // network I/O. Resolving declarations here would mean outbound DNS/HTTP *before* the
    // identifier-keyed login rate-limit gate below — the amplification hole that gate exists to
    // close — so this path shows the raw NSID and keeps the warning.
    let spaces = crate::auth::space_consent::space_displays_without_resolution(&form.scope);

    // Helper closure to re-render the consent page without redirecting to the client.
    let rerender = |hint: Option<&str>, error: &str| -> Response {
        Html(render_consent_page(
            &client_name_str,
            &form.client_id,
            &form.redirect_uri,
            &form.code_challenge,
            &form.code_challenge_method,
            &form.state,
            &form.scope,
            &form.response_type,
            mode,
            &state.config.public_url,
            hint,
            Some(error),
            // The password-error re-render creates no pending request, so the wallet path is
            // omitted here; the user retries the password form (or reloads to get the wallet code).
            None,
            &spaces,
        ))
        .into_response()
    };

    let identifier = match form.identifier.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(id) => id.to_string(),
        None => return rerender(None, "Please enter your handle or DID."),
    };

    // Rate-limit check: guard before any DB work, argon2, or scope resolution to shed load early.
    {
        let mut attempts = state
            .failed_login_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if is_rate_limited(&mut attempts, &identifier) {
            return rerender(
                Some(&identifier),
                "Too many attempts. Wait a few minutes, then try again.",
            );
        }
    }

    let password = match form.password.as_deref().filter(|s| !s.is_empty()) {
        Some(p) => p.to_string(),
        None => return rerender(Some(&identifier), "Please enter your password."),
    };

    // Look up the account and verify the password before issuing any auth code. Re-render the
    // consent form (200) on all credential errors so the user can retry without the OAuth
    // client seeing a denial. "Not found" and "wrong password" produce identical messages and
    // timing to prevent enumeration.
    let account = match resolve_identifier(&state.db, &identifier).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            // Run a dummy argon2 to equalize timing with the wrong-password path,
            // preventing timing-based account enumeration.
            let _ = verify_password(TIMING_DUMMY_HASH, &password);
            tracing::debug!(
                identifier = %identifier,
                "OAuth consent: identifier not found or account deactivated"
            );
            let mut attempts = state
                .failed_login_attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            record_failure(&mut attempts, &identifier);
            return rerender(
                Some(&identifier),
                "That handle and password didn't match. Check them and try again.",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "db error resolving identifier for OAuth approval");
            return redirect_err("server_error", "Internal server error");
        }
    };

    let verify_result = match account.password_hash.as_deref() {
        // Mobile accounts (NULL or empty password_hash) cannot authenticate via OAuth consent.
        None | Some("") => VerifyResult::WrongPassword,
        Some(h) => verify_password(h, &password),
    };

    match verify_result {
        VerifyResult::Ok => {}
        VerifyResult::WrongPassword => {
            tracing::warn!(
                client_id = %form.client_id,
                did = %account.did,
                "OAuth consent: credential verification failed"
            );
            let mut attempts = state
                .failed_login_attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            record_failure(&mut attempts, &identifier);
            return rerender(
                Some(&identifier),
                "That handle and password didn't match. Check them and try again.",
            );
        }
        VerifyResult::CorruptHash => {
            tracing::error!(
                identifier = %identifier,
                did = %account.did,
                "stored password_hash is not a valid PHC string; possible DB corruption"
            );
            return redirect_err("server_error", "Internal server error");
        }
    }

    {
        let mut attempts = state
            .failed_login_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        clear_failures(&mut attempts, &identifier);
    }

    // Validate & canonically normalize the requested granular scopes before issuing a code.
    // Deliberately deferred until after credential verification: scope resolution below can
    // perform real DNS/HTTP network calls for `include:<nsid>` references, so an unauthenticated
    // or wrong-password caller never reaches it — the network path stays behind valid
    // credentials, and an invalid `include:` reference can't be probed pre-auth either. Hidden
    // form fields are attacker-controllable, so this is re-checked here even though the PAR
    // endpoint already validated it.
    let normalized_scope = match crate::auth::oauth_scopes::normalize_scope_request(&form.scope) {
        Ok(s) => s,
        Err(desc) => return redirect_err("invalid_scope", &desc),
    };

    // Resolve any `include:<nsid>` permission-set references to their granular scopes.
    // Authoritative — re-run regardless of what the GET already displayed (hidden form fields
    // are attacker-controllable); fails closed for the same reason `get_authorization`'s
    // render-only expansion does (see the comment there).
    let expanded_scope = match crate::auth::permission_sets::expand_include_scopes(
        &state,
        &state.permission_set_cache,
        &normalized_scope,
    )
    .await
    {
        Ok(s) => s,
        Err(desc) => return redirect_err("invalid_scope", &desc),
    };

    // Reduce to the user's actually-checked permissions: `atproto` is always granted
    // (never a checkbox); every other token is granted only if its checkbox was left checked.
    // Filtering `expanded_scope`'s own tokens (rather than trusting `granted_scope` values
    // directly) means a tampered/injected checkbox value that was never part of the requested
    // set is simply not present to match against — it can't add scope, only remove it.
    let granted_tokens: Vec<&str> = expanded_scope
        .split_whitespace()
        .filter(|t| *t == "atproto" || form.granted_scope.iter().any(|g| g == t))
        .collect();
    let granted_scope =
        match crate::auth::oauth_scopes::normalize_scope_request(&granted_tokens.join(" ")) {
            Ok(s) => s,
            Err(desc) => return redirect_err("invalid_scope", &desc),
        };

    let did = account.did;

    // Store the SHA-256 hash of the code, matching the session/refresh-token pattern.
    // The token endpoint hashes the presented code before lookup, consistent with all
    // other tokens in this codebase.
    let token = generate_token();
    if let Err(e) = store_authorization_code(
        &state.db,
        &token.hash,
        &form.client_id,
        &did,
        &form.code_challenge,
        &form.code_challenge_method,
        &form.redirect_uri,
        &granted_scope,
        // No DPoP binding on this path. The PAR row (which holds the pushed `dpop_jkt`) is
        // consumed by the GET that rendered this form, so by POST time the only place the
        // thumbprint could travel is a hidden field — which is attacker-controllable, and a
        // binding an attacker can simply omit is no binding at all. The wallet-consent path
        // keeps its pending request server-side and does bind (see `oauth_consent.rs`).
        None,
    )
    .await
    {
        tracing::error!(error = %e, "failed to store authorization code");
        return redirect_err("server_error", "Failed to generate authorization code");
    }

    // Return plaintext to the client; the DB stores only the hash. `iss` (RFC 9207) is
    // required on the authorization response — the AS metadata advertises
    // `authorization_response_iss_parameter_supported: true`, so a conformant client
    // validates it. The shared builder answers in the client's requested response mode.
    build_code_redirect(
        &form.redirect_uri,
        &token.plaintext,
        &form.state,
        &issuer,
        mode,
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::resolve_login_hint_to_local_did;
    use crate::app::{app, test_state};
    use crate::auth::token::hash_bearer_token;
    use crate::db::oauth::register_oauth_client;
    use crate::routes::test_utils;

    const CLIENT_ID: &str = "https://app.example.com/client-metadata.json";
    const REDIRECT_URI: &str = "https://app.example.com/callback";
    const CLIENT_METADATA: &str =
        r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"Test App"}"#;
    const DID: &str = "did:plc:testaccount000000000000";
    const TEST_HANDLE: &str = "alice.test";
    const TEST_PASSWORD: &str = "correcthorse";

    async fn state_with_client() -> crate::app::AppState {
        let state = test_state().await;
        register_oauth_client(&state.db, CLIENT_ID, CLIENT_METADATA)
            .await
            .unwrap();
        state
    }

    async fn state_with_client_and_account() -> crate::app::AppState {
        let state = state_with_client().await;
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        state
    }

    /// Creates a test state with a registered client and an account that has a real Argon2id
    /// password hash, plus an associated handle for identifier-based login tests.
    async fn state_with_client_and_account_with_password(password: &str) -> crate::app::AppState {
        let state = state_with_client().await;
        test_utils::insert_account_with_password(
            &state.db,
            DID,
            TEST_HANDLE,
            "test@example.com",
            password,
        )
        .await;
        state
    }

    fn approve_form_with_credentials(identifier: &str, password: &str) -> String {
        format!(
            "action=approve\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &scope=atproto\
             &response_type=code\
             &identifier={}&password={}",
            urlencoding::encode(identifier),
            urlencoding::encode(password),
        )
    }

    /// Test state with a mobile-provisioned account: handle is set but password_hash is NULL.
    async fn state_with_client_and_mobile_account() -> crate::app::AppState {
        let state = state_with_client().await;
        test_utils::seed_handle(&state.db, TEST_HANDLE, DID).await;
        state
    }

    /// Test state with a deactivated account (deactivated_at is set).
    async fn state_with_client_and_deactivated_account() -> crate::app::AppState {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        state
    }

    /// Default stored-PAR parameters; tests mutate individual fields before storing.
    fn par_params() -> serde_json::Value {
        serde_json::json!({
            "redirect_uri": REDIRECT_URI,
            "code_challenge": "e3b0c44298fc1c149afb",
            "code_challenge_method": "S256",
            "state": "teststate",
            "response_type": "code",
            "scope": "atproto",
            "login_hint": null,
        })
    }

    /// Store `params` as a PAR request under a fresh `request_uri` and return the
    /// authorize URL referencing it — the only shape the PAR-only endpoint accepts.
    async fn authorize_url_via_par(
        state: &crate::app::AppState,
        params: &serde_json::Value,
    ) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let request_uri = format!(
            "urn:ietf:params:oauth:request_uri:test-{}",
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        crate::db::oauth::store_par_request(
            &state.db,
            &request_uri,
            CLIENT_ID,
            &params.to_string(),
        )
        .await
        .unwrap();
        format!(
            "/oauth/authorize?client_id={}&request_uri={}",
            urlencoding::encode(CLIENT_ID),
            urlencoding::encode(&request_uri),
        )
    }

    /// Push `params` via PAR, then GET the authorize endpoint with the issued reference.
    async fn get_authorize_via_par(
        state: crate::app::AppState,
        params: serde_json::Value,
    ) -> axum::response::Response {
        let url = authorize_url_via_par(&state, &params).await;
        get_authorize(state, &url).await
    }

    async fn get_authorize(state: crate::app::AppState, url: &str) -> axum::response::Response {
        app(state)
            .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn post_authorize(state: crate::app::AppState, body: &str) -> axum::response::Response {
        app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/authorize")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    fn approve_form(extra: &str) -> String {
        format!(
            "action=approve\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &scope=atproto\
             &response_type=code\
             {extra}"
        )
    }

    fn deny_form() -> &'static str {
        "action=deny\
         &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
         &code_challenge=e3b0c44298fc1c149afb\
         &code_challenge_method=S256\
         &state=teststate\
         &scope=atproto\
         &response_type=code"
    }

    // ── GET tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_200_with_html_content_type() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"));
    }

    #[tokio::test]
    async fn get_returns_400_for_mismatched_redirect_uri() {
        let mut params = par_params();
        params["redirect_uri"] = "https://evil.example.com/callback".into();
        let resp = get_authorize_via_par(state_with_client().await, params).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_redirects_with_error_for_wrong_response_type() {
        // response_type check happens after redirect_uri validation — redirects, not error page.
        let mut params = par_params();
        params["response_type"] = "token".into();
        let resp = get_authorize_via_par(state_with_client().await, params).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
    }

    #[tokio::test]
    async fn get_redirects_with_error_for_non_s256_challenge_method() {
        let mut params = par_params();
        params["code_challenge_method"] = "plain".into();
        let resp = get_authorize_via_par(state_with_client().await, params).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn get_consent_page_contains_client_name() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Test App"),
            "client_name should appear in the consent page"
        );
    }

    #[tokio::test]
    async fn get_consent_page_falls_back_to_client_id_when_no_client_name() {
        let state = test_state().await;
        let metadata_no_name = r#"{"redirect_uris":["https://app.example.com/callback"]}"#;
        register_oauth_client(&state.db, CLIENT_ID, metadata_no_name)
            .await
            .unwrap();
        let resp = get_authorize_via_par(state, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("app.example.com"),
            "client_id should appear when client_name is absent"
        );
    }

    #[tokio::test]
    async fn get_consent_page_escapes_xss_in_client_name() {
        let state = test_state().await;
        let xss_metadata = r#"{"redirect_uris":["https://app.example.com/callback"],"client_name":"<script>alert(1)</script>"}"#;
        register_oauth_client(&state.db, CLIENT_ID, xss_metadata)
            .await
            .unwrap();
        let resp = get_authorize_via_par(state, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        // The page carries a legitimate inline poll <script> for the wallet path, so assert on the
        // specific attacker payload rather than any <script>: the injected client_name must be
        // HTML-escaped, never reflected raw.
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw injected script must not appear in output"
        );
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "injected script tag must be HTML-escaped"
        );
    }

    #[tokio::test]
    async fn get_consent_page_rejects_malformed_scope_instead_of_rendering_it() {
        // scope=<b>bold</b> in the stored request — not a valid scope (no `atproto` base,
        // not a recognized token). `expand_include_scopes`'s embedded `normalize_scope_request`
        // validates the GET path's scope too, so this is rejected via redirect before ever
        // reaching render — a stronger property than merely escaping malicious/malformed content.
        let mut params = par_params();
        params["scope"] = "<b>bold</b>".into();
        let resp = get_authorize_via_par(state_with_client().await, params).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_scope"), "got: {location}");
        assert!(
            !location.contains("<b>"),
            "raw HTML tags must not appear anywhere in the response"
        );
    }

    /// The push recipient is resolved from the client-supplied `login_hint` with LOCAL lookups
    /// only — a handle goes through the local `handles` table, never outbound resolution (the
    /// hint is attacker-suppliable on an unauthenticated surface), and only an active local
    /// account qualifies.
    #[tokio::test]
    async fn login_hint_resolves_only_local_active_accounts_for_push() {
        let state = state_with_client_and_mobile_account().await;

        // A DID hint for the hosted account resolves; decoration-tolerant handle forms resolve.
        for hint in [DID, TEST_HANDLE, "@Alice.Test", "at://alice.test"] {
            assert_eq!(
                resolve_login_hint_to_local_did(&state, hint)
                    .await
                    .as_deref(),
                Some(DID),
                "hint {hint:?} should bind the local account"
            );
        }
        // Unknown handle, foreign DID, and structural junk resolve to nothing.
        for hint in [
            "nobody.example.com",
            "did:plc:someoneelse0000000000000",
            "not a handle",
        ] {
            assert_eq!(
                resolve_login_hint_to_local_did(&state, hint).await,
                None,
                "hint {hint:?} must not name a push target"
            );
        }
        // A deactivated account is not a push target.
        sqlx::query("UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ?")
            .bind(DID)
            .execute(&state.db)
            .await
            .unwrap();
        assert_eq!(resolve_login_hint_to_local_did(&state, DID).await, None);
    }

    /// With no notification relay configured, a hinted login changes nothing: no match code is
    /// latched, the page renders no number panel, and the Phase A/B channels are untouched.
    #[tokio::test]
    async fn hinted_login_without_a_relay_requires_no_number() {
        let state = state_with_client_and_mobile_account().await;
        let mut params = par_params();
        params["login_hint"] = TEST_HANDLE.into();
        let resp = get_authorize_via_par(state.clone(), params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            !html.contains("id=\"match-code\""),
            "no number panel without a dispatched push"
        );
        let match_codes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pending_oauth_authorizations WHERE match_code IS NOT NULL",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(match_codes, 0);
    }

    #[tokio::test]
    async fn get_consent_page_creates_pending_request_and_renders_wallet_path() {
        let state = state_with_client().await;
        let resp = get_authorize_via_par(state.clone(), par_params()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        // The wallet path renders: section heading, a request-id data attribute, and the poller.
        assert!(
            html.contains("Approve in your wallet"),
            "wallet section must render"
        );
        assert!(
            html.contains("data-request-id=\"poauth_"),
            "wallet block must carry the pending request_id"
        );
        assert!(
            html.contains("/oauth/authorize/status?request_id="),
            "the poll script must target the status endpoint"
        );
        // A single-use pending request row was created for this consent load.
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pending_oauth_authorizations WHERE status = 'pending'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(pending, 1);
    }

    #[tokio::test]
    async fn get_consent_page_contains_scope_tag() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("atproto"),
            "requested scope should appear in the consent page"
        );
    }

    #[tokio::test]
    async fn get_consent_page_has_approve_and_deny_buttons() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("value=\"approve\""));
        assert!(html.contains("value=\"deny\""));
    }

    #[tokio::test]
    async fn get_consent_page_has_hidden_inputs_with_request_values() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("name=\"state\""));
        assert!(html.contains("name=\"code_challenge\""));
        assert!(html.contains("name=\"redirect_uri\""));
        assert!(html.contains("name=\"response_type\""));
    }

    // ── POST tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn post_deny_redirects_with_access_denied() {
        let resp = post_authorize(state_with_client_and_account().await, deny_form()).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(location.contains("state=teststate"));
        // RFC 9207 iss must be present on error responses too (test_state issuer).
        assert!(
            location.contains("iss=https%3A%2F%2Ftest.example.com"),
            "error response must carry the iss parameter: {location}"
        );
    }

    #[tokio::test]
    async fn post_deny_with_tampered_redirect_uri_returns_400() {
        // Tampered redirect_uri fails DB validation before the deny redirect is issued.
        let body = deny_form().replace(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
            "redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "tampered redirect_uri must return an error page, not redirect to attacker URI"
        );
    }

    #[tokio::test]
    async fn post_invalid_action_redirects_with_invalid_request() {
        let body = approve_form("").replace("action=approve", "action=blah");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn post_approve_redirects_with_code() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with(REDIRECT_URI));
        assert!(location.contains("code="));
        assert!(location.contains("state=teststate"));
        assert!(!location.contains("error="));
        // RFC 9207 iss must be present on the successful authorization response so a
        // conformant client (which the AS metadata told to expect it) accepts the code.
        assert!(
            location.contains("iss=https%3A%2F%2Ftest.example.com"),
            "success response must carry the iss parameter: {location}"
        );
    }

    #[tokio::test]
    async fn post_approve_stores_hashed_code_in_db() {
        // The DB stores the SHA-256 hash of the code; the plaintext goes in the redirect URL.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let db = state.db.clone();
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let code_hash = hash_bearer_token(code_from_location(location)).unwrap();

        let row: Option<(String,)> =
            sqlx::query_as("SELECT code FROM oauth_authorization_codes WHERE code = ?")
                .bind(&code_hash)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(row.is_some(), "DB must store the hash, not the plaintext");
    }

    #[tokio::test]
    async fn post_approve_encodes_special_chars_in_state() {
        // state with &, =, spaces must be percent-encoded in the Location header.
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD)
            .replace("state=teststate", "state=a%26b%3Dc%20d");
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        // a&b=c d percent-encoded: a%26b%3Dc%20d
        assert!(
            location.contains("state=a%26b%3Dc%20d"),
            "special chars in state must be percent-encoded: {location}"
        );
    }

    #[tokio::test]
    async fn post_approve_redirects_with_error_for_non_s256_method() {
        let body =
            approve_form("").replace("code_challenge_method=S256", "code_challenge_method=plain");
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn post_approve_without_credentials_rerenders_form() {
        // No identifier submitted → re-render the consent page asking the user to identify
        // themselves. The client never sees a denial; the user can try again.
        let resp = post_authorize(state_with_client().await, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "should re-render the consent form with credential fields"
        );
    }

    // ── Credential-gate tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn get_consent_page_renders_identifier_input() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("name=\"identifier\""),
            "consent page must have identifier input"
        );
    }

    #[tokio::test]
    async fn get_consent_page_renders_password_input() {
        let resp = get_authorize_via_par(state_with_client().await, par_params()).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "consent page must have a password input"
        );
    }

    #[tokio::test]
    async fn get_consent_page_prepopulates_identifier_from_login_hint() {
        let mut params = par_params();
        params["login_hint"] = "alice.test".into();
        let resp = get_authorize_via_par(state_with_client().await, params).await;
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("alice.test"),
            "login_hint value should appear in the identifier input"
        );
    }

    #[tokio::test]
    async fn post_approve_with_valid_credentials_redirects_with_code() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with(REDIRECT_URI));
        assert!(location.contains("code="));
        assert!(!location.contains("error="));
    }

    #[tokio::test]
    async fn post_approve_with_wrong_password_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(TEST_HANDLE, "wrongpassword");
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("That handle and password didn&#39;t match. Check them and try again."),
            "exact error message must appear"
        );
        assert!(
            html.contains(TEST_HANDLE),
            "identifier should be pre-populated on re-render so the user can correct only the password"
        );
    }

    #[tokio::test]
    async fn post_approve_with_unknown_identifier_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials("nobody.test", TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("That handle and password didn&#39;t match. Check them and try again."),
            "must show same message as wrong-password to prevent enumeration"
        );
    }

    #[tokio::test]
    async fn post_approve_without_identifier_rerenders_consent_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(state, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("type=\"password\""),
            "should re-render the consent form"
        );
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_tampered_redirect_uri() {
        let body = approve_form("").replace(
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
            "redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_tampered_client_id() {
        let body = approve_form("").replace(
            "client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json",
            "client_id=https%3A%2F%2Fevil.example.com%2Fclient-metadata.json",
        );
        let resp = post_authorize(state_with_client_and_account().await, &body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_approve_returns_400_for_malformed_client_metadata() {
        let state = test_state().await;
        register_oauth_client(&state.db, CLIENT_ID, "not valid json")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(DID)
        .bind("test@example.com")
        .execute(&state.db)
        .await
        .unwrap();
        let resp = post_authorize(state, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Additional credential-gate tests ──────────────────────────────────────

    #[tokio::test]
    async fn post_approve_with_mobile_account_rerenders_consent_page() {
        // Mobile accounts have NULL password_hash — they can't log in via the consent page.
        let state = state_with_client_and_mobile_account().await;
        let body = approve_form_with_credentials(TEST_HANDLE, "anypassword");
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("That handle and password didn&#39;t match. Check them and try again."),
            "mobile account (NULL password_hash) must not pass the credential gate"
        );
    }

    #[tokio::test]
    async fn post_approve_with_deactivated_account_rerenders_consent_page() {
        let state = state_with_client_and_deactivated_account().await;
        let body = approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("That handle and password didn&#39;t match. Check them and try again."),
            "deactivated account must be rejected with the same message as unknown identifier"
        );
    }

    #[tokio::test]
    async fn post_approve_with_did_identifier_redirects_with_code() {
        // The DID branch of resolve_identifier must also work through the OAuth consent path.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let body = approve_form_with_credentials(DID, TEST_PASSWORD);
        let resp = post_authorize(state, &body).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(!location.contains("error="));
    }

    #[tokio::test]
    async fn post_approve_rate_limited_rerenders_form() {
        use crate::auth::rate_limit::RATE_LIMIT_MAX_FAILURES;
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        // Exhaust the failure budget.
        for _ in 0..RATE_LIMIT_MAX_FAILURES {
            post_authorize(
                state.clone(),
                &approve_form_with_credentials(TEST_HANDLE, "wrongpassword"),
            )
            .await;
        }
        // Next attempt must be rate-limited — the form re-renders with a rate-limit message.
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, "wrongpassword"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            html.contains("Too many"),
            "rate-limited attempt must show a rate-limit message, not an auth error"
        );
    }

    // ── PAR (Pushed Authorization Request) flow ───────────────────────────────

    #[tokio::test]
    async fn get_authorization_with_valid_request_uri_renders_consent_page() {
        let state = state_with_client().await;
        let response = get_authorize_via_par(state, par_params()).await;

        assert_eq!(response.status(), StatusCode::OK);
        let html = body_string(response).await;
        assert!(
            html.contains("Test App"),
            "consent page should show the registered client name"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_invalid_request_uri_returns_error_page() {
        let state = state_with_client().await;

        let response = get_authorize(
            state,
            &format!(
                "/oauth/authorize?client_id={}&request_uri=urn:ietf:params:oauth:request_uri:nonexistent",
                CLIENT_ID
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = body_string(response).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "invalid request_uri should render an error page"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_expired_request_uri_returns_error_page() {
        let state = state_with_client().await;

        // Insert a PAR request that is already expired.
        sqlx::query(
            "INSERT INTO oauth_par_requests \
             (request_uri, client_id, request_parameters, expires_at, created_at) \
             VALUES (?, ?, ?, datetime('now', '-1 seconds'), datetime('now'))",
        )
        .bind("urn:ietf:params:oauth:request_uri:formerly-valid-expired")
        .bind(CLIENT_ID)
        .bind(par_params().to_string())
        .execute(&state.db)
        .await
        .unwrap();

        let response = get_authorize(
            state,
            &format!(
                "/oauth/authorize?client_id={}&request_uri=urn:ietf:params:oauth:request_uri:formerly-valid-expired",
                CLIENT_ID
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = body_string(response).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "expired request_uri should render an error page"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_par_forwards_login_hint_to_consent_page() {
        let state = state_with_client().await;
        let mut params = par_params();
        params["login_hint"] = "alice.example.com".into();
        let response = get_authorize_via_par(state, params).await;

        assert_eq!(response.status(), StatusCode::OK);
        let html = body_string(response).await;
        assert!(
            html.contains("alice.example.com"),
            "login_hint from PAR should pre-populate the identifier field on the consent page"
        );
    }

    #[tokio::test]
    async fn get_authorization_without_request_uri_is_rejected() {
        // The metadata advertises require_pushed_authorization_requests: true — a direct
        // authorization request with inline parameters must be refused at flow start,
        // with no consent page and no pending wallet request created.
        let state = state_with_client().await;
        let response = get_authorize(
            state.clone(),
            &format!(
                "/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_challenge=abc&code_challenge_method=S256&state=s&response_type=code&scope=atproto",
                urlencoding::encode(CLIENT_ID)
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = body_string(response).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "a non-PAR request must get the no-redirect error page"
        );
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_oauth_authorizations")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(
            pending, 0,
            "a rejected request must not create consent state"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_jar_request_parameter_is_rejected() {
        // request_parameter_supported: false is advertised — a JAR `request` object must be
        // rejected, not silently ignored, even alongside a valid request_uri. The rejection
        // happens before the PAR row is consumed, so the single-use row survives.
        let state = state_with_client().await;
        let params = par_params();
        let url = authorize_url_via_par(&state, &params).await;
        let response = get_authorize(
            state.clone(),
            &format!("{url}&request=eyJhbGciOiJub25lIn0.e30."),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = body_string(response).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "a JAR request must get the no-redirect error page"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_par_requests")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(
            rows, 1,
            "the pushed request must not be consumed by the rejection"
        );
    }

    #[tokio::test]
    async fn get_authorization_with_mismatched_client_id_returns_error_page() {
        let state = state_with_client().await;
        let url = authorize_url_via_par(&state, &par_params()).await;
        let request_uri = url.split("request_uri=").nth(1).unwrap();

        let response = get_authorize(
            state,
            &format!("/oauth/authorize?client_id=https://other.example.com/client&request_uri={request_uri}"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = body_string(response).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "mismatched client_id should render an error page"
        );
    }

    // ── include: permission-set expansion ─────

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::routes::test_utils::{seed_did_document, FixedTxtResolver};

    const AUTHORITY_DID: &str = "did:plc:authoritydidxxxxxxxxxxxxx";
    const AUTHORITY_NSID: &str = "app.bsky.authFull";

    /// A test state with a registered client + password account, plus DNS/DID-document
    /// resolution wired up for `AUTHORITY_NSID` to a mock PDS serving `schema`.
    async fn state_with_include_authority(
        schema: serde_json::Value,
    ) -> (crate::app::AppState, MockServer) {
        let server = MockServer::start().await;
        let base = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let state = crate::app::AppState {
            txt_resolver: Some(std::sync::Arc::new(FixedTxtResolver {
                records: vec![format!("did={AUTHORITY_DID}")],
            })),
            ..base
        };
        seed_did_document(
            &state.db,
            AUTHORITY_DID,
            serde_json::json!({
                "id": AUTHORITY_DID,
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": server.uri(),
                }],
            }),
        )
        .await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": format!("at://{AUTHORITY_DID}/com.atproto.lexicon.schema/{AUTHORITY_NSID}"),
                "cid": "bafyreictest",
                "value": {
                    "lexicon": 1,
                    "id": AUTHORITY_NSID,
                    "defs": {
                        "main": {
                            "type": "permission-set",
                            "permissions": schema,
                        }
                    }
                },
            })))
            .mount(&server)
            .await;

        (state, server)
    }

    /// `granted` simulates which checkboxes a real browser would submit still checked —
    /// `post_authorization` only grants a non-`atproto` token if it's present here.
    fn include_scope_form(scope: &str, granted: &[&str]) -> String {
        let granted_params: String = granted
            .iter()
            .map(|g| format!("&granted_scope={}", urlencoding::encode(g)))
            .collect();
        format!(
            "action=approve\
             &client_id=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_challenge=e3b0c44298fc1c149afb\
             &code_challenge_method=S256\
             &state=teststate\
             &scope={}\
             &response_type=code\
             &identifier={}&password={}{}",
            urlencoding::encode(scope),
            urlencoding::encode(TEST_HANDLE),
            urlencoding::encode(TEST_PASSWORD),
            granted_params,
        )
    }

    #[tokio::test]
    async fn include_scope_stores_expanded_scope_on_authorization_code() {
        let (state, _server) = state_with_include_authority(serde_json::json!([
            { "type": "permission", "resource": "identity", "attr": "handle" }
        ]))
        .await;
        let db = state.db.clone();

        let scope = format!("atproto include:{AUTHORITY_NSID}");
        let resp = post_authorize(state, &include_scope_form(&scope, &["identity:handle"])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(!location.contains("error="), "unexpected error: {location}");

        assert_eq!(
            stored_scope_for(&db, location).await,
            "atproto identity:handle",
            "stored scope must be the expanded granular set, not the raw include: token"
        );
    }

    #[tokio::test]
    async fn consent_approve_with_transition_generic_checked_stores_it_on_the_code() {
        // The wallet's outbound-migration source login requests
        // "atproto transition:generic"; the consent page renders transition:generic as
        // a checked-by-default checkbox. Approving with it checked must store the full
        // scope on the code — this is the scope the migration orchestrator's
        // getServiceAuth call later depends on.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let db = state.db.clone();

        let resp = post_authorize(
            state,
            &include_scope_form("atproto transition:generic", &["transition:generic"]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(!location.contains("error="), "unexpected error: {location}");

        assert_eq!(
            stored_scope_for(&db, location).await,
            "atproto transition:generic"
        );
    }

    #[tokio::test]
    async fn unresolvable_include_scope_redirects_invalid_scope() {
        // No txt_resolver configured at all — the include: reference cannot resolve.
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let scope = "atproto include:app.bsky.authFull".to_string();
        let resp = post_authorize(state, &include_scope_form(&scope, &[])).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_scope"), "got: {location}");
    }

    #[tokio::test]
    async fn get_consent_page_shows_expanded_permissions_for_include_scope() {
        let (state, _server) = state_with_include_authority(serde_json::json!([
            { "type": "permission", "resource": "identity", "attr": "handle" }
        ]))
        .await;

        let mut params = par_params();
        params["scope"] = format!("atproto include:{AUTHORITY_NSID}").into();
        let resp = get_authorize_via_par(state, params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("identity:handle"),
            "consent page should show the expanded permission, not the raw include: token: {html}"
        );
        assert!(
            !html.contains("include:app.bsky.authFull"),
            "consent page should not show the unexpanded include: reference: {html}"
        );
    }

    #[tokio::test]
    async fn get_consent_page_redirects_invalid_scope_on_unresolvable_include_token() {
        // No txt_resolver configured — resolution fails. The page must redirect with an error
        // rather than falling back to rendering the raw include: token: a fallback here could
        // desync from what post_authorization later grants if the authority becomes reachable
        // by the time the user submits (see oauth-scopes-permission-sets design notes).
        let state = state_with_client().await;
        let mut params = par_params();
        params["scope"] = "atproto include:app.bsky.authFull".into();
        let resp = get_authorize_via_par(state, params).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_scope"), "got: {location}");
    }

    // ── Consent UI grouping + per-scope opt-out ──

    /// Extract the plaintext authorization code from a `Location` redirect's `code=` query param.
    fn code_from_location(location: &str) -> &str {
        location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
    }

    async fn stored_scope_for(db: &sqlx::SqlitePool, location: &str) -> String {
        let code_hash = hash_bearer_token(code_from_location(location)).unwrap();
        let row: (String,) =
            sqlx::query_as("SELECT scope FROM oauth_authorization_codes WHERE code = ?")
                .bind(&code_hash)
                .fetch_one(db)
                .await
                .unwrap();
        row.0
    }

    #[tokio::test]
    async fn consent_page_groups_permissions_by_resource_type() {
        let state = state_with_client().await;
        let mut params = par_params();
        params["scope"] = "atproto repo:app.bsky.feed.post identity:handle".into();
        let resp = get_authorize_via_par(state, params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32768).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("Repository writes"),
            "repo: scope should be grouped under a resource-type heading: {html}"
        );
        assert!(
            html.contains("Identity"),
            "identity: scope should be grouped under a resource-type heading: {html}"
        );
        assert!(
            html.contains("name=\"granted_scope\""),
            "should render checkboxes"
        );
        assert!(
            html.contains("value=\"repo:app.bsky.feed.post\" checked"),
            "checkboxes should default to checked: {html}"
        );
    }

    #[tokio::test]
    async fn unchecking_a_permission_excludes_it_from_the_granted_scope() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let db = state.db.clone();
        // Only identity:handle is submitted as granted — repo:app.bsky.feed.post was unchecked.
        let form = include_scope_form(
            "atproto repo:app.bsky.feed.post identity:handle",
            &["identity:handle"],
        );
        let resp = post_authorize(state, &form).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(!location.contains("error="), "unexpected error: {location}");
        assert_eq!(
            stored_scope_for(&db, location).await,
            "atproto identity:handle",
            "unchecked repo: scope must be excluded from the granted set"
        );
    }

    #[tokio::test]
    async fn atproto_cannot_be_unchecked() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let db = state.db.clone();
        // No granted_scope submitted at all — everything unchecked. atproto must still grant.
        let form = include_scope_form("atproto identity:handle", &[]);
        let resp = post_authorize(state, &form).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(!location.contains("error="), "unexpected error: {location}");
        assert_eq!(
            stored_scope_for(&db, location).await,
            "atproto",
            "atproto must remain granted even with nothing else checked"
        );
    }

    // ── response_mode (query vs fragment delivery) ────────────────────────────

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn fragment_response_mode_delivers_the_code_in_the_fragment() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let form = format!(
            "{}&response_mode=fragment",
            approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD)
        );
        let resp = post_authorize(state, &form).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://app.example.com/callback#code="),
            "fragment mode must answer in the URL fragment: {location}"
        );
        assert!(
            !location.contains('?'),
            "no query-string delivery in fragment mode: {location}"
        );
        assert!(location.contains("&state=teststate"), "{location}");
        assert!(location.contains("&iss="), "{location}");
    }

    #[tokio::test]
    async fn omitted_response_mode_still_answers_in_the_query_string() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let resp = post_authorize(
            state,
            &approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.starts_with("https://app.example.com/callback?code="),
            "query remains the default delivery: {location}"
        );
    }

    #[tokio::test]
    async fn get_carries_a_fragment_response_mode_into_the_consent_form() {
        let state = state_with_client().await;
        let mut params = par_params();
        params["response_mode"] = "fragment".into();
        let resp = get_authorize_via_par(state, params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(
            html.contains("name=\"response_mode\" value=\"fragment\""),
            "the consent form must round-trip the requested mode"
        );
    }

    #[tokio::test]
    async fn get_rejects_an_unsupported_response_mode() {
        // An unsupported mode in the stored PAR row (schema drift / hand-edited row —
        // the PAR endpoint validates before storing) still fails before any redirect.
        let state = state_with_client().await;
        let mut params = par_params();
        params["response_mode"] = "form_post".into();
        let resp = get_authorize_via_par(state, params).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let html = body_string(resp).await;
        assert!(
            html.contains("This sign-in request didn&#39;t work"),
            "the page carries the user-register copy; the parameter name goes to the log"
        );
    }

    #[tokio::test]
    async fn tampered_response_mode_hidden_field_gets_the_no_redirect_error_page() {
        let state = state_with_client_and_account_with_password(TEST_PASSWORD).await;
        let form = format!(
            "{}&response_mode=form_post",
            approve_form_with_credentials(TEST_HANDLE, TEST_PASSWORD)
        );
        let resp = post_authorize(state, &form).await;
        // An unknown delivery mode must not redirect anywhere.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Cache-only client lookup at the authorize endpoint ────────────────────

    #[tokio::test]
    async fn post_never_resolves_client_metadata_live() {
        // Registration happens at PAR; client lookup here is cache-only. The GET leg
        // can't even reach an unknown client (the PAR row's client_id is FK-bound to a
        // registered row), so the reachable case is a consent POST whose hidden,
        // attacker-controllable client_id names an unregistered URL — refused as
        // unknown, without attempting the live metadata fetch this endpoint used to
        // fall back to for non-PAR clients.
        let state = test_state().await; // CLIENT_ID not registered
        let resp = post_authorize(state, &approve_form("")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let html = body_string(resp).await;
        assert!(html.contains("This server doesn&#39;t recognize the app"));
    }

    #[tokio::test]
    async fn get_enforces_the_reverse_fqdn_rule_for_private_use_redirects() {
        // A registered discoverable client whose metadata lists a custom-scheme redirect
        // that does NOT reverse the client_id host — the authorize leg re-checks the
        // rule PAR enforces, so a stale/hand-edited row can't sidestep it.
        let state = test_state().await;
        register_oauth_client(
            &state.db,
            CLIENT_ID,
            r#"{"redirect_uris":["dev.other.app:/oauth/callback"],"client_name":"Test App"}"#,
        )
        .await
        .unwrap();

        let mut params = par_params();
        params["redirect_uri"] = "dev.other.app:/oauth/callback".into();
        let resp = get_authorize_via_par(state, params).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let html = body_string(resp).await;
        assert!(
            html.contains("com.example.app:"),
            "the rejection must name the required reverse-FQDN scheme"
        );
    }
}
