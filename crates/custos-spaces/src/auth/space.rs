// pattern: Mixed (unavoidable)

//! The authorization seam every `com.atproto.space.*` route enters through, and the Atproto
//! Spaces token machinery behind it (proposal 0016, "Access control").
//!
//! Routes may not import one another, and every space route needs identical admission rules,
//! so the rules live here once: authenticate the caller, confirm which repo it may touch, and
//! check the operation against its `space:` grant. Mixed because the `collection` a bare
//! `space:` grant covers is the space type declaration's, resolved over the network (DNS + HTTP)
//! per the spec's dynamic-resolution rule — the same reason `consent.rs`, whose
//! resolver this reuses, cannot be a pure Functional Core.
//!
//! The token flow:
//!
//! * **Delegation token** — the user's PDS mints it (`getDelegationToken`): an account-key JWT,
//!   `typ atproto-space-delegation+jwt`, `kid #atproto`, `sub` = space URI, `aud` = the
//!   authority's `#atproto_space_host`, single-use, ~60 s. [`mint_delegation_token`] /
//!   [`verify_delegation_token`] (the latter spends the `jti` in `space_jti_replay`).
//! * **Space credential** — the space authority mints it (`getSpaceCredential`) in exchange for
//!   a delegation token plus an RFC 9421 `atproto-space` signature over that request's
//!   `Authorization` (`auth/http_signature.rs`): `typ atproto-space-credential+jwt`, `kid
//!   #atproto_space`, no `aud`, `cnf.kid` = the signature's P-256 `did:key`, 10 min (a verifier
//!   accepts up to 60). [`mint_space_credential`] / [`verify_space_credential`] (the latter
//!   resolves the authority's key by `kid`: `#atproto_space` with the `#atproto` fallback, or
//!   `#atproto` only when the authority publishes no dedicated space key). The `jti` is a
//!   revocation id, not a nonce: a credential is reusable until it expires.
//! * **The read seam** — [`authenticate_space_read`] accepts a covering OAuth grant on the
//!   caller's *own* repo *or* a signature-bound space credential for any repo in the space,
//!   never a bearer credential. [`authenticate_space_access`] is the same pair of arms for a
//!   method that names a space but no repo (`simplespace.getSpace`), and
//!   [`authenticate_space_owner`] is the OAuth-only arm every simplespace management method
//!   *on an existing space* takes: grant check, then "the caller *is* the authority"
//!   (`NotSpaceOwner`). `createSpace` is the exception — a space anchored on the caller's own
//!   DID has no prior owner to check, so it takes [`authenticate_space_caller`] and the grant
//!   check alone. The credential arm takes `Authorization: Atproto-Space <credential>` plus an
//!   `atproto-space` signature over that header and `Atproto-Space-Audience`, verified against
//!   `cnf.kid`; the audience must be the DID the request is for (the repo owner on a repo read,
//!   the authority on a space-level one), which is what stops a credential captured at one repo
//!   host being replayed at another. Replay against the same audience is allowed until expiry,
//!   by spec. The compiler confines it: `verify_space_credential` is private to this module and
//!   `verify_space_signature` to `auth`, and the mint route's only signature check is
//!   `verify_delegation_signature`, so no route grows its own credential parsing.
//! * **The operator cut** — [`require_space_servable`] refuses a space the operator took down
//!   (V070), the per-space counterpart to [`require_serviceable_caller`]'s account-level one and
//!   the only lever that reaches a space whose authority is a foreign server. Every seam above
//!   applies it *after* authenticating, and the write choke point re-reads the same row inside
//!   its commit transaction.
//!
//! * **Credential issuance policy** — [`authorize_credential_request`] is the two-perimeter gate
//!   behind `getSpaceCredential`: the `appAccess` axis (`open`, or an `allowList` matched against
//!   the client_id `auth::client_attestation` verified) and then the `policy` axis (`public`,
//!   `member-list`, or `managing-app`, which asks the configured app over service auth and denies
//!   on any failure to get an answer).
//!
//! Both account-key-signed token shapes share `jwt.rs`'s [`sign_jwt`] / [`verify_did_key_jwt`]
//! core with service auth.

use axum::http::{HeaderMap, Method, Uri};
use common::{ApiError, ApiResultExt, ErrorCode};
use serde_json::Value;

use crate::db::accounts::{active_local_account_exists, AccountLifecycle};
use crate::db::space_jti::{insert_jti_if_absent, SpaceJtiScope};
use crate::db::spaces::{self, SpaceRow};
use crate::identity::resolution::{
    atproto_verification_key, dedicated_space_verification_key,
    refresh_did_document_after_signature_mismatch, resolve_did_document, service_endpoint,
    space_verification_key,
};
use crate::space_uri::SpaceRef;
use crate::SpacesState;

use super::bearer::{extract_access_token, extract_space_credential};
use super::extractors::AuthenticatedUser;
use super::http_signature::{verify_space_signature, SignedFor};
use super::jwt::{
    peek_jwt_iss, peek_jwt_typ, random_jti, sign_jwt, verify_did_key_jwt, AuthScope, DidKeyJwt,
    ServiceAuthError,
};
use super::oauth_scopes::{self, SpaceOp, SpaceRequest};

/// JWT `typ` of a delegation token.
pub const DELEGATION_TOKEN_TYP: &str = "atproto-space-delegation+jwt";
/// JWT `typ` of a space credential.
pub const SPACE_CREDENTIAL_TYP: &str = "atproto-space-credential+jwt";
/// Lifetime of a delegation token this server mints (the proposal's default).
pub const DELEGATION_TOKEN_TTL_SECS: u64 = 60;
/// Longest remaining lifetime accepted on an inbound delegation token — also the horizon its
/// spent `jti` is retained for, so a token can never outlive its replay row.
pub const DELEGATION_TOKEN_MAX_TTL_SECS: u64 = 5 * 60;
/// Lifetime of a space credential this server mints (the proposal's default).
pub const SPACE_CREDENTIAL_TTL_SECS: u64 = 10 * 60;
/// Longest `exp − iat` accepted on an inbound space credential (the proposal's cap).
pub const SPACE_CREDENTIAL_MAX_TTL_SECS: u64 = 60 * 60;
/// Clock skew tolerated on an inbound credential's `iat` (the reference's).
const CLOCK_SKEW_SECS: u64 = 5;

/// How long a `notifyCredentialRevoked` revocation is kept: past the last instant any credential
/// carrying the jti could verify (issued up to the skew ahead, living at most the maximum TTL).
pub const CREDENTIAL_REVOCATION_RETENTION_SECS: u64 =
    SPACE_CREDENTIAL_MAX_TTL_SECS + CLOCK_SKEW_SECS;

/// The delegation-token audience for `space`: its authority's space-host service reference.
pub fn space_host_aud(space: &SpaceRef) -> String {
    format!("{}#atproto_space_host", space.authority)
}

// ── OAuth admission ──────────────────────────────────────────────────────────

/// Authenticate a caller of a space method that names no one repo (`listSpaces`).
///
/// Runs the shared access-auth path, so the RFC 9449 scheme ↔ `cnf.jkt` binding rules are
/// identical to every other authenticated route's, and then applies the account-lifecycle
/// gate below. Every account-credential arm of every space and simplespace seam routes
/// through here, so this is the one place the gate has to hold.
pub async fn authenticate_space_caller(
    state: &SpacesState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<AuthenticatedUser, ApiError> {
    let user = crate::auth::authenticate_access(headers, method, uri, state)?;
    if !user.scope.is_access() {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "access token required",
        ));
    }

    require_serviceable_caller(state, &user.did).await?;
    Ok(user)
}

/// The account-lifecycle gate every space call made on an account's own credential passes.
///
/// A valid token is not enough: an account that was removed or put into a moderation state
/// (suspension/takedown) loses its space surface exactly as it loses the public one. A
/// self-service-deactivated account is deliberately still admitted — that is the migration
/// window, the same line `getPreferences`/`putPreferences` draw, and it is what lets a
/// deactivated destination account import its space repos before `activateAccount`. Writes
/// stay narrower than this: `space_record_write` refuses every non-active state inside its
/// commit transaction, so deactivation remains read-only for ordinary writes.
///
/// Called from [`authenticate_space_caller`], and directly by `getDelegationToken` — the one
/// space route that authenticates through the bare `AuthenticatedUser` extractor, because it
/// names a space this server need not host.
pub async fn require_serviceable_caller(state: &SpacesState, did: &str) -> Result<(), ApiError> {
    match crate::db::accounts::account_lifecycle(&state.db, did).await? {
        Some(AccountLifecycle::Active | AccountLifecycle::Deactivated) => Ok(()),
        _ => {
            tracing::warn!(did = %did, "space call: account missing or in a moderation state");
            Err(ApiError::new(ErrorCode::InvalidToken, "account not found"))
        }
    }
}

/// Authenticate a space *write* and confirm the caller owns the repo it names.
///
/// Writes are OAuth-only by spec — a space credential is a read/sync capability the authority
/// issues to syncers, never a licence to write into someone else's repo — so there is no second
/// credential branch here, unlike [`authenticate_space_read`].
pub async fn authenticate_space_write(
    state: &SpacesState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    repo: &str,
) -> Result<AuthenticatedUser, ApiError> {
    let user = authenticate_space_caller(state, headers, method, uri).await?;
    if user.did != repo {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "repo must match authenticated user",
        ));
    }
    Ok(user)
}

/// Who a space read was authenticated as.
// The read routes need only the verdict, so nothing in production destructures the arms —
// they exist so a test can assert *which* arm admitted a request, and which credential it
// was bound to. Dropping the payloads would drop that assertion with them.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SpaceReader {
    /// An account reading its own repo under an OAuth (or legacy) session.
    User(AuthenticatedUser),
    /// A syncer holding a space credential for the space, its `cnf.kid` signature verified for
    /// this request and audience. May read any repo in the space on this host.
    Credential(VerifiedCredential),
}

/// Authenticate a space *read* of one account's repo, and authorize it.
///
/// Two arms, never a bearer credential:
///
/// * An **account credential** (OAuth or legacy session) reads only that account's own repo,
///   under a `read`/`read_self` grant. A caller naming someone else's repo gets the same
///   `RepoNotFound` an absent repo gets, on purpose: whether a given account holds a repo in a
///   space is not a fact a caller without read access to that space is entitled to learn.
/// * A **space credential** — `Authorization: Atproto-Space <credential>` plus its signature —
///   reads any repo in the space it names. Only the authority issues one, and only after
///   deciding the holder may read the space; a repo host keeps no member list of its own to
///   consult. The request's audience must be `repo` (see [`authenticate_space_credential`]).
///   Because this caller is not the owner, the repo must be an active local account's: a
///   deactivated or taken-down owner's repo reads as `RepoNotFound` here, where the owner could
///   still read it.
pub async fn authenticate_space_read(
    state: &SpacesState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    space: &SpaceRef,
    repo: &str,
) -> Result<SpaceReader, ApiError> {
    let Some(token) = presented_space_credential(headers)? else {
        let user = authenticate_space_caller(state, headers, method, uri).await?;
        if user.did != repo {
            return Err(repo_not_found(repo));
        }
        require_space_grant(state, &user, space, SpaceOp::ReadSelf).await?;
        require_space_servable(state, space).await?;
        return Ok(SpaceReader::User(user));
    };

    let credential = authenticate_space_credential(state, headers, token, space, repo).await?;

    require_space_servable(state, space).await?;

    // Repo availability: the owner may read their own deactivated repo, a syncer may not.
    if !active_local_account_exists(&state.db, repo).await? {
        return Err(repo_not_found(repo));
    }

    Ok(SpaceReader::Credential(credential))
}

/// Authenticate access to a space *itself* (no repo named — `simplespace.getSpace`).
///
/// The same two arms as [`authenticate_space_read`]: an account credential must carry a
/// `read_self` grant for the space *and* belong to the space's authority (the reference's
/// `assertSpaceScope` + `assertSpaceOwner` — a member hosted here still presents a space
/// credential, like a member hosted anywhere else); a space credential for the space is
/// accepted when its signature is addressed to the authority.
///
/// This is the space-*host* seam — every route behind it answers only for a space anchored on
/// a local account — so the credential arm additionally requires that authority to be an
/// active account. A syncer holding a still-valid credential stops being served the moment the
/// authority is deactivated, suspended, or taken down, exactly as public sync stops serving a
/// non-active repo. The owner's own arm is one step wider (moderation states only, per
/// [`authenticate_space_caller`]), so a deactivated authority can still manage its own spaces
/// through the migration window.
pub async fn authenticate_space_access(
    state: &SpacesState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    space: &SpaceRef,
) -> Result<SpaceReader, ApiError> {
    let Some(token) = presented_space_credential(headers)? else {
        let user =
            authenticate_space_owner(state, headers, method, uri, space, SpaceOp::ReadSelf).await?;
        return Ok(SpaceReader::User(user));
    };
    let credential =
        authenticate_space_credential(state, headers, token, space, &space.authority).await?;
    require_serviceable_authority(state, space).await?;
    require_space_servable(state, space).await?;
    Ok(SpaceReader::Credential(credential))
}

/// Refuse to serve a space the operator has taken down (V070).
///
/// The per-space counterpart to [`require_serviceable_caller`]'s account-level cut, and the
/// only lever that reaches a space whose *authority* is a foreign server: this host stores
/// members' repos in such a space (`space_record_write` records the row on their first write),
/// so it can be serving content it has no `deleteSpace` of its own to stop.
///
/// `SpaceNotFound`, never `SpaceDeleted`, for the same reason
/// [`require_serviceable_authority`] answers that way: `SpaceDeleted` is the spec's durable
/// "drop your copy" signal, and a takedown is reversible. It is also the reply an unknown
/// space gets, so which spaces an operator refuses is not disclosed. Called *after*
/// authentication at every seam, so it can never become an unauthenticated probe.
///
/// Writes are not checked here — `space_record_write`'s choke point reads the same row inside
/// its commit transaction, where a concurrent takedown cannot land between check and commit.
pub async fn require_space_servable(state: &SpacesState, space: &SpaceRef) -> Result<(), ApiError> {
    let taken_down = spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .is_some_and(|row| row.takendown_at.is_some());
    if !taken_down {
        return Ok(());
    }
    tracing::warn!(space = %space.uri, "space host: space is taken down by the operator");
    Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"))
}

/// Refuse to act as space host for an authority that is no longer an active local account.
///
/// `SpaceNotFound` on purpose, never `SpaceDeleted`: the spec makes `SpaceDeleted` the durable
/// signal that a syncer must drop its copy, and a suspension or a migration window is not that.
/// Every other failure "means nothing", which is exactly the right thing for a state that can
/// be reversed.
pub async fn require_serviceable_authority(
    state: &SpacesState,
    space: &SpaceRef,
) -> Result<(), ApiError> {
    if active_local_account_exists(&state.db, &space.authority).await? {
        return Ok(());
    }
    tracing::warn!(
        space = %space.uri,
        authority = %space.authority,
        "space host: authority is not an active local account"
    );
    Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"))
}

/// Authenticate a simplespace management call (or owner-only read): an account credential
/// whose grant covers `op` on `space`, held by the space's authority.
///
/// Grant first, ownership second, as the reference orders them: an app without the `manage`
/// grant learns `InsufficientScope` whether or not the space is its user's. Not the
/// authority is `NotSpaceOwner` — a precondition failure, not an authentication one.
pub async fn authenticate_space_owner(
    state: &SpacesState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    space: &SpaceRef,
    op: SpaceOp<'_>,
) -> Result<AuthenticatedUser, ApiError> {
    let user = authenticate_space_caller(state, headers, method, uri).await?;
    require_space_grant(state, &user, space, op).await?;
    if user.did != space.authority {
        return Err(ApiError::new(
            ErrorCode::NotSpaceOwner,
            "not the space owner",
        ));
    }
    // Last, so the owner of a taken-down space learns no more than a stranger does. Applies to
    // `deleteSpace` too: the operator's refusal already stops the space being served, and a
    // restore has to be able to put it back exactly as it was.
    require_space_servable(state, space).await?;
    Ok(user)
}

/// The space credential a request presents, if it takes the credential arm at all: the token
/// in `Authorization: Atproto-Space <credential>`. A space credential under any other scheme is
/// refused outright rather than handed to the OAuth arm — that is the pre-RFC 9421 DPoP shape,
/// and naming it is kinder than the OAuth arm's generic signature failure.
fn presented_space_credential(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    if let Some(token) = extract_space_credential(headers) {
        return Ok(Some(token));
    }
    if let Ok((_, token)) = extract_access_token(headers) {
        if peek_jwt_typ(token).as_deref() == Some(SPACE_CREDENTIAL_TYP) {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "space credential must use the Atproto-Space authorization scheme",
            ));
        }
    }
    Ok(None)
}

/// The credential arm shared by the seams above: `token` (from `Authorization: Atproto-Space`)
/// must be a credential for `space`, and the request must carry an `atproto-space` signature
/// over `Authorization` and `Atproto-Space-Audience` by the credential's `cnf.kid`, with that
/// audience equal to `audience` — the DID this request is for. No nonce and no replay store:
/// the audience is the binding, and reuse against it is allowed until the credential expires.
async fn authenticate_space_credential(
    state: &SpacesState,
    headers: &HeaderMap,
    token: &str,
    space: &SpaceRef,
    audience: &str,
) -> Result<VerifiedCredential, ApiError> {
    // Cheap pre-filter on the unverified `sub`, so a credential for some other space cannot
    // drive DID resolution (a cache miss plus the force-refresh retry is two upstream fetches
    // per request) before it is thrown out. The authoritative comparison follows verification.
    if peek_jwt_payload(token)
        .and_then(|p| p.get("sub").and_then(Value::as_str).map(str::to_string))
        .as_deref()
        != Some(space.uri.as_str())
    {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "space credential is for a different space",
        ));
    }

    let credential = verify_space_credential(state, token, unix_now()?).await?;
    if credential.space.uri != space.uri {
        return Err(ApiError::new(
            ErrorCode::InvalidToken,
            "space credential is for a different space",
        ));
    }

    verify_space_signature(
        headers,
        SignedFor::Credential {
            key_id: &credential.kid,
            audience,
        },
    )?;

    // Charged last, on the *verified* key, so unauthenticated garbage cannot drain a holder's
    // budget.
    state
        .rate_limiter
        .check_space_credential(&credential.kid)
        .inspect_err(|_| {
            state.metrics.rate_limit_rejections.add(
                1,
                &[crate::metrics::label(
                    crate::metrics::names::LABEL_LIMITER,
                    "space_credential",
                )],
            );
        })?;

    Ok(credential)
}

/// The `RepoNotFound` a space read answers with, whether the repo is absent or merely not the
/// caller's. One reply for both, so the two cannot be told apart.
pub fn repo_not_found(repo: &str) -> ApiError {
    ApiError::new(
        ErrorCode::RepoNotFound,
        format!("could not find repo for DID: {repo}"),
    )
}

/// Check one space operation against the caller's `space:` grant.
///
/// Legacy access tokens — a full session or an app password — carry no space grants at all, so
/// there is nothing to evaluate; they are bounded instead by the repo-ownership check above,
/// which is exactly how the reference bounds them. Only an OAuth grant reaches the matcher.
pub async fn require_space_grant(
    state: &SpacesState,
    user: &AuthenticatedUser,
    space: &SpaceRef,
    op: SpaceOp<'_>,
) -> Result<(), ApiError> {
    if user.scope != AuthScope::Access {
        return Ok(());
    }

    // First pass with no declaration. A grant that names its own `collection`, and every
    // non-record operation (read is all-or-nothing at the space boundary), is decided here —
    // which is what keeps the resolution below off the hot path of an ordinary write.
    if oauth_scopes::require_space(
        &user.scope_claim,
        &SpaceRequest {
            space_type: &space.space_type,
            authority: &space.authority,
            skey: &space.skey,
            op,
            account_did: &user.did,
            declared_collections: &[],
        },
    )
    .is_ok()
    {
        return Ok(());
    }

    // Only a record write against a grant that named no `collection` can still pass, by falling
    // back to the space type declaration's `collections`. Resolved per request rather than
    // frozen at consent time, so a declaration that later adds a collection widens grants that
    // are already outstanding.
    let SpaceOp::Record { .. } = op else {
        return Err(insufficient_space_scope());
    };
    let declared = custos_core::scope_display::resolve_space_type_cached(
        state,
        &state.space_type_cache,
        &space.space_type,
    )
    .await
    .map(|decl| decl.collections)
    .unwrap_or_else(|message| {
        // Fail closed: an unresolvable declaration confers no write target. Logged rather than
        // surfaced, because the caller learns nothing useful from a third party's outage.
        tracing::warn!(
            space_type = %space.space_type,
            %message,
            "could not resolve space type declaration; treating its collection set as empty"
        );
        Vec::new()
    });

    oauth_scopes::require_space(
        &user.scope_claim,
        &SpaceRequest {
            space_type: &space.space_type,
            authority: &space.authority,
            skey: &space.skey,
            op,
            account_did: &user.did,
            declared_collections: &declared,
        },
    )
}

fn insufficient_space_scope() -> ApiError {
    ApiError::new(
        ErrorCode::InsufficientScope,
        "token scope does not permit this space operation",
    )
}

// ── Delegation tokens ────────────────────────────────────────────────────────

/// Mint a delegation token for `space` on behalf of `user_did`, signed by the account's
/// `#atproto` key via `sign` (a low-S 64-byte ES256 signature — `CommitSigner::sign`).
pub fn mint_delegation_token<F>(sign: F, user_did: &str, space: &SpaceRef, now: u64) -> String
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    let header = serde_json::json!({
        "typ": DELEGATION_TOKEN_TYP,
        "alg": "ES256",
        "kid": "#atproto",
    });
    let payload = serde_json::json!({
        "iss": user_did,
        "sub": space.uri,
        "aud": space_host_aud(space),
        "iat": now,
        "exp": now + DELEGATION_TOKEN_TTL_SECS,
        "jti": random_jti(),
    });
    sign_jwt(sign, &header, &payload)
}

/// A delegation token that verified and whose `jti` was spent.
#[derive(Debug)]
pub struct VerifiedDelegation {
    /// The delegating user (`iss`).
    pub user_did: common::Did,
}

/// Verify an inbound delegation token for `space`, as the space authority, and spend its `jti`.
///
/// Checks: `typ`; header `kid` is `#atproto`; the signature against the issuer's `#atproto` key
/// (cache-first, force-refreshed and retried once on a signature mismatch); `sub` = `space`;
/// `aud` = `space`'s `#atproto_space_host`; no `lxm` (a service-auth token is not a delegation
/// token); `exp` in the future and within [`DELEGATION_TOKEN_MAX_TTL_SECS`]; and a non-empty
/// `jti` not yet seen on this surface. Every verification failure is the lexicon's
/// `InvalidDelegationToken`; a failure to *resolve* the issuer (unknown or deactivated DID,
/// PLC directory unreachable) keeps its own code and status, so an upstream outage never reads
/// as the client's fault.
pub async fn verify_delegation_token(
    state: &SpacesState,
    token: &str,
    space: &SpaceRef,
    now: u64,
) -> Result<VerifiedDelegation, ApiError> {
    let invalid = |msg: &str| ApiError::new(ErrorCode::InvalidDelegationToken, msg);

    if peek_jwt_typ(token).as_deref() != Some(DELEGATION_TOKEN_TYP) {
        return Err(invalid(
            "delegation token typ must be atproto-space-delegation+jwt",
        ));
    }
    let iss = peek_jwt_iss(token)
        .and_then(|i| common::Did::parse(i).ok())
        .ok_or_else(|| invalid("delegation token issuer is missing or not a DID"))?;

    let jwt = verify_did_jwt_resolving_key(state, token, &iss, &atproto_verification_key)
        .await
        .map_err(|e| {
            if *e.code() == ErrorCode::InvalidToken {
                e.with_code(ErrorCode::InvalidDelegationToken)
            } else {
                e
            }
        })?;

    if jwt.header.get("kid").and_then(Value::as_str) != Some("#atproto") {
        return Err(invalid("delegation token kid must be #atproto"));
    }
    let claims = &jwt.payload;
    if claims.get("sub").and_then(Value::as_str) != Some(space.uri.as_str()) {
        return Err(invalid("delegation token is for a different space"));
    }
    if claims.get("aud").and_then(Value::as_str) != Some(space_host_aud(space).as_str()) {
        return Err(invalid(
            "delegation token audience is not this space's host",
        ));
    }
    if claims.get("lxm").is_some() {
        return Err(invalid("delegation token must not carry lxm"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("delegation token has no exp"))?;
    if exp <= now {
        return Err(invalid("delegation token has expired"));
    }
    let remaining = exp - now;
    if remaining > DELEGATION_TOKEN_MAX_TTL_SECS {
        return Err(invalid("delegation token lifetime is too long"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| invalid("delegation token has no jti"))?;

    let fresh = insert_jti_if_absent(&state.db, SpaceJtiScope::Delegation, jti, remaining as i64)
        .await
        .or_internal_as(
            "failed to record delegation token jti",
            "internal server error",
        )?;
    if !fresh {
        return Err(invalid("delegation token has already been used"));
    }

    Ok(VerifiedDelegation { user_did: iss })
}

// ── Space credentials ────────────────────────────────────────────────────────

/// Mint a space credential for `space`, as its authority `authority_did`, bound to the P-256
/// `did:key` `key_id` (from the exchange's signature). `sign` is the authority's space signing key — this server signs
/// with the account's repo key, which is also what it publishes as `#atproto_space`, hence that
/// `kid` (verifiers fall back to `#atproto` when the dedicated entry is absent).
pub fn mint_space_credential<F>(
    sign: F,
    authority_did: &str,
    space: &SpaceRef,
    key_id: &str,
    now: u64,
) -> String
where
    F: FnOnce(&[u8]) -> Vec<u8>,
{
    let header = serde_json::json!({
        "typ": SPACE_CREDENTIAL_TYP,
        "alg": "ES256",
        "kid": "#atproto_space",
    });
    let payload = serde_json::json!({
        "iss": authority_did,
        "sub": space.uri,
        "cnf": { "kid": key_id },
        "iat": now,
        "exp": now + SPACE_CREDENTIAL_TTL_SECS,
        "jti": random_jti(),
    });
    sign_jwt(sign, &header, &payload)
}

/// A space credential whose signature and claims verified. Its key binding is enforced by
/// [`authenticate_space_credential`], not here.
#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    /// The space the credential reads (`sub`).
    pub space: SpaceRef,
    /// The bound key (`cnf.kid`), a `did:key`.
    pub kid: String,
}

/// Verify a space credential as a repo host: `typ`; the signature against the authority's key
/// named by `kid` (cache-first, force-refreshed and retried once on a mismatch — a foreign
/// authority may be ES256K, which the shared core accepts); `sub` a space anchored on `iss`;
/// `exp` in the future, `iat` not, and `exp − iat` within [`SPACE_CREDENTIAL_MAX_TTL_SECS`]; a
/// `cnf.kid`; and a `jti` its authority has not revoked through `notifyCredentialRevoked`.
///
/// `kid` selects the key the way the proposal's key separation intends: `#atproto_space`
/// resolves the dedicated space key, falling back to `#atproto` only when the authority
/// publishes none; `#atproto` is honored only when the authority publishes **no** dedicated
/// space key — an authority that separates the two keys did so precisely so a repo-key
/// compromise cannot mint credentials, and the presenter chooses `kid`.
///
/// Only [`authenticate_space_credential`] may call this — the proof-of-possession check that
/// makes a verified credential usable lives there; this function is private to hold that.
async fn verify_space_credential(
    state: &SpacesState,
    token: &str,
    now: u64,
) -> Result<VerifiedCredential, ApiError> {
    let invalid = |msg: &str| ApiError::new(ErrorCode::InvalidToken, msg);

    if peek_jwt_typ(token).as_deref() != Some(SPACE_CREDENTIAL_TYP) {
        return Err(invalid(
            "space credential typ must be atproto-space-credential+jwt",
        ));
    }
    let iss = peek_jwt_iss(token)
        .and_then(|i| common::Did::parse(i).ok())
        .ok_or_else(|| invalid("space credential issuer is missing or not a DID"))?;

    // The header `kid` names which published key signed the credential; it is plain data until
    // the signature verifies, and only picks which key the resolved document is asked for.
    let kid = peek_jwt_header(token)
        .and_then(|h| h.get("kid").and_then(Value::as_str).map(str::to_string));
    let pick_key: &(dyn Fn(&Value) -> Option<crypto::DidKeyUri> + Sync) = match kid.as_deref() {
        Some("#atproto_space") => &space_verification_key,
        Some("#atproto") => &|doc: &Value| {
            dedicated_space_verification_key(doc)
                .is_none()
                .then(|| atproto_verification_key(doc))
                .flatten()
        },
        _ => {
            return Err(invalid(
                "space credential kid must be #atproto_space or #atproto",
            ))
        }
    };

    let jwt = verify_did_jwt_resolving_key(state, token, &iss, pick_key).await?;
    let claims = &jwt.payload;

    let space = claims
        .get("sub")
        .and_then(Value::as_str)
        .and_then(crate::space_uri::parse_space_ref)
        .ok_or_else(|| invalid("space credential sub is not a space reference"))?;
    if space.authority != iss {
        return Err(invalid(
            "space credential issuer is not the space's authority",
        ));
    }
    let (Some(iat), Some(exp)) = (
        claims.get("iat").and_then(Value::as_u64),
        claims.get("exp").and_then(Value::as_u64),
    ) else {
        return Err(invalid("space credential needs numeric iat and exp"));
    };
    if exp <= now {
        return Err(ApiError::new(
            ErrorCode::TokenExpired,
            "space credential has expired",
        ));
    }
    if iat > now + CLOCK_SKEW_SECS {
        return Err(invalid("space credential issued in the future"));
    }
    if exp <= iat || exp - iat > SPACE_CREDENTIAL_MAX_TTL_SECS {
        return Err(invalid("invalid space credential lifetime"));
    }
    let kid = claims
        .get("cnf")
        .and_then(|c| c.get("kid"))
        .and_then(Value::as_str)
        .filter(|k| k.starts_with("did:key:"))
        .ok_or_else(|| invalid("space credential has no cnf.kid binding"))?
        .to_string();
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| invalid("space credential has no jti"))?;
    let revoked = crate::db::space_jti::is_credential_revoked(&state.db, &space.uri, jti)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to read credential revocations");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?;
    if revoked {
        return Err(invalid("space credential has been revoked"));
    }

    Ok(VerifiedCredential { space, kid })
}

// ── Credential issuance policy ───────────────────────────────────────────────

/// Decide, as the space authority, whether an app-and-user pair may be issued a credential for
/// `space`. `client_id` is the *attested* client, `None` when the request carried no client
/// attestation.
///
/// Two perimeters, and the app clears its one first: `appAccess` is decided from the stored
/// config alone, so an app that is not allow-listed is refused before a third-party managing app
/// is ever told this user asked. The authority is deliberately **not** exempt from the app
/// perimeter — an authority that closed its space to all but two apps meant that for itself too.
///
/// The user perimeter is the read `policy` axis. Here the authority always passes: it is the only
/// party who can reconfigure the space, so it must not be able to lock itself out. `public`
/// admits anyone, `member-list` consults `space_members`, and `managing-app` hands the decision
/// to the app the config names.
pub async fn authorize_credential_request(
    state: &SpacesState,
    space: &SpaceRow,
    user_did: &str,
    client_id: Option<&str>,
) -> Result<(), ApiError> {
    if space.app_access.as_deref() == Some("allowList") {
        let allowed = space.allowed_client_ids();
        if !client_id.is_some_and(|id| allowed.iter().any(|entry| entry == id)) {
            return Err(ApiError::new(
                ErrorCode::AppNotAuthorized,
                "this space admits only allow-listed applications",
            ));
        }
    }
    if user_did == space.authority_did {
        return Ok(());
    }
    let authorized = policy_admits(
        state,
        space,
        space.policy.as_deref(),
        space.managing_app.as_deref(),
        Access::Read,
        user_did,
        client_id,
    )
    .await?;
    if authorized {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::UserNotAuthorized,
            "the requesting user is not authorized for this space",
        ))
    }
}

/// Whether the authority tracks and forwards `repo_did`'s write notifications, per the space's
/// **write** policy. The authority's own repo always passes, mirroring the read side.
pub async fn authorize_write_notification(
    state: &SpacesState,
    space: &SpaceRow,
    repo_did: &str,
) -> Result<bool, ApiError> {
    if repo_did == space.authority_did {
        return Ok(true);
    }
    policy_admits(
        state,
        space,
        space.write_policy.as_deref(),
        space.write_managing_app.as_deref(),
        Access::Write,
        repo_did,
        None,
    )
    .await
}

/// Which side of a space a policy decision is for.
#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

impl Access {
    fn as_str(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }
}

/// Evaluate one policy axis for `user_did`: `public` admits anyone, `member-list` consults
/// `space_members` (the read or write bit per `access`), and `managing-app` hands the decision
/// to the app the config names.
async fn policy_admits(
    state: &SpacesState,
    space: &SpaceRow,
    policy: Option<&str>,
    managing_app: Option<&str>,
    access: Access,
    user_did: &str,
    client_id: Option<&str>,
) -> Result<bool, ApiError> {
    Ok(match policy {
        Some("public") => true,
        Some("member-list") => spaces::member_can(
            &state.db,
            &space.uri,
            user_did,
            matches!(access, Access::Write),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to read space members");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?,
        Some("managing-app") => {
            check_managing_app(state, space, managing_app, access, user_did, client_id).await
        }
        // Unreachable through create/update, which refuse any policy this host cannot evaluate;
        // a row that got here some other way is not one to hand out credentials for.
        _ => false,
    })
}

/// The lexicon method a `managing-app` authorization check invokes.
const CHECK_USER_ACCESS_LXM: &str = "com.atproto.simplespace.checkUserAccess";

/// How long the authority waits on a managing app before treating it as unreachable. Credential
/// minting is interactive, and a stalled app must not hold the request open.
const CHECK_USER_ACCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask the space's `managingApp` whether to authorize `user_did`, as the authority and under
/// service auth (`com.atproto.simplespace.checkUserAccess`).
///
/// **Every** failure denies — unresolvable DID, no published endpoint, transport error, non-2xx,
/// unparseable body. Failing open would hand out credentials for exactly the spaces that asked
/// for the strictest gate, so the one policy that defers its decision must not become the one
/// that skips it when the decider is down.
///
/// `managingApp` is a service identifier: a DID with an optional service fragment. Without a
/// fragment the DID's `#atproto_pds` entry is used, since a bare DID names an account and an
/// account is served by its PDS. The `aud` is the identifier as published, fragment and all, so
/// a multi-service app can tell which of its services was addressed.
async fn check_managing_app(
    state: &SpacesState,
    space: &SpaceRow,
    managing_app: Option<&str>,
    access: Access,
    user_did: &str,
    client_id: Option<&str>,
) -> bool {
    let Some(managing_app) = managing_app else {
        return false;
    };
    let (did, fragment) = match managing_app.split_once('#') {
        Some((did, fragment)) => (did, fragment),
        None => (managing_app, "atproto_pds"),
    };

    let deny = |reason: &str| {
        tracing::warn!(
            space = %space.uri,
            managing_app = %managing_app,
            user = %user_did,
            reason,
            "managing-app check denied",
        );
        false
    };

    let Ok(did_doc) = resolve_did_document(state, did).await else {
        return deny("could not resolve the managing app's DID");
    };
    let Some(endpoint) = service_endpoint(&did_doc, fragment) else {
        return deny("the managing app publishes no endpoint for this service");
    };

    let Some(master_key) = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|secret| &*secret.0)
    else {
        return deny("signing key master key not configured");
    };
    let Ok(now) = unix_now() else {
        return deny("system clock is before the epoch");
    };
    let Ok(token) = crate::auth::signing_key::mint_account_service_auth(
        &state.db,
        master_key,
        &space.authority_did,
        managing_app,
        Some(CHECK_USER_ACCESS_LXM),
        now,
        now + 60,
    )
    .await
    else {
        return deny("could not sign service auth as the authority");
    };

    let Ok(mut url) = url::Url::parse(&format!(
        "{}/xrpc/{CHECK_USER_ACCESS_LXM}",
        endpoint.trim_end_matches('/')
    )) else {
        return deny("the managing app's published endpoint is not a URL");
    };
    url.query_pairs_mut()
        .append_pair("space", &space.uri)
        .append_pair("user", user_did)
        .append_pair("access", access.as_str());
    if let (Access::Read, Some(client_id)) = (access, client_id) {
        url.query_pairs_mut().append_pair("clientId", client_id);
    }
    // The endpoint comes from a DID document the space's own config points at, so it is
    // caller-influenced: the hardened client is what decides which address this reaches.
    let response = state
        .hardened_http_client
        .get(&crate::identity::proxy::CallerUrl::new(url))
        .bearer_auth(token)
        .timeout(CHECK_USER_ACCESS_TIMEOUT)
        .send()
        .await;
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => return deny(&format!("managing app answered HTTP {}", response.status())),
        Err(e) => return deny(&format!("could not reach the managing app: {e}")),
    };
    match response.json::<Value>().await {
        Ok(body) => body.get("authorized").and_then(Value::as_bool) == Some(true),
        Err(e) => deny(&format!("managing app answer was not readable: {e}")),
    }
}

// ── Shared plumbing ──────────────────────────────────────────────────────────

/// Resolve `iss`'s DID document, pick the verification key with `pick_key`, and verify `token`
/// against it — force-refreshing the cached document and retrying once on a signature
/// mismatch, the same fossil-key healing `service_auth::verify_service_auth_resolving_key`
/// does (the `did_documents` cache has no TTL) — through the one shared, cool-down-bounded
/// `refresh_did_document_after_signature_mismatch` seam.
///
/// A failure to resolve the issuer at all (`DidNotFound`, `DidDeactivated`,
/// `PlcDirectoryError`, …) passes through with its own code and status — an unreachable PLC
/// directory is not an invalid token. A failed *refresh* after a signature mismatch does not:
/// the cached document was there and the signature did not verify against it, so that verdict
/// stands — as does a refresh the per-DID cool-down suppressed. Verification failures are
/// `InvalidToken`; callers re-code those alone.
async fn verify_did_jwt_resolving_key(
    state: &SpacesState,
    token: &str,
    iss: &str,
    pick_key: &(dyn Fn(&Value) -> Option<crypto::DidKeyUri> + Sync),
) -> Result<DidKeyJwt, ApiError> {
    let verify = |doc: &Value| -> Result<DidKeyJwt, ServiceAuthError> {
        let key = pick_key(doc).ok_or_else(|| {
            ServiceAuthError::Invalid(ApiError::new(
                ErrorCode::InvalidToken,
                "the issuer's DID document has no matching verification key",
            ))
        })?;
        verify_did_key_jwt(token, &key)
    };
    let cached = resolve_did_document(state, iss).await?;
    match verify(&cached) {
        Ok(jwt) => Ok(jwt),
        Err(ServiceAuthError::SignatureMismatch) => {
            match refresh_did_document_after_signature_mismatch(state, iss).await {
                Ok(fresh) => Ok(verify(&fresh)?),
                Err(refresh_error) => {
                    tracing::debug!(
                        iss = %iss,
                        error = %refresh_error,
                        "force-refresh failed; keeping the signature-mismatch verdict"
                    );
                    Err(ApiError::new(
                        ErrorCode::InvalidToken,
                        "token signature does not verify against the issuer's published key",
                    ))
                }
            }
        }
        Err(other) => Err(other.into()),
    }
}

/// The decoded JWT header, unverified — for reading `kid` ahead of key resolution.
fn peek_jwt_header(token: &str) -> Option<Value> {
    peek_jwt_segment(token, 0)
}

/// The decoded JWT payload, unverified — for cheap pre-filters ahead of key resolution.
fn peek_jwt_payload(token: &str) -> Option<Value> {
    peek_jwt_segment(token, 1)
}

fn peek_jwt_segment(token: &str, index: usize) -> Option<Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let b64 = token.split('.').nth(index)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).ok()?).ok()
}

pub(crate) use crate::time::unix_now;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::dids::seed_did_document;
    use crate::db::spaces::{insert_space, NewSpace};
    use crate::space_uri::parse_space_ref;
    use crate::test_support::{
        access_jwt, app_pass_jwt, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
        SpaceSigKey,
    };
    use crate::SpacesState;
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
    const SPACE: &str = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self";
    const GET_RECORD: &str = "/xrpc/com.atproto.space.getRecord";

    /// A DID document whose `#atproto` (and, when `with_space_key`, `#atproto_space`) Multikey
    /// holds `kp`'s public key — what this server publishes for its own accounts. A
    /// `distinct_space_key` publishes a *different* `#atproto_space` key: the separated-keys
    /// authority.
    fn did_doc(
        did: &str,
        kp: &crypto::P256Keypair,
        with_space_key: bool,
        distinct_space_key: Option<&crypto::P256Keypair>,
    ) -> Value {
        let multibase =
            |kp: &crypto::P256Keypair| kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
        let mut methods = vec![serde_json::json!({
            "id": format!("{did}#atproto"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase(kp),
        })];
        if with_space_key {
            methods.push(serde_json::json!({
                "id": format!("{did}#atproto_space"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase(distinct_space_key.unwrap_or(kp)),
            }));
        }
        serde_json::json!({ "id": did, "verificationMethod": methods })
    }

    /// Seed a local account with a repo key and a cached DID document carrying that key.
    async fn seed_identity(
        state: &SpacesState,
        did: &str,
        with_space_key: bool,
    ) -> repo_engine::CommitSigner {
        let kp = seed_account_with_repo(&state.db, did).await;
        seed_did_document(&state.db, did, did_doc(did, &kp, with_space_key, None)).await;
        repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap()
    }

    fn space() -> SpaceRef {
        parse_space_ref(SPACE).unwrap()
    }

    fn payload(token: &str) -> Value {
        let b64 = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    fn header(token: &str) -> Value {
        let b64 = token.split('.').next().unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap()
    }

    fn headers(scheme: &str, token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("{scheme} {token}")).unwrap(),
        );
        h
    }

    /// Run the read seam for `repo` with `headers`, as a `getRecord` call.
    async fn read(
        state: &SpacesState,
        headers: &HeaderMap,
        repo: &str,
    ) -> Result<SpaceReader, ApiError> {
        authenticate_space_read(
            state,
            headers,
            &Method::GET,
            &get_uri(GET_RECORD),
            &space(),
            repo,
        )
        .await
    }

    fn get_uri(path: &str) -> Uri {
        path.parse().unwrap()
    }

    #[test]
    fn space_host_aud_is_the_authority_space_host_service() {
        assert_eq!(
            space_host_aud(&space()),
            "did:plc:abc234567abc234567abc234#atproto_space_host"
        );
    }

    #[tokio::test]
    async fn delegation_token_mints_verifies_and_is_single_use() {
        let state = state_with_master_key().await;
        let alice = seed_identity(&state, ALICE, false).await;
        let now = unix_now().unwrap();

        let token = mint_delegation_token(|b| alice.sign(b), ALICE, &space(), now);
        let hdr = header(&token);
        assert_eq!(hdr["typ"], DELEGATION_TOKEN_TYP);
        assert_eq!(hdr["kid"], "#atproto");
        let claims = payload(&token);
        assert_eq!(claims["iss"], ALICE);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(
            claims["aud"],
            "did:plc:abc234567abc234567abc234#atproto_space_host"
        );
        assert_eq!(claims["exp"], now + DELEGATION_TOKEN_TTL_SECS);
        assert!(claims.get("lxm").is_none());

        let verified = verify_delegation_token(&state, &token, &space(), now)
            .await
            .unwrap();
        assert_eq!(verified.user_did, ALICE);

        // Single-use: the same token is a replay.
        let err = verify_delegation_token(&state, &token, &space(), now)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), 401);
        assert_eq!(*err.code(), ErrorCode::InvalidDelegationToken);

        // A token for another space, an expired token, and a service-auth token (wrong typ)
        // are all InvalidDelegationToken.
        let other =
            parse_space_ref("at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other")
                .unwrap();
        let wrong_space = mint_delegation_token(|b| alice.sign(b), ALICE, &other, now);
        assert_eq!(
            verify_delegation_token(&state, &wrong_space, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
        let expired = mint_delegation_token(|b| alice.sign(b), ALICE, &space(), now - 120);
        assert_eq!(
            verify_delegation_token(&state, &expired, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
        let service_auth = super::super::jwt::mint_service_auth_jwt(
            |b| alice.sign(b),
            ALICE,
            &space_host_aud(&space()),
            None,
            now,
            now + 60,
        );
        assert_eq!(
            verify_delegation_token(&state, &service_auth, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
    }

    #[tokio::test]
    async fn delegation_token_ttl_and_audience_bounds_are_enforced() {
        let state = state_with_master_key().await;
        let alice = seed_identity(&state, ALICE, false).await;
        let now = unix_now().unwrap();
        let hdr = serde_json::json!({
            "typ": DELEGATION_TOKEN_TYP, "alg": "ES256", "kid": "#atproto",
        });
        // Lifetime beyond DELEGATION_TOKEN_MAX_TTL_SECS — the replay-row retention bound.
        let long = sign_jwt(
            |b| alice.sign(b),
            &hdr,
            &serde_json::json!({
                "iss": ALICE,
                "sub": SPACE,
                "aud": space_host_aud(&space()),
                "iat": now,
                "exp": now + DELEGATION_TOKEN_MAX_TTL_SECS + 1,
                "jti": "ttl-too-long",
            }),
        );
        assert_eq!(
            verify_delegation_token(&state, &long, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
        // Correct sub, wrong aud: addressed to some other host.
        let wrong_aud = sign_jwt(
            |b| alice.sign(b),
            &hdr,
            &serde_json::json!({
                "iss": ALICE,
                "sub": SPACE,
                "aud": "did:plc:alice#atproto_space_host",
                "iat": now,
                "exp": now + 60,
                "jti": "wrong-aud",
            }),
        );
        assert_eq!(
            verify_delegation_token(&state, &wrong_aud, &space(), now)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::InvalidDelegationToken
        );
    }

    #[tokio::test]
    async fn delegation_token_signed_by_the_wrong_key_is_rejected() {
        let state = state_with_master_key().await;
        seed_identity(&state, ALICE, false).await;
        // A key that is not the one in alice's DID document.
        let imposter = crypto::generate_p256_keypair().unwrap();
        let imposter = repo_engine::CommitSigner::from_bytes(&imposter.private_key_bytes).unwrap();
        let now = unix_now().unwrap();
        let forged = mint_delegation_token(|b| imposter.sign(b), ALICE, &space(), now);
        let err = verify_delegation_token(&state, &forged, &space(), now)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::InvalidDelegationToken);
    }

    #[tokio::test]
    async fn delegation_token_from_an_unresolvable_issuer_keeps_the_resolution_error() {
        // No account, no cached document, and no PLC directory to ask: the resolution failure
        // surfaces as itself, not as the client's InvalidDelegationToken.
        let state = state_with_master_key().await;
        let ghost = crypto::generate_p256_keypair().unwrap();
        let ghost = repo_engine::CommitSigner::from_bytes(&ghost.private_key_bytes).unwrap();
        let now = unix_now().unwrap();
        let token = mint_delegation_token(|b| ghost.sign(b), "did:plc:nobodyhere", &space(), now);
        let err = verify_delegation_token(&state, &token, &space(), now)
            .await
            .unwrap_err();
        assert_ne!(*err.code(), ErrorCode::InvalidDelegationToken);
        assert_ne!(*err.code(), ErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn space_credential_mints_and_the_seam_accepts_it_with_its_signature() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        // The repo being read belongs to alice, an active local account; the credential holder
        // is neither alice nor the authority.
        seed_identity(&state, ALICE, false).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();

        let credential = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            now,
        );
        let hdr = header(&credential);
        assert_eq!(hdr["typ"], SPACE_CREDENTIAL_TYP);
        assert_eq!(hdr["kid"], "#atproto_space");
        let claims = payload(&credential);
        assert_eq!(claims["iss"], AUTHORITY);
        assert_eq!(claims["sub"], SPACE);
        assert_eq!(claims["cnf"], serde_json::json!({ "kid": key.key_id() }));
        assert!(claims.get("aud").is_none());
        assert_eq!(claims["exp"], now + SPACE_CREDENTIAL_TTL_SECS);
        assert_eq!(SPACE_CREDENTIAL_TTL_SECS, 600);

        let signed = key.credential_headers(&credential, ALICE);
        match read(&state, &signed, ALICE).await.unwrap() {
            SpaceReader::Credential(c) => {
                assert_eq!(c.space.authority, AUTHORITY);
                assert_eq!(c.space.uri, SPACE);
                assert_eq!(c.kid, key.key_id());
            }
            other => panic!("expected the credential arm, got {other:?}"),
        }

        // The same signed request again is fine: replay against one audience is allowed until
        // expiry, by spec.
        assert!(read(&state, &signed, ALICE).await.is_ok());

        // A signature by a key other than cnf.kid is refused.
        let other_key = SpaceSigKey::generate();
        assert_eq!(
            read(
                &state,
                &other_key.credential_headers(&credential, ALICE),
                ALICE
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );

        // The audience must be the repo the request reads: a request signed for alice cannot
        // read another repo, nor one signed for anyone else read alice's.
        seed_identity(&state, "did:plc:carol", false).await;
        for (audience, repo) in [(ALICE, "did:plc:carol"), (AUTHORITY, ALICE)] {
            let err = read(&state, &key.credential_headers(&credential, audience), repo)
                .await
                .unwrap_err();
            assert_eq!(*err.code(), ErrorCode::InvalidToken, "{audience} → {repo}");
        }

        // A repo whose owner is not an active local account reads as RepoNotFound for a
        // credential holder (the owner could still read it themselves).
        let err = read(
            &state,
            &key.credential_headers(&credential, "did:plc:stranger"),
            "did:plc:stranger",
        )
        .await
        .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::RepoNotFound);
    }

    #[tokio::test]
    async fn space_credential_is_never_bearer_or_dpop() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        seed_identity(&state, ALICE, false).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let credential = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            now,
        );

        // The pre-RFC 9421 shapes are refused by name, signature attached or not.
        for scheme in ["Bearer", "DPoP"] {
            let mut signed = key.credential_headers(&credential, ALICE);
            signed.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("{scheme} {credential}")).unwrap(),
            );
            for h in [signed, headers(scheme, &credential)] {
                let err = read(&state, &h, ALICE).await.unwrap_err();
                assert_eq!(err.status_code(), 401, "{scheme}");
                assert!(err.message().contains("Atproto-Space"), "{scheme}: {err:?}");
            }
        }
        // The right scheme with no signature at all is refused too.
        assert_eq!(
            read(&state, &headers("Atproto-Space", &credential), ALICE)
                .await
                .unwrap_err()
                .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn space_credential_for_another_space_or_wrong_issuer_is_rejected() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let alice = seed_identity(&state, ALICE, false).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let other =
            parse_space_ref("at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other")
                .unwrap();

        for cred in [
            // Credential for a different space than the request targets.
            mint_space_credential(|b| authority.sign(b), AUTHORITY, &other, key.key_id(), now),
            // Signed by alice (a valid key, but not the space's authority).
            mint_space_credential(|b| alice.sign(b), ALICE, &space(), key.key_id(), now),
            // Forged: claims iss = authority but signed by alice's key.
            mint_space_credential(|b| alice.sign(b), AUTHORITY, &space(), key.key_id(), now),
        ] {
            let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), 401);
        }
    }

    #[tokio::test]
    async fn space_credential_lifetime_is_bounded() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let header = serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto_space" });
        let with = |iat: u64, exp: u64| {
            sign_jwt(
                |b| authority.sign(b),
                &header,
                &serde_json::json!({
                    "iss": AUTHORITY, "sub": SPACE, "cnf": { "kid": key.key_id() },
                    "iat": iat, "exp": exp, "jti": "lifetime",
                }),
            )
        };
        // Exactly the cap verifies; a minute over it, an iat from the future, or an inverted
        // pair does not.
        assert!(verify_space_credential(
            &state,
            &with(now, now + SPACE_CREDENTIAL_MAX_TTL_SECS),
            now
        )
        .await
        .is_ok());
        for (iat, exp) in [
            (now, now + SPACE_CREDENTIAL_MAX_TTL_SECS + 60),
            (now + 60, now + 120),
            (now + 1, now + 1),
        ] {
            assert_eq!(
                *verify_space_credential(&state, &with(iat, exp), now)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidToken,
                "iat={iat} exp={exp}"
            );
        }
        // Expired is its own code.
        assert_eq!(
            *verify_space_credential(&state, &with(now - 120, now - 60), now)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::TokenExpired
        );
    }

    #[tokio::test]
    async fn space_credential_needs_an_unrevoked_jti() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY, true).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let header = serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto_space" });
        let with = |jti: Option<&str>| {
            let mut claims = serde_json::json!({
                "iss": AUTHORITY, "sub": SPACE, "cnf": { "kid": key.key_id() },
                "iat": now, "exp": now + 60,
            });
            if let Some(jti) = jti {
                claims["jti"] = jti.into();
            }
            sign_jwt(|b| authority.sign(b), &header, &claims)
        };

        assert!(verify_space_credential(&state, &with(Some("live")), now)
            .await
            .is_ok());
        crate::db::space_jti::revoke_credentials(&state.db, SPACE, &["live".into()], 60)
            .await
            .unwrap();
        for cred in [with(Some("live")), with(None)] {
            assert_eq!(
                *verify_space_credential(&state, &cred, now)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidToken
            );
        }
    }

    #[tokio::test]
    async fn credential_kid_selects_the_key_and_honors_key_separation() {
        let state = state_with_master_key().await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let with_kid = |signer: &repo_engine::CommitSigner, kid: &str, claims: &Value| {
            let header =
                serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": kid });
            sign_jwt(|b| signer.sign(b), &header, claims)
        };

        // An authority with no dedicated `#atproto_space`: `kid #atproto_space` falls back to
        // `#atproto`, and `kid #atproto` resolves directly; an unknown kid is refused.
        let authority = seed_identity(&state, AUTHORITY, false).await;
        let cred = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            now,
        );
        assert_eq!(
            verify_space_credential(&state, &cred, now)
                .await
                .unwrap()
                .kid,
            key.key_id()
        );
        let claims = payload(&cred);
        assert!(
            verify_space_credential(&state, &with_kid(&authority, "#atproto", &claims), now)
                .await
                .is_ok()
        );
        assert!(
            verify_space_credential(&state, &with_kid(&authority, "#other", &claims), now)
                .await
                .is_err()
        );

        // An authority that publishes a *distinct* `#atproto_space` key: only that key signs
        // credentials. A repo-key signature under `kid #atproto` is refused (the presenter
        // chooses `kid`, so the weaker path must not exist), and under `kid #atproto_space` it
        // simply fails to verify.
        let separated = "did:plc:zzz234567zzz234567zzz234";
        let repo_kp = seed_account_with_repo(&state.db, separated).await;
        let space_kp = crypto::generate_p256_keypair().unwrap();
        seed_did_document(
            &state.db,
            separated,
            did_doc(separated, &repo_kp, true, Some(&space_kp)),
        )
        .await;
        let repo_signer =
            repo_engine::CommitSigner::from_bytes(&repo_kp.private_key_bytes).unwrap();
        let space_signer =
            repo_engine::CommitSigner::from_bytes(&space_kp.private_key_bytes).unwrap();
        let sep_space =
            parse_space_ref(&format!("at://{separated}/space/org.example.bucket/self")).unwrap();
        let claims = payload(&mint_space_credential(
            |b| space_signer.sign(b),
            separated,
            &sep_space,
            key.key_id(),
            now,
        ));
        assert!(
            verify_space_credential(
                &state,
                &with_kid(&space_signer, "#atproto_space", &claims),
                now
            )
            .await
            .is_ok(),
            "the dedicated space key signs"
        );
        assert!(
            verify_space_credential(&state, &with_kid(&repo_signer, "#atproto", &claims), now)
                .await
                .is_err(),
            "the repo key must not mint credentials for a key-separated authority"
        );
        assert!(verify_space_credential(
            &state,
            &with_kid(&repo_signer, "#atproto_space", &claims),
            now
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn credential_for_another_space_is_filtered_before_resolution() {
        // A credential whose unverified `sub` names another space never reaches DID resolution:
        // an issuer that does not exist anywhere is still answered with the mismatch, not a
        // resolution error.
        let state = state_with_master_key().await;
        let ghost = crypto::generate_p256_keypair().unwrap();
        let ghost = repo_engine::CommitSigner::from_bytes(&ghost.private_key_bytes).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let other = parse_space_ref("at://did:plc:nobodyhere/space/org.example.bucket/x").unwrap();
        let cred = mint_space_credential(
            |b| ghost.sign(b),
            "did:plc:nobodyhere",
            &other,
            key.key_id(),
            now,
        );
        let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::InvalidToken);
    }

    #[tokio::test]
    async fn seam_oauth_arm_reads_only_the_callers_own_repo_under_a_covering_grant() {
        let state = state_with_master_key().await;
        // The seam gates on the caller's account lifecycle, so the caller needs an account row.
        seed_account_with_repo(&state.db, ALICE).await;
        // Alice's own space (authority = self).
        let own = parse_space_ref("at://did:plc:alice/space/org.example.bucket/self").unwrap();

        let call = |token: String, space: SpaceRef, repo: &'static str| {
            let state = state.clone();
            async move {
                authenticate_space_read(
                    &state,
                    &headers("Bearer", &token),
                    &Method::GET,
                    &get_uri(GET_RECORD),
                    &space,
                    repo,
                )
                .await
            }
        };

        // Legacy full-access session: bounded by ownership only.
        assert!(matches!(
            call(access_jwt(&state.jwt_secret, ALICE), own.clone(), ALICE)
                .await
                .unwrap(),
            SpaceReader::User(u) if u.did == ALICE
        ));
        // A bare `space:<type>` grant defaults to authority=self, action incl. read.
        let bare = scoped_access_jwt(&state.jwt_secret, ALICE, "atproto space:org.example.bucket");
        assert!(call(bare.clone(), own.clone(), ALICE).await.is_ok());
        // ...but does not cover a space of another authority.
        assert_eq!(
            call(bare, space(), ALICE).await.unwrap_err().status_code(),
            403
        );
        // A named-authority `read` or `read_self` grant covers the holder's own repo there.
        for scope in [
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234",
            "atproto space:org.example.bucket?authority=did:plc:abc234567abc234567abc234&action=read_self",
        ] {
            let token = scoped_access_jwt(&state.jwt_secret, ALICE, scope);
            assert!(call(token.clone(), space(), ALICE).await.is_ok(), "{scope}");
            // Someone else's repo is RepoNotFound for any account credential, grant or not.
            assert_eq!(
                *call(token, space(), AUTHORITY).await.unwrap_err().code(),
                ErrorCode::RepoNotFound
            );
        }
        // An unrelated grant is refused; a legacy app password is bounded by ownership only.
        let repo_only = scoped_access_jwt(&state.jwt_secret, ALICE, "atproto repo:*");
        assert_eq!(
            call(repo_only, own.clone(), ALICE)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        let app_pass = app_pass_jwt(&state.jwt_secret, ALICE, true);
        assert!(call(app_pass, own, ALICE).await.is_ok());
    }

    #[tokio::test]
    async fn issuance_policy_user_perimeter_public_member_list_and_managing_app() {
        let state = state_with_master_key().await;
        let mut row = crate::db::spaces::SpaceRow {
            uri: SPACE.to_string(),
            authority_did: AUTHORITY.to_string(),
            policy: Some("member-list".to_string()),
            app_access: Some("open".to_string()),
            app_allowed: None,
            managing_app: None,
            write_policy: None,
            write_managing_app: None,
            deleted_at: None,
            takendown_at: None,
        };
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some("member-list"),
                app_access: Some("open"),
                app_allowed: None,
                managing_app: None,
                write_policy: None,
                write_managing_app: None,
            },
        )
        .await
        .unwrap();

        // The authority always may; a non-member may not; a member may.
        assert!(authorize_credential_request(&state, &row, AUTHORITY, None)
            .await
            .is_ok());
        let err = authorize_credential_request(&state, &row, ALICE, None)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::UserNotAuthorized);
        sqlx::query(
            "INSERT INTO space_members (space_uri, member_did, added_at) VALUES (?, ?, 'now')",
        )
        .bind(SPACE)
        .bind(ALICE)
        .execute(&state.db)
        .await
        .unwrap();
        assert!(authorize_credential_request(&state, &row, ALICE, None)
            .await
            .is_ok());

        row.policy = Some("public".to_string());
        assert!(
            authorize_credential_request(&state, &row, "did:plc:stranger", None)
                .await
                .is_ok()
        );

        // `managing-app` with no app to ask denies — the policy that defers its decision must
        // never become the one that skips it.
        row.policy = Some("managing-app".to_string());
        assert_eq!(
            authorize_credential_request(&state, &row, "did:plc:stranger", None)
                .await
                .unwrap_err()
                .code(),
            &ErrorCode::UserNotAuthorized
        );
        // ...and the authority still passes its own user perimeter, so a misconfigured
        // managing app cannot lock the owner out of its own space.
        assert!(authorize_credential_request(&state, &row, AUTHORITY, None)
            .await
            .is_ok());
    }

    /// The read and write axes are independent: a member-list read policy consults the `read`
    /// bit, a member-list write policy the `write` bit, and neither borrows the other's.
    #[tokio::test]
    async fn read_and_write_policies_consult_their_own_member_bits() {
        let state = state_with_master_key().await;
        insert_space(
            &state.db,
            &NewSpace {
                uri: SPACE,
                authority_did: AUTHORITY,
                space_type: "org.example.bucket",
                skey: "self",
                policy: Some("member-list"),
                app_access: Some("open"),
                app_allowed: None,
                managing_app: None,
                write_policy: Some("member-list"),
                write_managing_app: None,
            },
        )
        .await
        .unwrap();
        let row = spaces::get_space(&state.db, SPACE).await.unwrap().unwrap();

        spaces::put_member(&state.db, SPACE, ALICE, true, false)
            .await
            .unwrap();
        assert!(authorize_credential_request(&state, &row, ALICE, None)
            .await
            .is_ok());
        assert!(!authorize_write_notification(&state, &row, ALICE)
            .await
            .unwrap());

        spaces::put_member(&state.db, SPACE, ALICE, false, true)
            .await
            .unwrap();
        assert!(authorize_credential_request(&state, &row, ALICE, None)
            .await
            .is_err());
        assert!(authorize_write_notification(&state, &row, ALICE)
            .await
            .unwrap());

        // A public write policy admits a repo that is no member.
        let mut open_writes = row.clone();
        open_writes.write_policy = Some("public".to_string());
        assert!(
            authorize_write_notification(&state, &open_writes, "did:plc:stranger")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn issuance_policy_app_perimeter_is_the_allow_list() {
        let state = state_with_master_key().await;
        const ALLOWED: &str = "https://allowed.example.com/client-metadata.json";
        const OTHER: &str = "https://other.example.com/client-metadata.json";
        let mut row = crate::db::spaces::SpaceRow {
            uri: SPACE.to_string(),
            authority_did: AUTHORITY.to_string(),
            policy: Some("public".to_string()),
            app_access: Some("allowList".to_string()),
            app_allowed: Some(serde_json::json!([ALLOWED]).to_string()),
            managing_app: None,
            write_policy: None,
            write_managing_app: None,
            deleted_at: None,
            takendown_at: None,
        };

        async fn refusal(
            state: &SpacesState,
            row: &crate::db::spaces::SpaceRow,
            did: &str,
            client: Option<&str>,
        ) -> ErrorCode {
            authorize_credential_request(state, row, did, client)
                .await
                .unwrap_err()
                .code()
                .clone()
        }

        // No attestation at all, and an attestation naming an app that is not on the list.
        assert_eq!(
            refusal(&state, &row, ALICE, None).await,
            ErrorCode::AppNotAuthorized
        );
        assert_eq!(
            refusal(&state, &row, ALICE, Some(OTHER)).await,
            ErrorCode::AppNotAuthorized
        );
        // The authority is NOT exempt from the app perimeter: closing a space to all but one
        // app closed it for the owner too.
        assert_eq!(
            refusal(&state, &row, AUTHORITY, None).await,
            ErrorCode::AppNotAuthorized
        );

        // The allow-listed app clears the perimeter, and `public` then admits the user.
        assert!(
            authorize_credential_request(&state, &row, ALICE, Some(ALLOWED))
                .await
                .is_ok()
        );

        // An allow list with no entries admits nothing — never read as "open".
        row.app_allowed = Some("[]".to_string());
        assert_eq!(
            refusal(&state, &row, ALICE, Some(ALLOWED)).await,
            ErrorCode::AppNotAuthorized
        );
        // An unreadable list is the same refusal, not an accidental opening.
        row.app_allowed = None;
        assert_eq!(
            refusal(&state, &row, ALICE, Some(ALLOWED)).await,
            ErrorCode::AppNotAuthorized
        );
    }
}
