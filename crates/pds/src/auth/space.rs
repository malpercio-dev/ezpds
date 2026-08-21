// pattern: Mixed (unavoidable)
//
// The authorization seam every `com.atproto.space.*` route enters through. Mixed because the
// `collection` a bare `space:` grant covers is the space type declaration's, resolved over the
// network (DNS + HTTP) per the spec's dynamic-resolution rule — the same reason
// `auth/space_consent.rs`, whose resolver this reuses, cannot be a pure Functional Core.
//
// Routes may not import one another, and eight of them need identical admission rules, so the
// rules live here once: authenticate the access token, confirm the caller owns the repo it
// named, and check the operation against the caller's `space:` grant.

use axum::http::{HeaderMap, Method, Uri};

use crate::app::AppState;
use crate::space_uri::SpaceRef;
use common::{ApiError, ErrorCode};

use super::extractors::AuthenticatedUser;
use super::jwt::AuthScope;
use super::oauth_scopes::{self, SpaceOp, SpaceRequest};

/// Authenticate a caller of a space method that names no one repo (`listSpaces`).
///
/// Runs the shared access-auth path, so the RFC 9449 scheme ↔ `cnf.jkt` binding rules are
/// identical to every other authenticated route's.
pub fn authenticate_space_caller(
    state: &AppState,
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
    Ok(user)
}

/// Authenticate a space *write* and confirm the caller owns the repo it names.
///
/// Writes are OAuth-only by spec — a space credential is a read/sync capability the authority
/// issues to syncers, never a licence to write into someone else's repo — so there is no second
/// credential branch here, unlike [`authenticate_space_read`].
pub fn authenticate_space_write(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    repo: &str,
) -> Result<AuthenticatedUser, ApiError> {
    let user = authenticate_space_caller(state, headers, method, uri)?;
    if user.did != repo {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "repo must match authenticated user",
        ));
    }
    Ok(user)
}

/// Authenticate a space *read* of one account's repo, and authorize it.
///
/// An account credential reads only that account's own repo. Reaching another member's repo
/// takes a space credential, which only the authority issues and only after deciding the holder
/// may read the space — a repo host keeps no member list of its own to consult. That branch
/// lands with the credential mint; today every caller here is an account.
///
/// A caller naming someone else's repo gets the same `RepoNotFound` an absent repo gets, on
/// purpose: whether a given account holds a repo in a space is not a fact a caller without read
/// access to that space is entitled to learn.
///
/// No repo-availability check (takedown / suspension / deactivation) runs here, and that is a
/// consequence of the above rather than an omission: every caller today *is* the repo's owner,
/// and an owner may always read their own deactivated repo — the reference relaxes the same
/// check for the same reason. It stops being a no-op the moment the credential branch lands and
/// a caller can be someone other than the owner, so it belongs in that change.
pub async fn authenticate_space_read(
    state: &AppState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    space: &SpaceRef,
    repo: &str,
) -> Result<AuthenticatedUser, ApiError> {
    let user = authenticate_space_caller(state, headers, method, uri)?;
    if user.did != repo {
        return Err(repo_not_found(repo));
    }
    require_space_grant(state, &user, space, SpaceOp::ReadSelf).await?;
    Ok(user)
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
    state: &AppState,
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
    let declared = super::space_consent::resolve_space_type_cached(
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
