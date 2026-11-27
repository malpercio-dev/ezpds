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
//!   authority as space host (`{authority}#atproto_pds`), single-use, ~60 s.
//!   [`mint_delegation_token`] / [`verify_delegation_token`] (the latter spends the `jti` in
//!   `space_jti_replay`).
//! * **Space credential** — the space authority mints it (`authorizeSpaceSync`), bound to the
//!   P-256 `did:key` the request body names (`credentialKey`): `typ
//!   atproto-space-credential+jwt`, `kid #atproto`, no `aud`, `cnf.kid` = that key, 10 min (a
//!   verifier accepts up to 60). Possession of the key is proven on every use, not at minting.
//!   [`mint_space_credential`] / [`verify_space_credential`] (the latter verifies against the
//!   authority's `#atproto` key). The `jti` is a revocation id, not a nonce: a credential is
//!   reusable until it expires. Its checks run in the reference's order (`spaceCredentialAuth`)
//!   with two divergences, both so that an unsigned token never drives DID resolution:
//!   a `sub` that is not a space reference answers `BadJwtSub` *before* the signatures are
//!   checked, where the reference reaches that check only after them; and a well-formed
//!   credential for another space answers `InvalidCredential` before its signatures are
//!   checked, where the reference compares the space last.
//! * **The read seam** — [`authenticate_space_read`] accepts a covering OAuth grant on the
//!   caller's *own* repo *or* a signature-bound space credential for any repo in the space,
//!   never a bearer credential. [`authenticate_space_access`] is the same pair of arms for a
//!   space-host method that names a space but no repo (`listWriters`), and
//!   [`authenticate_space_authority`] is the OAuth-only arm every space management method *on
//!   an existing space* takes (`updateSpace`, `getSpace`, the memberspace methods): grant check,
//!   then "the caller *is* the authority" (`NotAuthorized`). `createSpace` is the exception — a
//!   space anchored on the caller's own DID has no prior authority to check, so it takes
//!   [`authenticate_space_caller`] and the grant check alone. The credential arm takes
//!   `Authorization: Atproto-Space-Credential <credential>` plus an RFC 9421 signature tagged
//!   `atproto-space-credential` over that header and `Atproto-Space-Audience`, verified against
//!   `cnf.kid`; the audience must be the DID the request is for (the repo's account on a repo read,
//!   the authority on a space-level one), which is what stops a credential captured at one repo
//!   host being replayed at another. Replay against the same audience is allowed until expiry,
//!   by spec. The compiler confines it: `verify_space_credential` is private to this module and
//!   `verify_credential_signature` to `auth`, so no route grows its own credential parsing.
//! * **Session scope** — every account-credential arm above admits a full-access token only (a
//!   full session or an OAuth grant), the reference's `scopes: ACCESS_FULL`: an app-password
//!   session answers 400 `InvalidToken` ("Bad token scope") in [`authenticate_space_caller`],
//!   the reference's reply. `listWriters`' account arm, which the reference does not have,
//!   refuses it too.
//! * **The operator cut** — [`require_space_servable`] refuses a space the operator took down
//!   (V070), the per-space counterpart to [`require_serviceable_caller`]'s account-level one and
//!   the only lever that reaches a space whose authority is a foreign server. Every seam above
//!   applies it *after* authenticating, and the write choke point re-reads the same row inside
//!   its commit transaction.
//!
//! * **Credential issuance policy** — [`authorize_credential_request`] is the two-perimeter gate
//!   behind `authorizeSpaceSync`, both decided by the space's [`SpacePolicy`]: the app perimeter
//!   (memberspace's `allowedApps`, matched against the client_id `auth::client_attestation`
//!   verified) and then the account perimeter (personalspace admits the authority alone,
//!   memberspace its public flags and member list, managedspace whatever its managing app's
//!   `checkAccess` answers — denying on any failure to get an answer). A request with no
//!   delegation token names no account, which only a `publicRead` memberspace (or a managing app
//!   that answers yes without one) admits.
//! * **Account status** — a repo read by anyone but its owner answers `RepoTakendown` /
//!   `RepoDeactivated` for a writer that is not active ([`require_available_repo`]), and the
//!   authority's own status gates only `authorizeSpaceSync` and `listWriters`
//!   ([`require_active_space_host`]): a credential already issued keeps reading the other
//!   writers' repos until it expires. A taken-down caller's own credential answers
//!   `AccountTakedown`.
//!
//! Both account-key-signed token shapes share `jwt.rs`'s [`sign_jwt`] / [`verify_did_key_jwt`]
//! core with service auth.

use axum::http::{HeaderMap, Method, Uri};
use common::{ApiError, ApiResultExt, ErrorCode};
use custos_core::CoreState;
use serde_json::Value;

use crate::db::space_jti::{insert_jti_if_absent, SpaceJtiScope};
use crate::db::spaces::{self, SpaceRow};
use crate::policy::SpacePolicy;
use custos_core::identity::resolution::{
    atproto_verification_key, refresh_did_document_after_signature_mismatch, resolve_did_document,
    service_endpoint,
};
use custos_core::space_uri::SpaceRef;
use custos_db::accounts::AccountLifecycle;

use super::http_signature::{require_audience, verify_credential_signature};
use custos_core::auth::bearer::{extract_access_token, extract_space_credential};
use custos_core::auth::extractors::AuthenticatedUser;
use custos_core::auth::jwt::{
    peek_jwt_iss, peek_jwt_typ, random_jti, sign_jwt, verify_did_key_jwt, AuthScope, DidKeyJwt,
    DidKeyJwtError, ServiceAuthError,
};
use custos_core::auth::oauth_scopes::{self, SpaceOp, SpaceRequest};

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

/// How long a `notifyCredentialsRevoked` revocation is kept: past the last instant any credential
/// carrying the jti could verify (issued up to the skew ahead, living at most the maximum TTL).
pub const CREDENTIAL_REVOCATION_RETENTION_SECS: u64 =
    SPACE_CREDENTIAL_MAX_TTL_SECS + CLOCK_SKEW_SECS;

/// The authority addressed as space host — the audience of a delegation token or client
/// attestation for `space`. The space host is the authority's PDS, like any other account's.
pub fn space_host_aud(space: &SpaceRef) -> String {
    format!("{}#atproto_pds", space.authority)
}

// ── OAuth admission ──────────────────────────────────────────────────────────

/// Authenticate a caller of a space method that names no one repo (`listSpaces`).
///
/// Runs the shared access-auth path, so the RFC 9449 scheme ↔ `cnf.jkt` binding rules are
/// identical to every other authenticated route's, then refuses an app-password session and
/// applies the account-lifecycle gate below. Every account-credential arm of every space seam
/// routes through here, so this is the one place either gate has to hold.
///
/// Only a full-access token (a full session or an OAuth grant) is admitted. An app-password
/// session, privileged or not, answers 400 `InvalidToken` ("Bad token scope"): the reference
/// authorizes every account-session space and memberspace method with `scopes: ACCESS_FULL`.
/// It runs before the lifecycle gate because the reference refuses the scope while verifying
/// the token, before it looks at the account.
pub async fn authenticate_space_caller(
    state: &CoreState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
) -> Result<AuthenticatedUser, ApiError> {
    let user = custos_core::auth::authenticate_access(headers, method, uri, state)?;
    if user.scope != AuthScope::Access {
        return Err(ApiError::new(ErrorCode::BadTokenScope, "Bad token scope"));
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
/// Called from [`authenticate_space_caller`].
pub async fn require_serviceable_caller(state: &CoreState, did: &str) -> Result<(), ApiError> {
    match custos_db::accounts::account_lifecycle(&state.db, did).await? {
        Some(AccountLifecycle::Active | AccountLifecycle::Deactivated) => Ok(()),
        Some(AccountLifecycle::TakenDown | AccountLifecycle::Suspended) => {
            tracing::warn!(did = %did, "space call: account is in a moderation state");
            Err(ApiError::new(
                ErrorCode::AccountTakedown,
                "account has been taken down",
            ))
        }
        None => {
            tracing::warn!(did = %did, "space call: account missing");
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
    state: &CoreState,
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
/// * A **space credential** — `Authorization: Atproto-Space-Credential <credential>` plus its
///   signature — reads any repo in the space it names. Only the authority issues one, and only
///   after deciding the holder may read the space; a repo host keeps no member list of its own
///   to consult. The request's audience must be `repo` (see [`authenticate_space_credential`]).
///   Because this caller is not the owner, the repo must be an active local account's
///   ([`require_available_repo`]), where the owner could still read it.
pub async fn authenticate_space_read(
    state: &CoreState,
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
    require_available_repo(state, repo).await?;

    Ok(SpaceReader::Credential(credential))
}

/// Authenticate access to a space *itself* on the space host (no repo named — `listWriters` is
/// so far the only one).
///
/// The same two arms as [`authenticate_space_read`]: an account credential must carry a
/// `read_self` grant for the space *and* belong to the space's authority (the reference's
/// `assertSpaceScope` + `assertSpaceAuthority` — a member hosted here still presents a space
/// credential, like a member hosted anywhere else); a space credential for the space is
/// accepted when its signature is addressed to the authority.
///
/// The authority's account status is not checked here: it gates only `authorizeSpaceSync` and
/// `listWriters`, each of which applies [`require_active_space_host`] itself.
pub async fn authenticate_space_access(
    state: &CoreState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    space: &SpaceRef,
) -> Result<SpaceReader, ApiError> {
    let Some(token) = presented_space_credential(headers)? else {
        let user =
            authenticate_space_authority(state, headers, method, uri, space, SpaceOp::ReadSelf)
                .await?;
        return Ok(SpaceReader::User(user));
    };
    let credential =
        authenticate_space_credential(state, headers, token, space, &space.authority).await?;
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
/// `SpaceNotFound`, never `SpaceDeleted`: `SpaceDeleted` is the spec's durable "drop your copy"
/// signal, and a takedown is reversible. It is also the reply an unknown
/// space gets, so which spaces an operator refuses is not disclosed. Called *after*
/// authentication at every seam, so it can never become an unauthenticated probe.
///
/// Writes are not checked here — `space_record_write`'s choke point reads the same row inside
/// its commit transaction, where a concurrent takedown cannot land between check and commit.
pub async fn require_space_servable(state: &CoreState, space: &SpaceRef) -> Result<(), ApiError> {
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

/// Refuse to act as space host for an authority that is not an active local account: the
/// reference's `assertActiveSpaceHost`, applied by `authorizeSpaceSync` and `listWriters` alone.
///
/// No local account is `SpaceNotFound`. A taken-down (or suspended) authority is
/// `RepoTakendown` and a deactivated one `RepoDeactivated` — never `SpaceDeleted`, the spec's
/// durable "drop your copy" signal, since either state can be reversed.
pub async fn require_active_space_host(
    state: &CoreState,
    space: &SpaceRef,
) -> Result<(), ApiError> {
    let Some(lifecycle) =
        custos_db::accounts::account_lifecycle(&state.db, &space.authority).await?
    else {
        return Err(ApiError::new(ErrorCode::SpaceNotFound, "space not found"));
    };
    match unavailable_repo(lifecycle, &space.authority) {
        None => Ok(()),
        Some(err) => {
            tracing::warn!(
                space = %space.uri,
                authority = %space.authority,
                "space host: authority is not an active account"
            );
            Err(err)
        }
    }
}

/// Refuse a read of `repo`'s space repo by anyone but its owner unless the owner is an active
/// local account: `RepoNotFound` with no local account, `RepoTakendown` for a taken-down (or
/// suspended) one, `RepoDeactivated` for a deactivated one — the reference's
/// `assertRepoAvailability`.
async fn require_available_repo(state: &CoreState, repo: &str) -> Result<(), ApiError> {
    match custos_db::accounts::account_lifecycle(&state.db, repo).await? {
        None => Err(repo_not_found(repo)),
        Some(lifecycle) => unavailable_repo(lifecycle, repo).map_or(Ok(()), Err),
    }
}

/// The reply a repo (or a space authority) in `lifecycle` gets when it may not be served, or
/// `None` when it is active.
fn unavailable_repo(lifecycle: AccountLifecycle, did: &str) -> Option<ApiError> {
    match lifecycle {
        AccountLifecycle::Active => None,
        AccountLifecycle::TakenDown | AccountLifecycle::Suspended => Some(ApiError::new(
            ErrorCode::RepoTakendown,
            format!("repo has been taken down: {did}"),
        )),
        AccountLifecycle::Deactivated => Some(ApiError::new(
            ErrorCode::RepoDeactivated,
            format!("repo has been deactivated: {did}"),
        )),
    }
}

/// Authenticate a space management call (or authority-only read): an account credential whose
/// grant covers `op` on `space`, held by the space's authority.
///
/// Grant first, authority second, as the reference orders them: an app without the `manage`
/// grant learns `InsufficientScope` whether or not the space is its user's. Not the
/// authority is `NotAuthorized` — a precondition failure, not an authentication one.
pub async fn authenticate_space_authority(
    state: &CoreState,
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
            ErrorCode::NotAuthorized,
            "Not the space authority",
        ));
    }
    // Last, so the authority of a taken-down space learns no more than a stranger does. Applies to
    // `deleteSpace` too: the operator's refusal already stops the space being served, and a
    // restore has to be able to put it back exactly as it was.
    require_space_servable(state, space).await?;
    Ok(user)
}

/// The space credential a request presents, if it takes the credential arm at all: the token
/// in `Authorization: Atproto-Space-Credential <credential>`. A space credential under any other
/// scheme is refused outright rather than handed to the OAuth arm — that is the pre-RFC 9421 DPoP shape,
/// and naming it is kinder than the OAuth arm's generic signature failure.
fn presented_space_credential(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    if let Some(token) = extract_space_credential(headers) {
        return Ok(Some(token));
    }
    if let Ok((_, token)) = extract_access_token(headers) {
        if peek_jwt_typ(token).as_deref() == Some(SPACE_CREDENTIAL_TYP) {
            return Err(ApiError::new(
                ErrorCode::InvalidToken,
                "space credential must use the Atproto-Space-Credential authorization scheme",
            ));
        }
    }
    Ok(None)
}

/// The credential arm shared by the seams above: `token` (from `Authorization:
/// Atproto-Space-Credential`) must be a credential for `space`, and the request must carry an
/// `atproto-space-credential` signature over `Authorization` and `Atproto-Space-Audience` by the
/// credential's `cnf.kid`, with that
/// audience equal to `audience` — the DID this request is for. No nonce and no replay store:
/// the audience is the binding, and reuse against it is allowed until the credential expires.
async fn authenticate_space_credential(
    state: &CoreState,
    headers: &HeaderMap,
    token: &str,
    space: &SpaceRef,
    audience: &str,
) -> Result<VerifiedCredential, ApiError> {
    // The reference's order: the credential (structure, the other-space filter, then the issuer
    // and its signature), then the request's signature, revocation, and last the audience.
    let credential = verify_space_credential(state, token, space, unix_now()?).await?;
    let presented = verify_credential_signature(headers, &credential.kid)?;
    let revoked = crate::db::space_jti::is_credential_revoked(
        &state.db,
        &space.uri,
        &credential.jti,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, "failed to read credential revocations");
        ApiError::new(ErrorCode::InternalError, "internal server error")
    })?;
    if revoked {
        return Err(ApiError::new(
            ErrorCode::CredentialRevoked,
            "space credential has been revoked",
        ));
    }
    require_audience(presented, audience)?;

    // Charged last, on the *verified* key, so unauthenticated garbage cannot drain a holder's
    // budget.
    state
        .rate_limiter
        .check_space_credential(&credential.kid)
        .inspect_err(|_| {
            state.metrics.rate_limit_rejections.add(
                1,
                &[custos_core::metrics::label(
                    custos_core::metrics::names::LABEL_LIMITER,
                    "space_credential",
                )],
            );
        })?;

    Ok(credential)
}

/// A credential for some other space: the reference's `InvalidCredential` (400), a request
/// error rather than an auth failure.
fn other_space() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidCredential,
        "space credential is for a different space",
    )
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
/// `user` comes from [`authenticate_space_caller`], which has already refused an app-password
/// session. A full session's `com.atproto.access` claim covers every space operation, so the
/// matcher admits it; an OAuth grant is matched operation by operation.
pub async fn require_space_grant(
    state: &CoreState,
    user: &AuthenticatedUser,
    space: &SpaceRef,
    op: SpaceOp<'_>,
) -> Result<(), ApiError> {
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
/// `aud` = [`space_host_aud`]; no `lxm` (a service-auth token is not a delegation
/// token); `exp` in the future and within [`DELEGATION_TOKEN_MAX_TTL_SECS`]; and a non-empty
/// `jti` not yet seen on this surface. Every verification failure is the lexicon's
/// `InvalidDelegationToken`; a failure to *resolve* the issuer (unknown or deactivated DID,
/// PLC directory unreachable) keeps its own code and status, so an upstream outage never reads
/// as the client's fault.
pub async fn verify_delegation_token(
    state: &CoreState,
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
        .map_err(|DidJwtFailure { error: e, .. }| {
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
/// `did:key` `key_id` (the request's `credentialKey`). `sign` is the authority's `#atproto`
/// signing key.
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
        "kid": "#atproto",
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
    /// The bound key (`cnf.kid`), a `did:key`.
    pub kid: String,
    /// The revocation id, checked by [`authenticate_space_credential`] after the request's own
    /// signature, as the reference orders it.
    jti: String,
}

/// A space credential's claims that passed the structural checks, read before its signature
/// is verified. The signature later covers these exact bytes, so nothing read here is trusted
/// on its own until then.
struct CredentialClaims {
    iss: Value,
    sub: String,
    kid: String,
    jti: String,
}

/// The structural checks, in the reference's order (`parseSpaceToken` then the time checks in
/// `verifySpaceToken`, `packages/space/src/credential.ts`): three segments with JSON header and
/// payload; `typ`; an `alg`; header `kid` `#atproto`; an `iss`; a `sub`; a numeric `exp`; a
/// `cnf.kid`; a `jti`; `exp` after `iat` and within [`SPACE_CREDENTIAL_MAX_TTL_SECS`] of it;
/// `iat` not in the future; not expired. Pure: nothing here resolves a DID.
fn check_credential_structure(token: &str, now: u64) -> Result<CredentialClaims, ApiError> {
    let fail = |code: ErrorCode, msg: &str| ApiError::new(code, msg);
    let bad = |msg: &str| fail(ErrorCode::BadJwt, msg);
    let present = |v: &Value| !v.is_null() && v.as_str() != Some("");

    let (3, Some(header), Some(claims)) = (
        token.split('.').count(),
        peek_jwt_header(token),
        peek_jwt_payload(token),
    ) else {
        return Err(bad("malformed space credential"));
    };
    if header.get("typ").and_then(Value::as_str) != Some(SPACE_CREDENTIAL_TYP) {
        return Err(fail(
            ErrorCode::BadJwtType,
            "space credential typ must be atproto-space-credential+jwt",
        ));
    }
    if header
        .get("alg")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(bad("space credential has no alg"));
    }
    if header.get("kid").and_then(Value::as_str) != Some("#atproto") {
        return Err(bad("space credential kid must be #atproto"));
    }
    let iss = claims
        .get("iss")
        .filter(|i| present(i))
        .ok_or_else(|| fail(ErrorCode::BadJwtIss, "space credential has no issuer"))?
        .clone();
    let sub = claims
        .get("sub")
        .filter(|s| present(s))
        .and_then(Value::as_str)
        .ok_or_else(|| fail(ErrorCode::BadJwtSub, "space credential has no sub"))?
        .to_string();
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("space credential has no numeric exp"))?;
    let kid = claims
        .get("cnf")
        .and_then(|c| c.get("kid"))
        .and_then(Value::as_str)
        .filter(|k| k.starts_with("did:key:"))
        .ok_or_else(|| {
            fail(
                ErrorCode::BadJwtCnf,
                "space credential has no cnf.kid binding",
            )
        })?
        .to_string();
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty())
        .ok_or_else(|| bad("space credential has no jti"))?
        .to_string();
    let iat = claims.get("iat").and_then(Value::as_u64);
    if !iat.is_some_and(|iat| exp > iat && exp - iat <= SPACE_CREDENTIAL_MAX_TTL_SECS) {
        return Err(bad("invalid space credential lifetime"));
    }
    if iat.is_some_and(|iat| iat > now + CLOCK_SKEW_SECS) {
        return Err(bad("space credential issued in the future"));
    }
    if exp <= now {
        return Err(fail(ErrorCode::JwtExpired, "space credential has expired"));
    }
    Ok(CredentialClaims { iss, sub, kid, jti })
}

/// Verify a space credential for `space` as a repo host: [`check_credential_structure`]; then
/// that its `sub` is a space reference naming `space`; then the signature against the issuer's
/// `#atproto` key (cache-first, force-refreshed and retried once on a mismatch — a foreign
/// authority may be ES256K, which the shared core accepts); then that space anchored on `iss`.
/// Revocation and the request's own signature are [`authenticate_space_credential`]'s, after
/// this.
///
/// Only [`authenticate_space_credential`] may call this — the proof-of-possession check that
/// makes a verified credential usable lives there; this function is private to hold that.
///
/// Each failure answers the reference's name for it (`BadJwt`, `BadJwtType`, `BadJwtIss`,
/// `BadJwtSub`, `BadJwtCnf`, `BadJwtSignature`, `JwtExpired`, all 401); an issuer that does not
/// resolve, or whose document has no `#atproto` key, is `BadJwtIss`.
///
/// **Divergences** (module doc): a `sub` that is not a space reference (`BadJwtSub`) and a
/// well-formed credential for another space (`InvalidCredential`, 400) are both answered before
/// the signatures are checked, so an unsigned token never drives DID resolution (a cache miss
/// plus the force-refresh retry is two upstream fetches per request). The structural checks
/// come first, so a malformed token still answers its own name.
async fn verify_space_credential(
    state: &CoreState,
    token: &str,
    space: &SpaceRef,
    now: u64,
) -> Result<VerifiedCredential, ApiError> {
    let fail = |code: ErrorCode, msg: &str| ApiError::new(code, msg);
    let bad = |msg: &str| fail(ErrorCode::BadJwt, msg);

    let claims = check_credential_structure(token, now)?;
    // A `sub` that is no space reference at all is `BadJwtSub` here rather than after the
    // signatures (where the reference checks it), so the other-space filter only ever answers
    // for a credential that names a space.
    let named = custos_core::space_uri::parse_space_ref(&claims.sub).ok_or_else(|| {
        fail(
            ErrorCode::BadJwtSub,
            "space credential sub is not a space reference",
        )
    })?;
    if named.uri != space.uri {
        return Err(other_space());
    }
    // A non-DID `iss` is `BadJwt`, as the reference's resolver throws on it.
    let iss = claims
        .iss
        .as_str()
        .and_then(|i| common::Did::parse(i).ok())
        .ok_or_else(|| bad("space credential issuer is not a DID"))?;

    // An issuer that does not resolve is `BadJwtIss` (401), not the resolver's own code; a
    // server fault stays one.
    verify_did_jwt_resolving_key(state, token, &iss, &atproto_verification_key)
        .await
        .map_err(|DidJwtFailure { kind, error }| match kind {
            DidJwtFault::Signature => fail(ErrorCode::BadJwtSignature, error.message()),
            DidJwtFault::Malformed => bad(error.message()),
            DidJwtFault::NoKey => fail(ErrorCode::BadJwtIss, error.message()),
            DidJwtFault::Resolution if *error.code() == ErrorCode::InternalError => error,
            DidJwtFault::Resolution => fail(
                ErrorCode::BadJwtIss,
                &format!(
                    "could not resolve the space credential issuer: {}",
                    error.message()
                ),
            ),
        })?;

    if named.authority != iss {
        return Err(fail(
            ErrorCode::BadJwtIss,
            "space credential issuer is not the space's authority",
        ));
    }

    Ok(VerifiedCredential {
        kid: claims.kid,
        jti: claims.jti,
    })
}

// ── Credential issuance policy ───────────────────────────────────────────────

/// Decide, as the space authority, whether an app-and-account pair may be issued a credential
/// for `space`. `account` is the delegation token's issuer, `None` when the request carried no
/// delegation token; `client_id` is the *attested* client, `None` when the request carried no
/// client attestation.
///
/// Two perimeters, and the app clears its one first: memberspace's `allowedApps` is decided from
/// the stored policy alone, so an app that is not allowed is refused before a third-party
/// managing app is ever told this user asked. The authority is deliberately **not** exempt from
/// the app perimeter — an authority that closed its space to all but two apps meant that for
/// itself too.
///
/// The account perimeter is the policy's read decision ([`policy_admits`]), which the authority
/// always passes.
pub async fn authorize_credential_request(
    state: &CoreState,
    space: &SpaceRow,
    policy: &SpacePolicy,
    account: Option<&str>,
    client_id: Option<&str>,
) -> Result<(), ApiError> {
    if !policy.app_authorized(client_id) {
        return Err(ApiError::new(
            ErrorCode::AppNotAuthorized,
            "Application not authorized for this space",
        ));
    }
    if policy_admits(state, space, policy, Access::Read, account, client_id).await? {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::AccountNotAuthorized,
            "the requesting account is not authorized for this space",
        ))
    }
}

/// Whether the authority tracks and forwards `repo_did`'s write notifications: the policy's
/// write decision.
pub async fn authorize_write_notification(
    state: &CoreState,
    space: &SpaceRow,
    policy: &SpacePolicy,
    repo_did: &str,
) -> Result<bool, ApiError> {
    policy_admits(state, space, policy, Access::Write, Some(repo_did), None).await
}

/// Which side of a space a policy decision is for.
#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
}

/// Whether `space`'s policy admits `did` for `access` (the reference's `authorizeRepo`). `did`
/// is `None` for a read with no delegation token, which only a policy that does not gate on the
/// account admits.
///
/// The authority is admitted under every policy: it is the only party who can reconfigure the
/// space, so it must not be able to lock itself out. Personalspace admits no one else.
/// Memberspace admits anyone to read under `publicRead`, otherwise a member with the matching
/// bit; a write needs the member's write bit when the DID is a member (a member without write
/// access stays excluded even under `publicWrite`), and `publicWrite` otherwise. Managedspace
/// hands the decision to its managing app.
async fn policy_admits(
    state: &CoreState,
    space: &SpaceRow,
    policy: &SpacePolicy,
    access: Access,
    did: Option<&str>,
    client_id: Option<&str>,
) -> Result<bool, ApiError> {
    if did == Some(space.authority_did.as_str()) {
        return Ok(true);
    }
    Ok(match policy {
        SpacePolicy::Personal => false,
        SpacePolicy::Member(member_policy) => {
            if matches!(access, Access::Read) && member_policy.public_read {
                return Ok(true);
            }
            let Some(did) = did else {
                return Ok(false);
            };
            let member = spaces::get_member(&state.db, &space.uri, did)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, space = %space.uri, "failed to read space members");
                    ApiError::new(ErrorCode::InternalError, "internal server error")
                })?;
            match access {
                Access::Read => member.is_some_and(|m| m.read),
                Access::Write => member_admits_write(member_policy, member),
            }
        }
        SpacePolicy::Managed(managed) => {
            check_access(state, space, &managed.managing_app, did, client_id)
                .await
                .is_some_and(|answer| match access {
                    Access::Read => answer.read,
                    Access::Write => answer.write,
                })
        }
    })
}

/// A memberspace's write rule for a non-authority: a member needs its `write` bit (a member
/// without it stays excluded even under `publicWrite`), and a non-member needs `publicWrite`.
/// Shared with the write path's in-transaction writer-set gate, so the two can't drift.
pub(crate) fn member_admits_write(
    policy: &crate::policy::MemberPolicy,
    member: Option<crate::policy::Access>,
) -> bool {
    match member {
        Some(member) => member.write,
        None => policy.public_write,
    }
}

/// The lexicon method a managedspace access check invokes.
const CHECK_ACCESS_LXM: &str = "com.atproto.managedspace.checkAccess";

/// How long the authority waits on a managing app before treating it as unreachable. Credential
/// minting is interactive, and a stalled app must not hold the request open.
const CHECK_ACCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask a managedspace's managing app for `repo`'s read and write access, as the authority and
/// under service auth (`com.atproto.managedspace.checkAccess`). Resolved on every call; nothing
/// is cached. `repo` is omitted for a read with no delegation token. `client_id` is sent for a
/// read only: a write notification does not identify the app that made the write.
///
/// **Every** failure denies (`None`) — unresolvable DID, no published endpoint, transport error,
/// timeout, non-2xx, a body without both booleans. Failing open would hand out credentials for
/// exactly the spaces that asked for the strictest gate.
///
/// `managingApp` is a `did#serviceId` reference. A bare DID (only possible on a policy V079
/// carried over) uses the DID's `#atproto_pds` entry. The `aud` is the reference as published,
/// fragment and all, so a multi-service app can tell which of its services was addressed.
async fn check_access(
    state: &CoreState,
    space: &SpaceRow,
    managing_app: &str,
    repo: Option<&str>,
    client_id: Option<&str>,
) -> Option<crate::policy::Access> {
    let (did, fragment) = managing_app
        .split_once('#')
        .unwrap_or((managing_app, "atproto_pds"));

    let deny = |reason: &str| {
        tracing::warn!(
            space = %space.uri,
            managing_app = %managing_app,
            repo = ?repo,
            reason,
            "managing app check failed; denying",
        );
        None
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
    let Ok(token) = custos_core::auth::signing_key::mint_account_service_auth(
        &state.db,
        master_key,
        &space.authority_did,
        managing_app,
        Some(CHECK_ACCESS_LXM),
        now,
        now + 60,
    )
    .await
    else {
        return deny("could not sign service auth as the authority");
    };

    let Ok(mut url) = url::Url::parse(&format!(
        "{}/xrpc/{CHECK_ACCESS_LXM}",
        endpoint.trim_end_matches('/')
    )) else {
        return deny("the managing app's published endpoint is not a URL");
    };
    url.query_pairs_mut().append_pair("space", &space.uri);
    if let Some(repo) = repo {
        url.query_pairs_mut().append_pair("repo", repo);
    }
    if let Some(client_id) = client_id {
        url.query_pairs_mut().append_pair("clientId", client_id);
    }
    // The endpoint comes from a DID document the space's own policy points at, so it is
    // caller-influenced: the hardened client is what decides which address this reaches.
    let response = state
        .hardened_http_client
        .get(&custos_core::identity::proxy::CallerUrl::new(url))
        .bearer_auth(token)
        .timeout(CHECK_ACCESS_TIMEOUT)
        .send()
        .await;
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => return deny(&format!("managing app answered HTTP {}", response.status())),
        Err(e) => return deny(&format!("could not reach the managing app: {e}")),
    };
    let body = match response.json::<Value>().await {
        Ok(body) => body,
        Err(e) => return deny(&format!("managing app answer was not readable: {e}")),
    };
    match (
        body.get("read").and_then(Value::as_bool),
        body.get("write").and_then(Value::as_bool),
    ) {
        (Some(read), Some(write)) => Some(crate::policy::Access { read, write }),
        _ => deny("managing app answer lacks read and write"),
    }
}

// ── Shared plumbing ──────────────────────────────────────────────────────────

/// Why [`verify_did_jwt_resolving_key`] refused a token: `error`, what a caller answers by
/// default, and `kind`, which failure it was, for a caller that names it (the space credential).
#[derive(Debug)]
struct DidJwtFailure {
    kind: DidJwtFault,
    error: ApiError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DidJwtFault {
    /// The issuer's DID document could not be resolved; `error` is the resolver's own.
    Resolution,
    /// The resolved document has no verification key `pick_key` accepts.
    NoKey,
    /// The signature does not verify against the issuer's key, even after the refresh retry, or
    /// cannot (`alg` outside the allowlist or not the key's curve, or not 64 bytes).
    Signature,
    /// The token is not a well-formed JWT, or its signature segment does not decode.
    Malformed,
}

impl DidJwtFailure {
    fn new(kind: DidJwtFault, error: ApiError) -> Self {
        Self { kind, error }
    }
}

impl From<DidKeyJwtError> for DidJwtFailure {
    fn from(err: DidKeyJwtError) -> Self {
        match err {
            // The same error service auth's conversion gives a signature that never verified.
            DidKeyJwtError::SignatureMismatch => DidJwtFailure::new(
                DidJwtFault::Signature,
                ServiceAuthError::SignatureMismatch.into(),
            ),
            DidKeyJwtError::Unverifiable(e) => DidJwtFailure::new(DidJwtFault::Signature, e),
            DidKeyJwtError::Malformed(e) => DidJwtFailure::new(DidJwtFault::Malformed, e),
        }
    }
}

/// Resolve `iss`'s DID document, pick the verification key with `pick_key`, and verify `token`
/// against it — force-refreshing the cached document and retrying once on a signature
/// mismatch, the same fossil-key healing `service_auth::verify_service_auth_resolving_key`
/// does (the `did_documents` cache has no TTL) — through the one shared, cool-down-bounded
/// `refresh_did_document_after_signature_mismatch` seam.
///
/// A failure to resolve the issuer at all (`DidNotFound`, `DidDeactivated`,
/// `PlcDirectoryError`, …) carries its own code and status — an unreachable PLC directory is not
/// an invalid token. A failed *refresh* after a signature mismatch does not: the cached document
/// was there and the signature did not verify against it, so that verdict stands — as does a
/// refresh the per-DID cool-down suppressed. Verification failures are `InvalidToken`; callers
/// re-code those alone, by [`DidJwtFailure::kind`] where they name the failure.
async fn verify_did_jwt_resolving_key(
    state: &CoreState,
    token: &str,
    iss: &str,
    pick_key: &(dyn Fn(&Value) -> Option<crypto::DidKeyUri> + Sync),
) -> Result<DidKeyJwt, DidJwtFailure> {
    let key_in = |doc: &Value| {
        pick_key(doc).ok_or_else(|| {
            DidJwtFailure::new(
                DidJwtFault::NoKey,
                ApiError::new(
                    ErrorCode::InvalidToken,
                    "the issuer's DID document has no matching verification key",
                ),
            )
        })
    };
    let cached = resolve_did_document(state, iss)
        .await
        .map_err(|e| DidJwtFailure::new(DidJwtFault::Resolution, e))?;
    match verify_did_key_jwt(token, &key_in(&cached)?) {
        Ok(jwt) => Ok(jwt),
        Err(DidKeyJwtError::SignatureMismatch) => {
            match refresh_did_document_after_signature_mismatch(state, iss).await {
                Ok(fresh) => Ok(verify_did_key_jwt(token, &key_in(&fresh)?)?),
                Err(refresh_error) => {
                    tracing::debug!(
                        iss = %iss,
                        error = %refresh_error,
                        "force-refresh failed; keeping the signature-mismatch verdict"
                    );
                    Err(DidJwtFailure::new(
                        DidJwtFault::Signature,
                        ApiError::new(
                            ErrorCode::InvalidToken,
                            "token signature does not verify against the issuer's published key",
                        ),
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

pub(crate) use custos_core::time::unix_now;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        access_jwt, app_pass_jwt, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
        SpaceSigKey,
    };
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use custos_core::space_uri::parse_space_ref;
    use custos_db::dids::seed_did_document;

    const AUTHORITY: &str = "did:plc:abc234567abc234567abc234";
    const ALICE: &str = "did:plc:alice";
    const SPACE: &str = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/self";
    const GET_RECORD: &str = "/xrpc/com.atproto.space.getRecord";

    /// A DID document whose `#atproto` Multikey holds `kp`'s public key — what this server
    /// publishes for its own accounts.
    fn did_doc(did: &str, kp: &crypto::P256Keypair) -> Value {
        serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": kp.key_id.0.strip_prefix("did:key:").unwrap(),
            }],
        })
    }

    /// Seed a local account with a repo key and a cached DID document carrying that key.
    async fn seed_identity(state: &CoreState, did: &str) -> repo_engine::CommitSigner {
        let kp = seed_account_with_repo(&state.db, did).await;
        seed_did_document(&state.db, did, did_doc(did, &kp)).await;
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
        state: &CoreState,
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
            "did:plc:abc234567abc234567abc234#atproto_pds"
        );
    }

    #[tokio::test]
    async fn delegation_token_mints_verifies_and_is_single_use() {
        let state = state_with_master_key().await;
        let alice = seed_identity(&state, ALICE).await;
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
            "did:plc:abc234567abc234567abc234#atproto_pds"
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
        assert_eq!(err.status_code(), 400);
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
        let service_auth = custos_core::auth::jwt::mint_service_auth_jwt(
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
        let alice = seed_identity(&state, ALICE).await;
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
                "aud": "did:plc:alice#atproto_pds",
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
        seed_identity(&state, ALICE).await;
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
        let authority = seed_identity(&state, AUTHORITY).await;
        // The repo being read belongs to alice, an active local account; the credential holder
        // is neither alice nor the authority.
        seed_identity(&state, ALICE).await;
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
        assert_eq!(hdr["kid"], "#atproto");
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
                assert_eq!(c.kid, key.key_id());
            }
            other => panic!("expected the credential arm, got {other:?}"),
        }

        // The same signed request again is fine: replay against one audience is allowed until
        // expiry, by spec.
        assert!(read(&state, &signed, ALICE).await.is_ok());

        // A signature by a key other than cnf.kid, or none at all, is the reference's
        // BadSpaceSignature.
        let other_key = SpaceSigKey::generate();
        let mut unsigned = signed.clone();
        unsigned.remove("signature");
        unsigned.remove("signature-input");
        for headers in [other_key.credential_headers(&credential, ALICE), unsigned] {
            let err = read(&state, &headers, ALICE).await.unwrap_err();
            assert_eq!(*err.code(), ErrorCode::BadSpaceSignature);
            assert_eq!(err.status_code(), 401);
        }

        // The audience must be the repo the request reads: a request signed for alice cannot
        // read another repo, nor one signed for anyone else read alice's.
        seed_identity(&state, "did:plc:carol").await;
        for (audience, repo) in [(ALICE, "did:plc:carol"), (AUTHORITY, ALICE)] {
            let err = read(&state, &key.credential_headers(&credential, audience), repo)
                .await
                .unwrap_err();
            assert_eq!(
                *err.code(),
                ErrorCode::BadSpaceAudience,
                "{audience} → {repo}"
            );
        }

        // A repo with no local account reads as RepoNotFound for a credential holder.
        let err = read(
            &state,
            &key.credential_headers(&credential, "did:plc:stranger"),
            "did:plc:stranger",
        )
        .await
        .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::RepoNotFound);
    }

    /// A writer that is not active answers a credential holder's read with its status, as the
    /// reference's `assertRepoAvailability` does; the owner could still read it themselves. The
    /// authority's own status does not gate the read: an issued credential keeps reading the
    /// other writers' repos until it expires.
    #[tokio::test]
    async fn a_credential_read_answers_the_writers_status() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        seed_identity(&state, ALICE).await;
        let key = SpaceSigKey::generate();
        let credential = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            unix_now().unwrap(),
        );
        let set = |did: &'static str, column: &'static str, value: Option<&'static str>| {
            let db = state.db.clone();
            async move {
                sqlx::query(&format!("UPDATE accounts SET {column} = ? WHERE did = ?"))
                    .bind(value)
                    .bind(did)
                    .execute(&db)
                    .await
                    .unwrap();
            }
        };
        let signed = key.credential_headers(&credential, ALICE);

        set(AUTHORITY, "taken_down_at", Some("2026-01-01T00:00:00Z")).await;
        assert!(
            read(&state, &signed, ALICE).await.is_ok(),
            "the authority's status does not gate a repo read"
        );

        for (column, code) in [
            ("taken_down_at", ErrorCode::RepoTakendown),
            ("suspended_at", ErrorCode::RepoTakendown),
            ("deactivated_at", ErrorCode::RepoDeactivated),
        ] {
            set(ALICE, column, Some("2026-01-01T00:00:00Z")).await;
            let err = read(&state, &signed, ALICE).await.unwrap_err();
            assert_eq!(*err.code(), code, "{column}");
            assert_eq!(err.status_code(), 400, "{column}");
            set(ALICE, column, None).await;
        }
    }

    #[tokio::test]
    async fn space_credential_is_never_bearer_or_dpop() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        seed_identity(&state, ALICE).await;
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
            read(
                &state,
                &headers("Atproto-Space-Credential", &credential),
                ALICE
            )
            .await
            .unwrap_err()
            .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn space_credential_for_another_space_or_wrong_issuer_is_rejected() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let alice = seed_identity(&state, ALICE).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let other =
            parse_space_ref("at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other")
                .unwrap();

        for (cred, code) in [
            // Credential for a different space than the request targets.
            (
                mint_space_credential(|b| authority.sign(b), AUTHORITY, &other, key.key_id(), now),
                ErrorCode::InvalidCredential,
            ),
            // Signed by alice (a valid key, but not the space's authority).
            (
                mint_space_credential(|b| alice.sign(b), ALICE, &space(), key.key_id(), now),
                ErrorCode::BadJwtIss,
            ),
            // Forged: claims iss = authority but signed by alice's key.
            (
                mint_space_credential(|b| alice.sign(b), AUTHORITY, &space(), key.key_id(), now),
                ErrorCode::BadJwtSignature,
            ),
        ] {
            let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
                .await
                .unwrap_err();
            assert_eq!(err.status_code(), code.status_code());
            assert_eq!(*err.code(), code);
        }
    }

    #[tokio::test]
    async fn space_credential_lifetime_is_bounded() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto" });
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
            &space(),
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
                *verify_space_credential(&state, &with(iat, exp), &space(), now)
                    .await
                    .unwrap_err()
                    .code(),
                ErrorCode::BadJwt,
                "iat={iat} exp={exp}"
            );
        }
        // Expired is its own code.
        assert_eq!(
            *verify_space_credential(&state, &with(now - 120, now - 60), &space(), now)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::JwtExpired
        );
    }

    #[tokio::test]
    async fn space_credential_needs_an_unrevoked_jti() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto" });
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

        // Revocation is checked after the request's own signature, as the reference orders it,
        // so it goes through the seam.
        seed_identity(&state, ALICE).await;
        let read_with = |cred: String| {
            let headers = key.credential_headers(&cred, ALICE);
            let state = state.clone();
            async move { read(&state, &headers, ALICE).await }
        };
        assert!(read_with(with(Some("live"))).await.is_ok());
        crate::db::space_jti::revoke_credentials(&state.db, SPACE, &["live".into()], 60)
            .await
            .unwrap();
        for (cred, code) in [
            (with(Some("live")), ErrorCode::CredentialRevoked),
            (with(None), ErrorCode::BadJwt),
        ] {
            assert_eq!(*read_with(cred).await.unwrap_err().code(), code);
        }
    }

    /// Each structural fault answers the reference's name for it.
    #[tokio::test]
    async fn space_credential_claim_faults_answer_the_reference_names() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto" });
        let claims = serde_json::json!({
            "iss": AUTHORITY, "sub": SPACE, "cnf": { "kid": key.key_id() },
            "iat": now, "exp": now + 60, "jti": "faults",
        });
        let edit = |field: &str, value: Value| {
            let mut c = claims.clone();
            if value.is_null() {
                c.as_object_mut().unwrap().remove(field);
            } else {
                c[field] = value;
            }
            sign_jwt(|b| authority.sign(b), &header, &c)
        };
        let mut wrong_typ = header.clone();
        wrong_typ["typ"] = "JWT".into();
        for (cred, code) in [
            ("not.a.jwt".to_string(), ErrorCode::BadJwt),
            (
                sign_jwt(|b| authority.sign(b), &wrong_typ, &claims),
                ErrorCode::BadJwtType,
            ),
            (edit("iss", Value::Null), ErrorCode::BadJwtIss),
            (edit("iss", "not-a-did".into()), ErrorCode::BadJwt),
            (edit("sub", "not-a-space".into()), ErrorCode::BadJwtSub),
            (edit("cnf", Value::Null), ErrorCode::BadJwtCnf),
        ] {
            let err = verify_space_credential(&state, &cred, &space(), now)
                .await
                .unwrap_err();
            assert_eq!(*err.code(), code, "{}", err.message());
            assert_eq!(err.status_code(), 401);
        }
    }

    /// The failures inside the shared JWT verification each answer the reference's name on the
    /// credential path, while the delegation token, which shares that verification, keeps its
    /// one `InvalidDelegationToken` with the message it always had.
    #[tokio::test]
    async fn jwt_verification_faults_are_named_on_the_credential_path_only() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let claims = serde_json::json!({
            "iss": AUTHORITY, "sub": SPACE, "cnf": { "kid": key.key_id() },
            "iat": now, "exp": now + 60, "jti": "jwt-faults",
        });
        let es256k =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256K", "kid": "#atproto" });
        let valid = mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            now,
        );
        let unsigned = valid.rsplit_once('.').unwrap().0;

        for (cred, code) in [
            // `alg` names a curve the authority's P-256 key is not on.
            (
                sign_jwt(|b| authority.sign(b), &es256k, &claims),
                ErrorCode::BadJwtSignature,
            ),
            // A signature segment that is not base64url is malformed; one that decodes to the
            // wrong length reaches the signature check, as in the reference.
            (format!("{unsigned}.not-base64!"), ErrorCode::BadJwt),
            (format!("{unsigned}.YWJj"), ErrorCode::BadJwtSignature),
        ] {
            let err = verify_space_credential(&state, &cred, &space(), now)
                .await
                .unwrap_err();
            assert_eq!(*err.code(), code, "{}", err.message());
            assert_eq!(err.status_code(), 401);
        }

        // An issuer whose document publishes no #atproto key.
        let keyless = "did:plc:keylessauthority0000000";
        seed_did_document(
            &state.db,
            keyless,
            serde_json::json!({ "id": keyless, "verificationMethod": [] }),
        )
        .await;
        let keyless_space =
            parse_space_ref(&format!("at://{keyless}/space/org.example.bucket/x")).unwrap();
        let cred = mint_space_credential(
            |b| authority.sign(b),
            keyless,
            &keyless_space,
            key.key_id(),
            now,
        );
        let err = verify_space_credential(&state, &cred, &keyless_space, now)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::BadJwtIss, "{}", err.message());
        assert_eq!(err.status_code(), 401);

        // The delegation token through the same verification: unchanged.
        let delegation = mint_delegation_token(|b| authority.sign(b), AUTHORITY, &space(), now);
        let (unsigned, _) = delegation.rsplit_once('.').unwrap();
        let mut es256k = header(&delegation);
        es256k["alg"] = "ES256K".into();
        for (token, message) in [
            (format!("{unsigned}.not-base64!"), "invalid token"),
            (
                sign_jwt(|b| authority.sign(b), &es256k, &payload(&delegation)),
                "token algorithm does not match the signing key's curve",
            ),
        ] {
            let err = verify_delegation_token(&state, &token, &space(), now)
                .await
                .unwrap_err();
            assert_eq!(*err.code(), ErrorCode::InvalidDelegationToken);
            assert_eq!(err.message(), message);
        }
    }

    /// The credential is signed by the authority's `#atproto` key and says so: any other `kid`
    /// is refused, whatever key the document publishes under it.
    #[tokio::test]
    async fn credential_kid_must_be_atproto() {
        let state = state_with_master_key().await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let authority = seed_identity(&state, AUTHORITY).await;
        let claims = payload(&mint_space_credential(
            |b| authority.sign(b),
            AUTHORITY,
            &space(),
            key.key_id(),
            now,
        ));
        for (kid, ok) in [
            ("#atproto", true),
            ("#atproto_space", false),
            ("#other", false),
        ] {
            let header =
                serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": kid });
            let cred = sign_jwt(|b| authority.sign(b), &header, &claims);
            assert_eq!(
                verify_space_credential(&state, &cred, &space(), now)
                    .await
                    .is_ok(),
                ok,
                "{kid}"
            );
        }
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
        assert_eq!(*err.code(), ErrorCode::InvalidCredential);
        assert_eq!(err.status_code(), 400);

        // Once that filter passes, an issuer that resolves nowhere is the reference's
        // BadJwtIss, not the resolver's own code.
        let err = verify_space_credential(&state, &cred, &other, now)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::BadJwtIss, "{}", err.message());
        assert_eq!(err.status_code(), 401);
    }

    /// An unparseable token is the reference's `BadJwt` whether or not the request is signed:
    /// the structural checks run before the other-space filter and before the request's own
    /// signature.
    #[tokio::test]
    async fn an_unparseable_credential_answers_bad_jwt() {
        let state = state_with_master_key().await;
        seed_identity(&state, ALICE).await;
        let key = SpaceSigKey::generate();
        let mut unsigned = key.credential_headers("x.y.z", ALICE);
        unsigned.remove("signature");
        unsigned.remove("signature-input");
        for headers in [unsigned, key.credential_headers("x.y.z", ALICE)] {
            let err = read(&state, &headers, ALICE).await.unwrap_err();
            assert_eq!(*err.code(), ErrorCode::BadJwt, "{}", err.message());
            assert_eq!(err.status_code(), 401);
        }
    }

    /// Each structural fault answers its own name even when the credential names another
    /// space: the other-space filter runs only on a credential that is well formed.
    #[tokio::test]
    async fn structural_faults_answer_their_names_before_the_other_space_filter() {
        let state = state_with_master_key().await;
        let authority = seed_identity(&state, AUTHORITY).await;
        seed_identity(&state, ALICE).await;
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let other = "at://did:plc:abc234567abc234567abc234/space/org.example.bucket/other";
        let header =
            serde_json::json!({ "typ": SPACE_CREDENTIAL_TYP, "alg": "ES256", "kid": "#atproto" });
        let claims = serde_json::json!({
            "iss": AUTHORITY, "sub": other, "cnf": { "kid": key.key_id() },
            "iat": now, "exp": now + 60, "jti": "elsewhere",
        });
        let with = |header_edit: (&str, Value), claim_edit: (&str, Value)| {
            let (mut h, mut c) = (header.clone(), claims.clone());
            for (obj, (field, value)) in [(&mut h, header_edit), (&mut c, claim_edit)] {
                if field.is_empty() {
                    continue;
                }
                if value.is_null() {
                    obj.as_object_mut().unwrap().remove(field);
                } else {
                    obj[field] = value;
                }
            }
            sign_jwt(|b| authority.sign(b), &h, &c)
        };
        let none = || ("", Value::Null);
        for (cred, code) in [
            (with(("typ", "JWT".into()), none()), ErrorCode::BadJwtType),
            (with(("alg", Value::Null), none()), ErrorCode::BadJwt),
            (with(("kid", "#other".into()), none()), ErrorCode::BadJwt),
            (with(none(), ("iss", Value::Null)), ErrorCode::BadJwtIss),
            (with(none(), ("sub", Value::Null)), ErrorCode::BadJwtSub),
            (
                with(none(), ("sub", "not-a-space".into())),
                ErrorCode::BadJwtSub,
            ),
            (with(none(), ("exp", Value::Null)), ErrorCode::BadJwt),
            (with(none(), ("cnf", Value::Null)), ErrorCode::BadJwtCnf),
            (with(none(), ("jti", Value::Null)), ErrorCode::BadJwt),
            (with(none(), ("iat", (now + 600).into())), ErrorCode::BadJwt),
            (with(none(), ("exp", (now - 1).into())), ErrorCode::BadJwt),
            // Well formed: the other-space filter answers.
            (with(none(), none()), ErrorCode::InvalidCredential),
        ] {
            let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
                .await
                .unwrap_err();
            assert_eq!(*err.code(), code, "{}", err.message());
        }
        // Expired, with a lifetime that is otherwise valid.
        let mut expired = claims.clone();
        expired["iat"] = (now - 120).into();
        expired["exp"] = (now - 60).into();
        let cred = sign_jwt(|b| authority.sign(b), &header, &expired);
        let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::JwtExpired);
    }

    /// A well-formed credential for another space is refused before any DID is resolved: the
    /// issuer here resolves nowhere, and the PLC directory is never asked.
    #[tokio::test]
    async fn a_credential_for_another_space_resolves_no_did() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let plc = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .expect(0)
            .mount(&plc)
            .await;
        let state = custos_core::test_support::test_state_with_plc_url(plc.uri()).await;
        seed_identity(&state, ALICE).await;
        let ghost = crypto::generate_p256_keypair().unwrap();
        let ghost = repo_engine::CommitSigner::from_bytes(&ghost.private_key_bytes).unwrap();
        let key = SpaceSigKey::generate();
        let now = unix_now().unwrap();
        let elsewhere =
            parse_space_ref("at://did:plc:nobodyhere/space/org.example.bucket/x").unwrap();
        let cred = mint_space_credential(
            |b| ghost.sign(b),
            "did:plc:nobodyhere",
            &elsewhere,
            key.key_id(),
            now,
        );
        let err = read(&state, &key.credential_headers(&cred, ALICE), ALICE)
            .await
            .unwrap_err();
        assert_eq!(*err.code(), ErrorCode::InvalidCredential);
        assert_eq!(err.status_code(), 400);
        plc.verify().await;
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
        // An unrelated grant is refused, and an app-password session is refused outright.
        let repo_only = scoped_access_jwt(&state.jwt_secret, ALICE, "atproto repo:*");
        assert_eq!(
            call(repo_only, own.clone(), ALICE)
                .await
                .unwrap_err()
                .status_code(),
            403
        );
        for privileged in [false, true] {
            let err = call(
                app_pass_jwt(&state.jwt_secret, ALICE, privileged),
                own.clone(),
                ALICE,
            )
            .await
            .unwrap_err();
            assert_eq!(*err.code(), ErrorCode::BadTokenScope);
            assert_eq!(err.status_code(), 400);
            assert_eq!(err.message(), "Bad token scope");
        }
    }

    fn member_policy(
        public_read: bool,
        public_write: bool,
        allowed_apps: Option<Vec<&str>>,
    ) -> SpacePolicy {
        SpacePolicy::Member(crate::policy::MemberPolicy {
            public_read,
            public_write,
            allowed_apps: allowed_apps.map(|apps| apps.into_iter().map(str::to_string).collect()),
            publish_policy: false,
            publish_members: false,
        })
    }

    async fn seeded_row(state: &CoreState, policy: &SpacePolicy) -> SpaceRow {
        crate::test_support::seed_authority_space(&state.db, SPACE, &policy.to_json().to_string())
            .await;
        spaces::get_space(&state.db, SPACE).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn issuance_account_perimeter_under_each_baseline_policy() {
        let state = state_with_master_key().await;
        let members_only = member_policy(false, false, None);
        let row = seeded_row(&state, &members_only).await;
        let issue = |policy: SpacePolicy, did: &'static str| {
            let (state, row) = (state.clone(), row.clone());
            async move { authorize_credential_request(&state, &row, &policy, Some(did), None).await }
        };

        // Memberspace: the authority always may; a non-member may not; a reading member may.
        assert!(issue(members_only.clone(), AUTHORITY).await.is_ok());
        assert_eq!(
            *issue(members_only.clone(), ALICE).await.unwrap_err().code(),
            ErrorCode::AccountNotAuthorized
        );
        spaces::put_member(&state.db, SPACE, ALICE, true, false)
            .await
            .unwrap();
        assert!(issue(members_only.clone(), ALICE).await.is_ok());
        assert!(issue(member_policy(true, false, None), "did:plc:stranger")
            .await
            .is_ok());
        // No delegation token names no account: only `publicRead` admits that.
        for (policy, admitted) in [
            (member_policy(true, false, None), true),
            (members_only.clone(), false),
            (SpacePolicy::Personal, false),
        ] {
            assert_eq!(
                authorize_credential_request(&state, &row, &policy, None, None)
                    .await
                    .is_ok(),
                admitted
            );
        }

        // Personalspace admits the authority alone, members or not.
        assert!(issue(SpacePolicy::Personal, AUTHORITY).await.is_ok());
        assert!(issue(SpacePolicy::Personal, ALICE).await.is_err());

        // Managedspace with no app to ask denies — the policy that defers its decision must
        // never become the one that skips it — and the authority still passes, so a
        // misconfigured managing app cannot lock it out of its own space.
        let managed = SpacePolicy::Managed(crate::policy::ManagedPolicy {
            managing_app: "did:web:unresolvable.invalid#app".to_string(),
            publish_policy: false,
        });
        assert_eq!(
            *issue(managed.clone(), ALICE).await.unwrap_err().code(),
            ErrorCode::AccountNotAuthorized
        );
        assert!(issue(managed, AUTHORITY).await.is_ok());
    }

    /// Reads consult a member's `read` bit and writes its `write` bit, neither borrowing the
    /// other's; `publicWrite` admits a non-member but never a member without write access.
    #[tokio::test]
    async fn reads_and_writes_consult_their_own_member_bits() {
        let state = state_with_master_key().await;
        let policy = member_policy(false, false, None);
        let row = seeded_row(&state, &policy).await;

        spaces::put_member(&state.db, SPACE, ALICE, true, false)
            .await
            .unwrap();
        assert!(
            authorize_credential_request(&state, &row, &policy, Some(ALICE), None)
                .await
                .is_ok()
        );
        assert!(!authorize_write_notification(&state, &row, &policy, ALICE)
            .await
            .unwrap());

        spaces::put_member(&state.db, SPACE, ALICE, false, true)
            .await
            .unwrap();
        assert!(
            authorize_credential_request(&state, &row, &policy, Some(ALICE), None)
                .await
                .is_err()
        );
        assert!(authorize_write_notification(&state, &row, &policy, ALICE)
            .await
            .unwrap());

        let open_writes = member_policy(false, true, None);
        assert!(
            authorize_write_notification(&state, &row, &open_writes, "did:plc:stranger")
                .await
                .unwrap()
        );
        spaces::put_member(&state.db, SPACE, ALICE, true, false)
            .await
            .unwrap();
        assert!(
            !authorize_write_notification(&state, &row, &open_writes, ALICE)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn issuance_app_perimeter_is_memberspace_allowed_apps() {
        let state = state_with_master_key().await;
        const ALLOWED: &str = "https://allowed.example.com/client-metadata.json";
        const OTHER: &str = "https://other.example.com/client-metadata.json";
        let policy = member_policy(true, false, Some(vec![ALLOWED]));
        let row = seeded_row(&state, &policy).await;

        let refusal = |policy: SpacePolicy, did: &'static str, client: Option<&'static str>| {
            let (state, row) = (state.clone(), row.clone());
            async move {
                authorize_credential_request(&state, &row, &policy, Some(did), client)
                    .await
                    .unwrap_err()
                    .code()
                    .clone()
            }
        };

        // No attestation at all, and an attestation naming an app that is not on the list.
        assert_eq!(
            refusal(policy.clone(), ALICE, None).await,
            ErrorCode::AppNotAuthorized
        );
        assert_eq!(
            refusal(policy.clone(), ALICE, Some(OTHER)).await,
            ErrorCode::AppNotAuthorized
        );
        // The authority is NOT exempt from the app perimeter: closing a space to all but one
        // app closed it for the authority too.
        assert_eq!(
            refusal(policy.clone(), AUTHORITY, None).await,
            ErrorCode::AppNotAuthorized
        );
        // The allowed app clears the perimeter, and `publicRead` then admits the user.
        assert!(
            authorize_credential_request(&state, &row, &policy, Some(ALICE), Some(ALLOWED))
                .await
                .is_ok()
        );
        // An empty list admits nothing; an absent one admits any app.
        assert_eq!(
            refusal(
                member_policy(true, false, Some(vec![])),
                ALICE,
                Some(ALLOWED)
            )
            .await,
            ErrorCode::AppNotAuthorized
        );
        assert!(authorize_credential_request(
            &state,
            &row,
            &member_policy(true, false, None),
            Some(ALICE),
            None
        )
        .await
        .is_ok());
    }
}
