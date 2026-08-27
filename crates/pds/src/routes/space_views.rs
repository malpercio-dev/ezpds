// pattern: Imperative Shell

//! Shared handler-free support for the `com.atproto.space.*` and `com.atproto.simplespace.*`
//! routes (routes may not import one another): space-ref parsing, the `validate`-flag record
//! check, stored-block decoding, the `{uri, cid, validationStatus}` shape every write route
//! answers with, and the simplespace config's lexicon ↔ column mapping.
//!
//! Authorization is deliberately *not* here — it lives in `auth/space.rs`, the one seam every
//! space route enters through.

use crate::db::spaces::SpaceRow;
use crate::lexicon::RecordValidation;
use crate::space_record_write::SpaceCommitOutcome;
use crate::space_uri::SpaceRef;
use common::{ApiError, ErrorCode};

/// Parse the `space` a request named.
///
/// The lexicon layer's `space-ref` format has already rejected a malformed one before any
/// handler runs, so this only fails for a caller that reached a handler some other way — but it
/// is also the only way the `(authority, type, skey)` triple is obtained, so nothing downstream
/// can be handed a URI that was never checked.
pub fn parse_space(space: &str) -> Result<SpaceRef, ApiError> {
    crate::space_uri::parse_space_ref(space).ok_or_else(|| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            format!("not a space uri: {space}"),
        )
    })
}

/// `assertValidRecord`-parity validation for a space write, exactly as the public repo routes
/// run it: an invalid record of a vendored collection is rejected by default, `validate: true`
/// requires validity, `validate: false` skips, and the outcome is reported as
/// `validationStatus`.
///
/// The write choke point deliberately does not do this — it enforces the schema-free record
/// format gate, and the lexicon-aware half is the route's, so `validate` stays a wire concern.
pub fn validate_record(
    collection: &str,
    rkey: &str,
    record: &serde_json::Value,
    validate: Option<bool>,
) -> Result<Option<RecordValidation>, ApiError> {
    crate::lexicon::registry()
        .validate_record(collection, rkey, record, validate)
        .map_err(crate::record_write::record_validation_error)
}

/// The `{uri, cid, validationStatus}` body a single-record write answers with.
pub fn write_result(
    space: &SpaceRef,
    did: &str,
    collection: &str,
    rkey: &str,
    outcome: &SpaceCommitOutcome,
    validation_status: Option<RecordValidation>,
) -> Result<serde_json::Value, ApiError> {
    let cid = outcome
        .results
        .first()
        .and_then(|result| result.cid.as_deref())
        .ok_or_else(|| {
            tracing::error!(space = %space.uri, did = %did, "space write reported no record cid");
            ApiError::new(ErrorCode::InternalError, "failed to write space record")
        })?;
    let mut body = serde_json::json!({
        "uri": space.record_uri(did, collection, rkey),
        "cid": cid,
    });
    if let Some(status) = validation_status {
        body["validationStatus"] = serde_json::Value::String(status.as_str().to_string());
    }
    Ok(body)
}

/// Decode a stored record block back to JSON (CID links → `{"$link": …}`, byte strings →
/// `{"$bytes": …}`), the same mapping the public record routes serve.
pub fn decode_value(bytes: &[u8]) -> Result<serde_json::Value, ApiError> {
    let ipld = repo_engine::decode_record_block(bytes).map_err(decode_error)?;
    repo_engine::record_value_to_json(&ipld).map_err(decode_error)
}

fn decode_error(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "stored space record block is undecodable");
    ApiError::new(ErrorCode::InternalError, "failed to read space record")
}

/// Confirm this host is the space's authority — the precondition for every space-host method
/// (`registerNotify`, `unregisterNotify`, `listRepos`).
///
/// A `spaces` row with no simplespace config is a space this host only keeps repos in; its
/// authority is elsewhere and is the one to answer. That reads as `SpaceNotFound`, the same
/// reply a space this host has never heard of gets — whether some other authority's space
/// happens to have a repo here is not a fact this surface discloses.
pub async fn require_local_authority(
    state: &crate::app::AppState,
    space: &SpaceRef,
) -> Result<SpaceRow, ApiError> {
    crate::db::spaces::get_space(&state.db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .filter(|row| row.deleted_at.is_none() && row.policy.is_some())
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))
}

/// Lex-JSON encoding of a byte string: `{"$bytes": "<base64>"}`, the JSON form the lexicon
/// `bytes` type takes on the wire.
pub fn lex_bytes(bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(bytes) })
}

// ── repo head + signed commit ────────────────────────────────────────────────

/// Load the repo head, or the shared `RepoNotFound` when the account holds no repo in the
/// space. That does not distinguish a member who has never written from a non-member: a repo
/// host tracks writers, not membership.
pub async fn load_repo(
    state: &crate::app::AppState,
    space_uri: &str,
    did: &str,
) -> Result<crate::db::space_repos::SpaceRepoRow, ApiError> {
    crate::db::space_repos::get_repo(&state.db, space_uri, did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to load space repo");
            ApiError::new(ErrorCode::InternalError, "failed to load space repo")
        })?
        .ok_or_else(|| crate::auth::space::repo_not_found(did))
}

/// Mint a signed commit over a repo's current state.
///
/// A commit is produced **per serving**, never stored: fresh `ikm`, a fresh signature over the
/// `(space, author, rev, ikm)` context, and a fresh MAC binding the repo hash to that context.
/// The signature deliberately does not cover the hash — that deniability is the whole point,
/// and it is why this cannot be a cached artifact.
pub async fn sign_current_commit(
    state: &crate::app::AppState,
    space: &SpaceRef,
    did: &str,
    repo: &crate::db::space_repos::SpaceRepoRow,
) -> Result<crypto::SignedSpaceCommit, ApiError> {
    let hash = crypto::LtHash::from_state(&repo.lthash_state)
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, did = %did, "stored LtHash state is malformed");
            ApiError::new(ErrorCode::InternalError, "failed to read space commit")
        })?
        .digest();

    let master_key: &[u8; 32] = state
        .config
        .signing_key_master_key
        .as_ref()
        .map(|s| &*s.0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::ServiceUnavailable,
                "signing key master key not configured",
            )
        })?;
    let signing_key =
        crate::auth::signing_key::load_repo_signing_key(&state.db, did, master_key).await?;

    crypto::sign_space_commit(
        &crypto::SpaceCommitCtx {
            space: &space.uri,
            author: did,
            rev: &repo.rev,
        },
        hash,
        &signing_key,
    )
    .map_err(|e| {
        tracing::error!(error = %e, space = %space.uri, did = %did, "failed to sign space commit");
        ApiError::new(ErrorCode::InternalError, "failed to sign space commit")
    })
}

/// The lexicon `com.atproto.space.defs#signedCommit` JSON shape.
pub fn commit_json(commit: &crypto::SignedSpaceCommit) -> serde_json::Value {
    serde_json::json!({
        "ver": commit.ver,
        "hash": lex_bytes(&commit.hash),
        "ikm": lex_bytes(&commit.ikm),
        "sig": lex_bytes(&commit.sig),
        "mac": lex_bytes(&commit.mac),
        "rev": commit.rev,
    })
}

// ── blob references ──────────────────────────────────────────────────────────

/// The blob CIDs referenced by one repo's records — optionally only records written after
/// `since` — derived by decoding the stored blocks (blob linkage is deliberately not a table;
/// blob GC derives the same way). Sorted ascending, deduplicated: exactly the order
/// `listBlobs` pages in.
// ponytail: O(records in repo) per call — a derived-refs table if space repos outgrow this fleet.
pub async fn space_blob_cids(
    state: &crate::app::AppState,
    space_uri: &str,
    did: &str,
    since: Option<&str>,
) -> Result<std::collections::BTreeSet<String>, ApiError> {
    const PAGE: i64 = 500;
    let mut cids = std::collections::BTreeSet::new();
    let mut after: Option<(String, String)> = None;
    loop {
        let page = crate::db::space_repos::list_record_blocks_for_repo(
            &state.db,
            space_uri,
            did,
            since,
            after.as_ref().map(|(c, r)| (c.as_str(), r.as_str())),
            PAGE,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space_uri, did = %did, "failed to page space records");
            ApiError::new(ErrorCode::InternalError, "failed to read space records")
        })?;
        let last_page = (page.len() as i64) < PAGE;
        for (collection, rkey, value) in page {
            let ipld = repo_engine::decode_record_block(&value).map_err(decode_error)?;
            cids.extend(
                repo_engine::record_blob_cids(&ipld)
                    .into_iter()
                    .map(|cid| cid.to_string()),
            );
            after = Some((collection, rkey));
        }
        if last_page {
            return Ok(cids);
        }
    }
}

// ── simplespace config ───────────────────────────────────────────────────────

const PUBLIC_POLICY: &str = "com.atproto.simplespace.defs#publicPolicy";
const MEMBER_LIST_POLICY: &str = "com.atproto.simplespace.defs#memberListPolicy";
const MANAGING_APP_POLICY: &str = "com.atproto.simplespace.defs#managingAppPolicy";
const OPEN_APP_ACCESS: &str = "com.atproto.simplespace.defs#open";
const ALLOW_LIST_APP_ACCESS: &str = "com.atproto.simplespace.defs#allowList";

/// The `$type` of a union member, with the optional `lex:` URI prefix a client may send.
fn union_type(value: &serde_json::Value) -> &str {
    value
        .get("$type")
        .and_then(serde_json::Value::as_str)
        .map(|t| t.strip_prefix("lex:").unwrap_or(t))
        .unwrap_or("")
}

/// Map a lexicon `policy` union to the `(policy, managing_app)` columns.
///
/// `policy` is an open union, and the spec makes a host reject any value it does not
/// implement at create/update time rather than store what it cannot enforce — so an
/// unrecognized member is refused here, never stored and never silently downgraded.
///
/// `managingApp` is a service identifier: a DID with an optional service fragment
/// (`did:web:example.com#forum`). Only the `did:` prefix is checked, matching the reference —
/// whether that DID resolves to a reachable service is a question for mint time, where an
/// unresolvable managing app denies rather than invalidating the stored config.
pub fn policy_from_lex(
    value: &serde_json::Value,
) -> Result<(&'static str, Option<String>), ApiError> {
    match union_type(value) {
        PUBLIC_POLICY => Ok(("public", None)),
        MEMBER_LIST_POLICY => Ok(("member-list", None)),
        MANAGING_APP_POLICY => {
            let managing_app = value
                .get("managingApp")
                .and_then(serde_json::Value::as_str)
                .filter(|app| app.starts_with("did:"))
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::UnsupportedPolicy,
                        "managingApp must be a DID with an optional service fragment",
                    )
                })?;
            Ok(("managing-app", Some(managing_app.to_string())))
        }
        other => Err(ApiError::new(
            ErrorCode::UnsupportedPolicy,
            format!("unsupported policy: {other}"),
        )),
    }
}

/// Map a lexicon `appAccess` union to the `(app_access, app_allowed)` columns, the latter the
/// JSON array of allow-listed client IDs (`None` for `open`).
///
/// An `allowList` with no entries is accepted and admits nothing: an authority may legitimately
/// close a space to every app, and inventing an "empty means open" reading would turn the
/// strictest config into the weakest one.
pub fn app_access_from_lex(
    value: &serde_json::Value,
) -> Result<(&'static str, Option<String>), ApiError> {
    match union_type(value) {
        OPEN_APP_ACCESS => Ok(("open", None)),
        ALLOW_LIST_APP_ACCESS => {
            let allowed: Vec<&str> = value
                .get("allowed")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::UnsupportedAppAccess,
                        "allowList appAccess requires an \"allowed\" array of client IDs",
                    )
                })?
                .iter()
                .map(|entry| {
                    entry.as_str().ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::UnsupportedAppAccess,
                            "allowList entries must be client ID strings",
                        )
                    })
                })
                .collect::<Result<_, _>>()?;
            let json = serde_json::to_string(&allowed).map_err(|e| {
                tracing::error!(error = %e, "failed to encode allowList");
                ApiError::new(ErrorCode::InternalError, "internal server error")
            })?;
            Ok(("allowList", Some(json)))
        }
        other => Err(ApiError::new(
            ErrorCode::UnsupportedAppAccess,
            format!("unsupported appAccess: {other}"),
        )),
    }
}

/// The `getSpace` body for a stored simplespace row.
pub fn simplespace_view(row: &SpaceRow) -> serde_json::Value {
    let policy = match row.policy.as_deref() {
        Some("public") => serde_json::json!({ "$type": PUBLIC_POLICY }),
        Some("managing-app") => serde_json::json!({
            "$type": MANAGING_APP_POLICY,
            "managingApp": row.managing_app.clone().unwrap_or_default(),
        }),
        _ => serde_json::json!({ "$type": MEMBER_LIST_POLICY }),
    };
    let app_access = match row.app_access.as_deref() {
        Some("allowList") => serde_json::json!({
            "$type": ALLOW_LIST_APP_ACCESS,
            "allowed": row.allowed_client_ids(),
        }),
        _ => serde_json::json!({ "$type": OPEN_APP_ACCESS }),
    };
    serde_json::json!({ "uri": row.uri, "policy": policy, "appAccess": app_access })
}

/// Load the simplespace this host answers for at `space`, or `SpaceNotFound`: absent, deleted,
/// or recorded only as a foreign authority's space (no config) all read the same — the
/// reference's `getActiveSpaceConfig`.
///
/// Generic over the executor so a mutating route can run it inside the same transaction as
/// its write: checked-then-written outside one, a concurrent `deleteSpace` could land between
/// the check and the write and be partially undone (a tombstone with config set can never be
/// created again).
pub async fn load_active_simplespace<'e, E>(db: E, space: &SpaceRef) -> Result<SpaceRow, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    crate::db::spaces::get_space(db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .filter(|row| row.deleted_at.is_none() && row.policy.is_some())
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))
}
