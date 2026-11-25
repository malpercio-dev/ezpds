// pattern: Imperative Shell

//! Shared handler-free support for the `com.atproto.space.*` and `com.atproto.memberspace.*`
//! routes (routes may not import one another): space-ref parsing, the `validate`-flag record
//! check, stored-block decoding, the `{uri, cid, validationStatus}` shape every write route
//! answers with, and loading an active space with its policy.
//!
//! Authorization is deliberately *not* here — it lives in `auth/space.rs`, the one seam every
//! space route enters through.

use crate::db::spaces::SpaceRow;
use crate::space_record_write::SpaceCommitOutcome;
use common::{ApiError, ErrorCode};
use custos_core::lexicon::RecordValidation;
use custos_core::space_uri::SpaceRef;
use custos_core::CoreState;

/// Parse the `space` a request named.
///
/// The lexicon layer's `space-ref` format has already rejected a malformed one before any
/// handler runs, so this only fails for a caller that reached a handler some other way — but it
/// is also the only way the `(authority, type, skey)` triple is obtained, so nothing downstream
/// can be handed a URI that was never checked.
pub fn parse_space(space: &str) -> Result<SpaceRef, ApiError> {
    custos_core::space_uri::parse_space_ref(space).ok_or_else(|| {
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
    custos_core::lexicon::registry()
        .validate_record(collection, rkey, record, validate)
        .map_err(custos_core::lexicon::record_validation_error)
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
    ApiError::internal_as(
        e,
        "stored space record block is undecodable",
        "failed to read space record",
    )
}

/// Confirm this host is the space's authority — the precondition for every space-host method
/// (`listRepos`).
///
/// A `spaces` row with no policy is a space this host only keeps repos in; its
/// authority is elsewhere and is the one to answer. That reads as `SpaceNotFound`, the same
/// reply a space this host has never heard of gets — whether some other authority's space
/// happens to have a repo here is not a fact this surface discloses.
pub async fn require_local_authority(
    state: &CoreState,
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
    state: &CoreState,
    space_uri: &str,
    did: &str,
) -> Result<crate::db::space_repos::SpaceRepoRow, ApiError> {
    crate::db::space_repos::get_repo(&state.db, space_uri, did)
        .await
        .map_err(|e| {
            {
                tracing::error!(error = %e, space = %space_uri, did = %did, "failed to load space repo");
                ApiError::new(ErrorCode::InternalError, "failed to load space repo")
            }
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
    state: &CoreState,
    space: &SpaceRef,
    did: &str,
    repo: &crate::db::space_repos::SpaceRepoRow,
) -> Result<crypto::SignedSpaceCommit, ApiError> {
    let hash = crypto::LtHash::from_state(&repo.lthash_state)
        .map_err(|e| {
            {
                tracing::error!(error = %e, space = %space.uri, did = %did, "stored LtHash state is malformed");
                ApiError::new(ErrorCode::InternalError, "failed to read space commit")
            }
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
        custos_core::auth::signing_key::load_repo_signing_key(&state.db, did, master_key).await?;

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
    state: &CoreState,
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
            {
                tracing::error!(error = %e, space = %space_uri, did = %did, "failed to page space records");
                ApiError::new(ErrorCode::InternalError, "failed to read space records")
            }
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

// ── space policy ─────────────────────────────────────────────────────────────

/// Load the space this host is the authority for at `space`, with its policy, or
/// `SpaceNotFound`: absent, deleted, or recorded only as a foreign authority's space (no policy)
/// all read the same — the reference's `getActiveSpacePolicy`.
///
/// Generic over the executor so a mutating route can run it inside the same transaction as its
/// write: checked-then-written outside one, a concurrent `deleteSpace` could land between the
/// check and the write and be partially undone (a tombstone with a policy set can never be
/// created again).
pub async fn load_active_space<'e, E>(
    db: E,
    space: &SpaceRef,
) -> Result<(SpaceRow, crate::policy::SpacePolicy), ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = crate::db::spaces::get_space(db, &space.uri)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, "failed to load space");
            ApiError::new(ErrorCode::InternalError, "internal server error")
        })?
        .filter(|row| row.deleted_at.is_none())
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))?;
    let policy = row
        .space_policy()?
        .ok_or_else(|| ApiError::new(ErrorCode::SpaceNotFound, "space not found"))?;
    Ok((row, policy))
}
