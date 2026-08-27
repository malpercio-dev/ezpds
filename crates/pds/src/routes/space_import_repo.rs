// pattern: Imperative Shell
//
// Gathers: query params (space-ref), headers (access auth), CAR request body
// Processes: space seam auth → deactivated-account precondition → two-root CAR parse
//            → re-encode round-trip check → one Put/Delete commit through the write choke point
// Returns: JSON { rev, records } on success; ApiError on failure
//
// Implements: POST /v1/space/import-repo

//! The inbound half of permissioned-repo migration: take the two-root CAR
//! `com.atproto.space.getRepo` exported on the old host and land it as this account's repo in
//! the same space here.
//!
//! **Why this is not a `com.atproto.space.*` method.** The alpha lexicons define no import
//! endpoint — spaces are moved by whatever the destination host offers — so this lives under
//! the `/v1/*` Custos surface rather than squatting a namespace the spec may fill differently.
//! It is the space analog of `com.atproto.repo.importRepo` and shares its precondition: the
//! account must be **deactivated**, the state `createAccount` leaves a migration target in, so
//! an import can never be mistaken for a live write. That window is the only reason
//! [`SpaceWriteAdmission::Import`] exists.
//!
//! **What it does not carry.** Blobs (transfer them with `uploadBlob`, enumerated on the source
//! by `com.atproto.space.listBlobs`) and, when this host is to be the space's *authority*, the
//! simplespace config and member list (recreate those with `createSpace`/`addMember`). A repo
//! in a space whose authority lives elsewhere needs neither — the space row is recorded by the
//! write itself, exactly as it would be by the account's first ordinary write.
//!
//! **Oplog reset.** The new host's oplog starts empty and gains exactly this import's one
//! batch; nothing of the source's oplog is carried across, and no attempt is made to preserve
//! the source's revs. A syncer that reconnects with a `since` from the old host therefore folds
//! to a set hash that does not match the new head's commit, which is precisely the signal the
//! sync design already gives it to heal with a full `getRepo` (see `space_list_repo_ops.rs`).

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{Method, Request, StatusCode, Uri};
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::app::AppState;
use crate::auth::oauth_scopes::{RepoAction, SpaceOp};
use crate::space_record_write::{SpaceWriteAction, SpaceWriteAdmission, SpaceWriteOp};
use common::{ApiError, ErrorCode};

/// Same ceiling as `com.atproto.repo.importRepo`. A permissioned repo has no MST overhead, so
/// this buys proportionally more records than it does on the public path.
const MAX_IMPORT_CAR_BYTES: usize = 100 * 1024 * 1024;

/// Plain `Query`, not `LexiconParams`: this is a Custos `/v1/*` route, so there is no lexicon
/// document to validate its parameters against.
#[derive(Deserialize)]
pub struct SpaceImportRepoParams {
    /// The space the CAR belongs to (`space-ref`). Must be the same space it was exported from:
    /// nothing in the CAR names one, since a space repo's identity is `(space, account)`.
    space: String,
}

/// POST /v1/space/import-repo?space=at://{authority}/space/{type}/{skey}
pub async fn space_import_repo(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    Query(params): Query<SpaceImportRepoParams>,
    request: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let headers = request.headers().clone();
    let space = super::space_views::parse_space(&params.space)?;

    // The account-credential space seam: access auth with the RFC 9449 binding rules plus the
    // moderation gate. `authenticate_space_write`'s repo-ownership comparison has nothing to do
    // here — an import writes the caller's own repo by construction, there being no `repo`
    // parameter to disagree with. The `space:` grant is checked per collection below, exactly as
    // `applyWrites` checks it per op.
    let user =
        crate::auth::space::authenticate_space_caller(&state, &headers, &method, &uri).await?;
    // Migration is an account operation, never something an agent performs on the owner's behalf.
    user.require_not_agent()?;
    let did = user.did.clone();

    // Precondition: deactivated. Read before buffering the (large) body so an active account is
    // refused cheaply; `apply_space_writes` re-reads the lifecycle inside its commit transaction,
    // which is what actually closes the race against a concurrent `activateAccount`.
    match crate::db::accounts::account_lifecycle(&state.db, &did).await? {
        Some(crate::db::accounts::AccountLifecycle::Deactivated) => {}
        Some(_) => {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "account must be deactivated to import a space repo",
            ))
        }
        None => return Err(ApiError::new(ErrorCode::NotFound, "account not found")),
    }

    let too_large = || {
        ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!("space repo CAR exceeds maximum size of {MAX_IMPORT_CAR_BYTES} bytes"),
        )
    };
    if let Some(len) = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > MAX_IMPORT_CAR_BYTES {
            return Err(too_large());
        }
    }
    let car_bytes = axum::body::to_bytes(request.into_body(), MAX_IMPORT_CAR_BYTES)
        .await
        .map_err(|_| too_large())?;

    // Structural validation (framing, CIDv1 + SHA2-256, every block hashes to its CID) happens
    // here, so a record block that contradicts the CID its index entry promised never reaches
    // the store.
    let car = repo_engine::import_space_car(&car_bytes).await.map_err(|e| {
        tracing::warn!(did = %did, space = %space.uri, error = %e, "space import rejected: invalid CAR");
        ApiError::new(ErrorCode::InvalidRequest, "invalid space repo CAR")
    })?;

    // One grant check per distinct collection rather than per record: the check is identical
    // for every record in a collection and resolving a grant's default collections can reach
    // the network.
    let mut checked: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for record in &car.records {
        if checked.insert(record.collection.as_str()) {
            crate::auth::space::require_space_grant(
                &state,
                &user,
                &space,
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: &record.collection,
                },
            )
            .await?;
        }
    }

    let mut ops = Vec::with_capacity(car.records.len());
    for record in &car.records {
        let value = super::space_views::decode_value(&record.block)?;
        // The store round-trips a record through JSON on the way in, so a CID that survives the
        // source's DAG-CBOR → JSON → DAG-CBOR trip is what makes the imported set hash to the
        // same digest the source published. Checked before the commit rather than after, so a
        // drifting encoder fails the import instead of silently producing a repo whose LtHash
        // no syncer can reproduce.
        let ipld = repo_engine::json_to_record_value(&value)
            .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
        let (cid, _) = repo_engine::encode_record_block(&ipld)
            .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
        if cid != record.cid {
            tracing::warn!(
                did = %did,
                space = %space.uri,
                path = %format!("{}/{}", record.collection, record.rkey),
                expected = %record.cid,
                found = %cid,
                "space import rejected: record does not re-encode to its CID"
            );
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "space repo CAR contains a record that does not re-encode to its own CID",
            ));
        }
        ops.push(SpaceWriteOp {
            action: SpaceWriteAction::Put,
            collection: record.collection.clone(),
            rkey: record.rkey.clone(),
            value: Some(value),
        });
    }

    // A return migration lands on a repo that may still hold this account's previous residency.
    // Import means "the repo is now exactly this CAR", so anything the index does not name is
    // deleted in the same commit — otherwise the imported repo would hash to a digest the
    // source never published, and every syncer would heal in a loop against a set that never
    // converges.
    let existing = crate::db::space_repos::list_record_index(&state.db, &space.uri, &did)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, space = %space.uri, did = %did, "failed to read space record index");
            ApiError::new(ErrorCode::InternalError, "failed to import space repo")
        })?;
    let imported: std::collections::HashSet<(&str, &str)> = car
        .records
        .iter()
        .map(|r| (r.collection.as_str(), r.rkey.as_str()))
        .collect();
    for (collection, rkey, _) in &existing {
        if !imported.contains(&(collection.as_str(), rkey.as_str())) {
            crate::auth::space::require_space_grant(
                &state,
                &user,
                &space,
                SpaceOp::Record {
                    action: RepoAction::Delete,
                    collection,
                },
            )
            .await?;
            ops.push(SpaceWriteOp {
                action: SpaceWriteAction::Delete,
                collection: collection.clone(),
                rkey: rkey.clone(),
                value: None,
            });
        }
    }

    if ops.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "space repo CAR declares no records",
        ));
    }

    // ponytail: one transaction for the whole repo. Fine at the scale a single-connection
    // SQLite pool serves; if imports ever outgrow it, page the CAR into rev-chained batches
    // (which costs the all-or-nothing guarantee, so do it only when forced).
    let record_count = car.records.len();
    let outcome = crate::space_record_write::apply_space_writes(
        &state,
        &space,
        &did,
        &ops,
        SpaceWriteAdmission::Import,
    )
    .await?;

    tracing::info!(
        did = %did,
        space = %space.uri,
        rev = %outcome.rev,
        records = record_count,
        removed = ops.len() - record_count,
        "imported space repo"
    );

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "rev": outcome.rev,
            "records": record_count,
        })),
    ))
}
