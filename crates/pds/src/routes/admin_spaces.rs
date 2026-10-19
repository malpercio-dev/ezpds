// pattern: Imperative Shell
//
// Gathers: admin credentials (master token or signed device request), pagination/filter
//          query params or the takedown body, DB pool
// Processes: admin auth → cursor page of stored spaces, or → apply/clear a per-space takedown
//            atomically with its audit entry
// Returns: JSON space page / resulting takedown state on success; ApiError on all failure paths

//! `GET /v1/admin/spaces` and `POST /v1/admin/spaces/takedown` — the operator's per-space
//! moderation surface.
//!
//! Account takedown already cascades to spaces (`auth::space::require_serviceable_caller`), but
//! only at whole-account granularity, and it has no reach at all into a space whose *authority*
//! is a foreign server — this host stores members' repos in such a space, recorded by
//! `space_record_write` on their first write, with no `deleteSpace` of its own to call. These
//! two routes are the lever for both cases: see the space listing for what is stored (owned and
//! foreign, with repo/record counts), then refuse to serve one URI.
//!
//! A takedown is reversible and destroys nothing — members, notify registrations, and every
//! stored repo stay exactly as they were, so a restore puts the space back. Enforcement lives at
//! the space auth seam (`auth::space::require_space_servable`) and inside the write choke point's
//! commit transaction; a refused space answers `SpaceNotFound`, the same reply an unknown space
//! gets. Not gated on `[spaces] enabled`: turning the surface off stops serving new traffic but
//! leaves whatever is already stored, which is precisely when an operator still needs to look.

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};

use common::{ApiError, ApiResultExt, ErrorCode};

use crate::app::AppState;
use crate::auth::guards::require_admin;
use crate::db::admin_audit::{record_admin_audit_event, AdminAuditAction};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

#[derive(Deserialize)]
pub struct ListSpacesParams {
    limit: Option<i64>,
    /// The previous page's last `uri`.
    cursor: Option<String>,
    /// `takendown` narrows to the operator's refusal list; unknown values → 400, like the
    /// account listing's own status filter, so a typo is never an empty page.
    status: Option<String>,
}

/// One stored space, as the operator sees it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedSpaceEntry {
    uri: String,
    authority_did: String,
    /// Whether this host is the space's authority (it holds the simplespace config). `false` is
    /// the liability case: repos stored here for a space someone else governs, where takedown is
    /// the only action available.
    local_authority: bool,
    created_at: String,
    /// The *owner's* tombstone (`simplespace.deleteSpace`), not the operator's.
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted_at: Option<String>,
    /// When the operator took the space down; absent means it is being served.
    #[serde(skip_serializing_if = "Option::is_none")]
    takendown_at: Option<String>,
    /// Repos this host stores in the space.
    repo_count: i64,
    /// Records across those repos — what is actually being served.
    record_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSpacesResponse {
    spaces: Vec<HostedSpaceEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

/// GET /v1/admin/spaces
///
/// Every space this host stores anything about, URI order, cursor-paginated — the spaces it is
/// the authority for *and* the ones it merely keeps members' repos in. `limit` defaults to 50,
/// max 100; `status=takendown` narrows to the spaces the operator has refused (unknown → 400).
/// Includes deleted spaces: a tombstoned row can still carry other members' records. Admin-authed
/// via `require_admin`; the signature covers the bare path, so paging varies without re-signing.
pub async fn list_hosted_spaces(
    State(state): State<AppState>,
    Query(params): Query<ListSpacesParams>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ListSpacesResponse>, ApiError> {
    require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    let takendown_only = match params.status.as_deref() {
        None => false,
        Some("takendown") => true,
        Some(other) => {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                format!("unknown status filter: {other}"),
            ))
        }
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let rows = crate::db::spaces::list_hosted_spaces(
        &state.db,
        params.cursor.as_deref(),
        takendown_only,
        limit,
    )
    .await
    .or_internal_as("DB error listing hosted spaces", "failed to list spaces")?;

    let cursor = (rows.len() as i64 == limit).then(|| rows[rows.len() - 1].uri.clone());
    Ok(Json(ListSpacesResponse {
        spaces: rows
            .into_iter()
            .map(|row| HostedSpaceEntry {
                uri: row.uri,
                authority_did: row.authority_did,
                local_authority: row.policy.is_some(),
                created_at: row.created_at,
                deleted_at: row.deleted_at,
                takendown_at: row.takendown_at,
                repo_count: row.repo_count,
                record_count: row.record_count,
            })
            .collect(),
        cursor,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceTakedownInput {
    /// Canonical space URI (`at://{authority}/space/{type}/{skey}`).
    uri: String,
    /// `true` applies the takedown, `false` clears it — the `takedown.applied` shape
    /// `com.atproto.admin.updateSubjectStatus` uses for an account.
    applied: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceTakedownResponse {
    uri: String,
    applied: bool,
    /// When the takedown started; absent once cleared. An already-applied takedown keeps its
    /// original timestamp, so this and the audit log agree on when the refusal began.
    #[serde(skip_serializing_if = "Option::is_none")]
    takendown_at: Option<String>,
}

/// POST /v1/admin/spaces/takedown
///
/// Apply (`applied: true`) or clear (`false`) the operator takedown on one space. While applied,
/// every space seam answers `SpaceNotFound` for it — reads, writes, credential minting,
/// notification fan-out, and the member-facing `listSpaces` — while members, registrations, and
/// stored repos are left untouched so a restore returns the space to exactly its prior state.
///
/// Idempotent in both directions, and the response restates the resulting state as the row holds
/// it rather than echoing the request. A URI with no row is `404`: this host cannot refuse to
/// serve a space it stores nothing for. Checked after auth, so there is no space-presence oracle.
/// Admin-authed via `require_admin` (master token or a paired device's signed request); the URI
/// travels in the signed body, so a takedown signature is bound to its space.
pub async fn set_space_takedown(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SpaceTakedownResponse>, ApiError> {
    let actor = require_admin(method.as_str(), uri.path(), &headers, &body, &state).await?;

    // Parsed from the raw bytes `require_admin` verified the signature over, so the space acted
    // on is exactly the one signed for.
    let input: SpaceTakedownInput = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid request body"))?;
    let space = crate::routes::space_views::parse_space(&input.uri)?;

    let map_err = |e: sqlx::Error| {
        tracing::error!(error = %e, space = %space.uri, "DB error setting space takedown");
        ApiError::new(ErrorCode::InternalError, "failed to update space takedown")
    };

    // One transaction: the row must not be observed changed without its audit entry, and the
    // read-back has to see this write rather than a concurrent one.
    let mut tx = state.db.begin().await.map_err(map_err)?;
    if crate::db::spaces::get_space(&mut *tx, &space.uri)
        .await
        .map_err(map_err)?
        .is_none()
    {
        return Err(ApiError::new(ErrorCode::NotFound, "space not found"));
    }
    crate::db::spaces::set_space_takedown(&mut *tx, &space.uri, input.applied)
        .await
        .map_err(map_err)?;
    let takendown_at = crate::db::spaces::get_space(&mut *tx, &space.uri)
        .await
        .map_err(map_err)?
        .and_then(|row| row.takendown_at);

    record_admin_audit_event(
        &mut *tx,
        actor.as_log_str().as_ref(),
        if input.applied {
            AdminAuditAction::SpaceTakedown
        } else {
            AdminAuditAction::SpaceRestore
        },
        Some(&space.uri),
        "ok",
        None,
    )
    .await?;
    tx.commit().await.map_err(map_err)?;

    tracing::info!(
        space = %space.uri,
        applied = input.applied,
        "space takedown updated by operator"
    );
    Ok(Json(SpaceTakedownResponse {
        uri: space.uri,
        applied: takendown_at.is_some(),
        takendown_at,
    }))
}
