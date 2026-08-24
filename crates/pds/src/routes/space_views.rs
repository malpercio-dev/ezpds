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

/// Lex-JSON encoding of a byte string: `{"$bytes": "<base64>"}`, the JSON form the lexicon
/// `bytes` type takes on the wire.
pub fn lex_bytes(bytes: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({ "$bytes": base64::engine::general_purpose::STANDARD.encode(bytes) })
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
/// implement at create/update time rather than store what it cannot enforce. This host
/// evaluates `public` and `member-list`; `managing-app` needs the outbound `checkUserAccess`
/// call, which lands with the client-attestation work, so it is refused here — never stored
/// and never silently downgraded.
pub fn policy_from_lex(
    value: &serde_json::Value,
) -> Result<(&'static str, Option<String>), ApiError> {
    match union_type(value) {
        PUBLIC_POLICY => Ok(("public", None)),
        MEMBER_LIST_POLICY => Ok(("member-list", None)),
        MANAGING_APP_POLICY => Err(ApiError::new(
            ErrorCode::UnsupportedPolicy,
            "this host does not implement the managing-app policy",
        )),
        other => Err(ApiError::new(
            ErrorCode::UnsupportedPolicy,
            format!("unsupported policy: {other}"),
        )),
    }
}

/// Map a lexicon `appAccess` union to the `app_access` column. `allowList` needs client
/// attestation verification, which this host does not yet do, so it is refused (a host must not
/// store an app-access policy it cannot enforce).
pub fn app_access_from_lex(value: &serde_json::Value) -> Result<&'static str, ApiError> {
    match union_type(value) {
        OPEN_APP_ACCESS => Ok("open"),
        ALLOW_LIST_APP_ACCESS => Err(ApiError::new(
            ErrorCode::UnsupportedAppAccess,
            "this host does not implement allow-list app access",
        )),
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
        Some("allowList") => serde_json::json!({ "$type": ALLOW_LIST_APP_ACCESS, "allowed": [] }),
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
