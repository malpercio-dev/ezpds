// pattern: Imperative Shell
//
// Shared ATProto identity-resolution helpers. Routes gather query/body parameters and delegate the
// actual handle/DID lookup here so resolveHandle, resolveIdentity, refreshIdentity, and resolveDid
// all use the same local → network fallback rules.

use std::net::IpAddr;

use common::{ApiError, ErrorCode};
use serde_json::Value;

use crate::app::AppState;

pub const INVALID_HANDLE: &str = "handle.invalid";

/// Resolve a handle to a DID using ezpds' ATProto handle-resolution chain:
/// local handles table → DNS TXT `_atproto.<handle>` → HTTP `.well-known/atproto-did`.
///
/// Infrastructure errors in DNS / well-known are logged and treated as misses so later fallbacks
/// still get a chance to resolve the handle. Database errors fail closed.
pub async fn resolve_handle_to_did(
    state: &AppState,
    handle: &str,
) -> Result<Option<String>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM handles WHERE handle = ?")
        .bind(handle)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, handle = %handle, "failed to query handle");
            ApiError::new(ErrorCode::InternalError, "handle lookup failed")
        })?;

    if let Some((did,)) = row {
        return Ok(Some(did));
    }

    if let Some(resolver) = &state.txt_resolver {
        let name = format!("_atproto.{handle}");
        match resolver.txt_lookup(&name).await {
            Ok(records) => {
                for record in records {
                    if let Some(did) = record.strip_prefix("did=") {
                        return Ok(Some(did.to_string()));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "DNS TXT lookup failed; falling through to well-known"
                );
            }
        }
    }

    if let Some(resolver) = &state.well_known_resolver {
        match resolver.resolve(handle).await {
            Ok(Some(did)) => return Ok(Some(did)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    handle = %handle,
                    "HTTP well-known lookup failed"
                );
            }
        }
    }

    Ok(None)
}

/// Resolve a DID to its current DID document.
///
/// Local cached documents are preferred. Unknown `did:plc` values are proxied to the configured PLC
/// directory; unknown `did:web` values are resolved through the method's `did.json` URL. Returned
/// documents must assert the requested DID in their `id` field.
pub async fn resolve_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    if !did.starts_with("did:") {
        return Err(ApiError::new(ErrorCode::InvalidClaim, "invalid DID format"));
    }

    if let Some(doc) = crate::db::dids::get_did_document(&state.db, did).await? {
        return validate_did_doc_id(doc, did, ErrorCode::InternalError);
    }

    if did.starts_with("did:plc:") {
        return resolve_plc_did_document(state, did).await;
    }

    if did.starts_with("did:web:") {
        return resolve_web_did_document(state, did).await;
    }

    Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"))
}

/// Return the verified handle for `did` and `did_doc`, or `handle.invalid` when the document's
/// `alsoKnownAs` handles do not resolve back to the DID.
pub async fn verified_handle_for_did(
    state: &AppState,
    did: &str,
    did_doc: &Value,
) -> Result<String, ApiError> {
    for handle in also_known_as_handles(did_doc) {
        if resolve_handle_to_did(state, &handle).await?.as_deref() == Some(did) {
            return Ok(handle);
        }
    }

    Ok(INVALID_HANDLE.to_string())
}

/// Verify a caller-provided handle against a DID document and the handle-resolution chain.
pub async fn verified_handle_for_identifier(
    state: &AppState,
    did: &str,
    did_doc: &Value,
    handle: &str,
) -> Result<String, ApiError> {
    let asserted = also_known_as_handles(did_doc)
        .into_iter()
        .any(|candidate| candidate == handle);
    if !asserted {
        return Ok(INVALID_HANDLE.to_string());
    }

    if resolve_handle_to_did(state, handle).await?.as_deref() == Some(did) {
        Ok(handle.to_string())
    } else {
        Ok(INVALID_HANDLE.to_string())
    }
}

async fn resolve_plc_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    let plc_url = format!(
        "{}/{}",
        state.config.plc_directory_url.trim_end_matches('/'),
        did
    );
    let response = state.http_client.get(&plc_url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, plc_url = %plc_url, "failed to contact plc.directory");
        ApiError::new(ErrorCode::PlcDirectoryError, "failed to contact plc.directory")
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        tracing::debug!(did = %did, "DID not found in plc.directory");
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated in plc.directory");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "plc.directory returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "plc.directory returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse plc.directory response");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "invalid response from plc.directory",
        )
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

async fn resolve_web_did_document(state: &AppState, did: &str) -> Result<Value, ApiError> {
    let url = did_web_document_url(did)?;
    let response = state.http_client.get(&url).send().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, url = %url, "failed to resolve did:web document");
        ApiError::new(
            ErrorCode::PlcDirectoryError,
            "failed to resolve did:web document",
        )
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ApiError::new(ErrorCode::DidNotFound, "DID not found"));
    }

    if response.status() == reqwest::StatusCode::GONE {
        tracing::debug!(did = %did, "DID deactivated at did:web endpoint");
        return Err(ApiError::new(ErrorCode::DidDeactivated, "DID deactivated"));
    }

    if !response.status().is_success() {
        let status = response.status();
        let truncated = bounded_body_preview(response).await;
        tracing::error!(did = %did, status = %status, response_body = %truncated, "did:web endpoint returned error");
        return Err(ApiError::new(
            ErrorCode::PlcDirectoryError,
            "did:web endpoint returned error",
        ));
    }

    let doc: Value = response.json().await.map_err(|e| {
        tracing::error!(did = %did, error = %e, "failed to parse did:web response");
        ApiError::new(ErrorCode::PlcDirectoryError, "invalid did:web response")
    })?;

    validate_did_doc_id(doc, did, ErrorCode::PlcDirectoryError)
}

fn validate_did_doc_id(doc: Value, did: &str, error_code: ErrorCode) -> Result<Value, ApiError> {
    if doc.get("id").and_then(Value::as_str) == Some(did) {
        Ok(doc)
    } else {
        tracing::warn!(did = %did, doc_id = ?doc.get("id"), "DID document id mismatch");
        Err(ApiError::new(error_code, "DID document id mismatch"))
    }
}

const ERROR_BODY_PREVIEW_BYTES: usize = 2048;

async fn bounded_body_preview(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    while body.len() < ERROR_BODY_PREVIEW_BYTES {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => break,
        };
        let remaining = ERROR_BODY_PREVIEW_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }

    safe_body_preview(&String::from_utf8_lossy(&body))
}

fn safe_body_preview(body: &str) -> String {
    body.chars().take(500).collect()
}

fn did_web_document_url(did: &str) -> Result<String, ApiError> {
    let method_specific = did
        .strip_prefix("did:web:")
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))?;
    if method_specific.is_empty() {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    let segments = method_specific
        .split(':')
        .map(|segment| {
            urlencoding::decode(segment)
                .map(|decoded| decoded.into_owned())
                .map_err(|_| ApiError::new(ErrorCode::InvalidClaim, "invalid did:web DID"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let Some(host) = segments.first() else {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    };
    if host.is_empty()
        || forbidden_did_web_authority(host)
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.contains('/')
                || segment.contains('\\')
                || segment.contains('?')
                || segment.contains('#')
        })
    {
        return Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "invalid did:web DID",
        ));
    }

    if segments.len() == 1 {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        let path = segments[1..].join("/");
        Ok(format!("https://{host}/{path}/did.json"))
    }
}

fn forbidden_did_web_authority(authority: &str) -> bool {
    if authority.contains('@') || authority.contains('[') || authority.contains(']') {
        return true;
    }

    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => host,
        Some(_) => return true,
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    host == "localhost" || host.ends_with(".localhost") || host.parse::<IpAddr>().is_ok()
}

fn also_known_as_handles(did_doc: &Value) -> Vec<String> {
    did_doc
        .get("alsoKnownAs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|alias| alias.strip_prefix("at://"))
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{did_web_document_url, safe_body_preview};

    #[test]
    fn did_web_url_uses_well_known_for_bare_domain() {
        assert_eq!(
            did_web_document_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_uses_path_segments_when_present() {
        assert_eq!(
            did_web_document_url("did:web:example.com:users:alice").unwrap(),
            "https://example.com/users/alice/did.json"
        );
    }

    #[test]
    fn did_web_url_decodes_percent_encoded_host_port() {
        assert_eq!(
            did_web_document_url("did:web:example.com%3A8443").unwrap(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_url_rejects_path_separator_inside_segment() {
        assert!(did_web_document_url("did:web:example.com:%2Fadmin").is_err());
    }

    #[test]
    fn did_web_url_rejects_userinfo_loopback_and_ip_literals() {
        assert!(did_web_document_url("did:web:user%40example.com").is_err());
        assert!(did_web_document_url("did:web:localhost").is_err());
        assert!(did_web_document_url("did:web:sub.localhost").is_err());
        assert!(did_web_document_url("did:web:127.0.0.1").is_err());
        assert!(did_web_document_url("did:web:10.0.0.1%3A8443").is_err());
        assert!(did_web_document_url("did:web:%5B%3A%3A1%5D").is_err());
        assert!(did_web_document_url("did:web:%3A443").is_err());
        assert!(did_web_document_url("did:web:example.com%3A99999").is_err());
    }

    #[test]
    fn safe_body_preview_truncates_on_char_boundary() {
        let preview = safe_body_preview(&"é".repeat(600));
        assert_eq!(preview.chars().count(), 500);
        assert!(preview.is_char_boundary(preview.len()));
    }
}
