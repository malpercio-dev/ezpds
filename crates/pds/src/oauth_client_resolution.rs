// pattern: Mixed (unavoidable)
//
// Gathers: a URL-shaped OAuth client_id + the shared outbound HTTP client
// Processes: URL policy validation (pure) → metadata-document fetch (shell) →
//            document validation (pure)
// Returns: the raw client-metadata JSON for the caller to cache, or a typed refusal
//
// ATProto OAuth clients identify themselves by the URL of their client-metadata
// document; authorization servers resolve unknown client_ids by fetching that URL
// (https://atproto.com/specs/oauth). This module is that resolver. The fetched URL is
// caller-controlled, so the policy check runs before any network I/O: https is
// required everywhere except loopback hosts, which may use plain http (the spec's
// local-development exception — also what lets tests serve metadata from 127.0.0.1).

use url::{Host, Url};

/// Upper bound on an accepted client-metadata document. Real documents are well under
/// 4 KiB; the cap only exists so a hostile URL can't stream an unbounded body into memory.
const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Fetch timeout for the metadata document, independent of (and tighter than) the shared
/// client's default: PAR is interactive and a slow metadata host shouldn't hold it long.
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why a URL client_id could not be resolved to a usable client-metadata document.
///
/// The `Display` text becomes the OAuth `error_description`, so each message names the
/// problem from the client developer's point of view.
#[derive(Debug, thiserror::Error)]
pub enum ClientResolutionError {
    #[error("client_id is not a valid URL")]
    InvalidUrl,

    #[error("client_id must be an https URL (plain http is allowed for loopback hosts only)")]
    InsecureUrl,

    #[error("client_id URL must not contain credentials or a fragment")]
    ForbiddenUrlParts,

    #[error("failed to fetch client metadata: {0}")]
    Fetch(String),

    #[error("client metadata document exceeds {MAX_METADATA_BYTES} bytes")]
    TooLarge,

    #[error("client metadata document is not valid JSON")]
    InvalidJson,

    #[error(
        "client metadata client_id mismatch (the document must declare the URL it is served from)"
    )]
    ClientIdMismatch,
}

/// Validate the URL policy for a metadata-URL client_id (pure; no I/O).
///
/// Rules: parseable; https (http only for loopback hosts); no userinfo; no fragment.
fn validate_client_id_url(client_id: &str) -> Result<Url, ClientResolutionError> {
    let url = Url::parse(client_id).map_err(|_| ClientResolutionError::InvalidUrl)?;

    match url.scheme() {
        "https" => {}
        "http" if host_is_loopback(&url) => {}
        _ => return Err(ClientResolutionError::InsecureUrl),
    }

    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ClientResolutionError::ForbiddenUrlParts);
    }

    Ok(url)
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Validate a fetched metadata document against the client_id it was fetched from (pure).
///
/// Per the ATProto OAuth spec the document MUST declare its own URL as `client_id` —
/// this is what stops one origin from impersonating another origin's client.
fn validate_metadata_document(client_id: &str, body: &str) -> Result<(), ClientResolutionError> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|_| ClientResolutionError::InvalidJson)?;

    if doc.get("client_id").and_then(|v| v.as_str()) != Some(client_id) {
        return Err(ClientResolutionError::ClientIdMismatch);
    }

    Ok(())
}

/// Resolve a URL client_id to its raw client-metadata JSON (validate URL → fetch →
/// validate document). The caller decides whether/when to cache the returned JSON.
pub async fn resolve_client_metadata(
    http: &reqwest::Client,
    client_id: &str,
) -> Result<String, ClientResolutionError> {
    let url = validate_client_id_url(client_id)?;

    let response = http
        .get(url)
        .header("Accept", "application/json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| ClientResolutionError::Fetch(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(ClientResolutionError::Fetch(format!("HTTP {status}")));
    }

    if response
        .content_length()
        .is_some_and(|l| l > MAX_METADATA_BYTES as u64)
    {
        return Err(ClientResolutionError::TooLarge);
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| ClientResolutionError::Fetch(e.to_string()))?;
    if body.len() > MAX_METADATA_BYTES {
        return Err(ClientResolutionError::TooLarge);
    }

    let body = String::from_utf8(body.to_vec()).map_err(|_| ClientResolutionError::InvalidJson)?;
    validate_metadata_document(client_id, &body)?;

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_url_passes_policy() {
        assert!(validate_client_id_url("https://app.example.com/client-metadata.json").is_ok());
    }

    #[test]
    fn plain_http_is_loopback_only() {
        assert!(validate_client_id_url("http://127.0.0.1:8080/m.json").is_ok());
        assert!(validate_client_id_url("http://localhost/m.json").is_ok());
        assert!(matches!(
            validate_client_id_url("http://app.example.com/m.json"),
            Err(ClientResolutionError::InsecureUrl)
        ));
    }

    #[test]
    fn credentials_and_fragments_are_rejected() {
        assert!(matches!(
            validate_client_id_url("https://user@app.example.com/m.json"),
            Err(ClientResolutionError::ForbiddenUrlParts)
        ));
        assert!(matches!(
            validate_client_id_url("https://app.example.com/m.json#frag"),
            Err(ClientResolutionError::ForbiddenUrlParts)
        ));
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        assert!(matches!(
            validate_client_id_url("ftp://app.example.com/m.json"),
            Err(ClientResolutionError::InsecureUrl)
        ));
    }

    #[test]
    fn document_must_declare_its_own_url() {
        let url = "https://app.example.com/client-metadata.json";
        assert!(validate_metadata_document(
            url,
            r#"{"client_id":"https://app.example.com/client-metadata.json"}"#
        )
        .is_ok());
        assert!(matches!(
            validate_metadata_document(url, r#"{"client_id":"https://evil.example.com/m.json"}"#),
            Err(ClientResolutionError::ClientIdMismatch)
        ));
        assert!(matches!(
            validate_metadata_document(url, "not json"),
            Err(ClientResolutionError::InvalidJson)
        ));
    }
}
