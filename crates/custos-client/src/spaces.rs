// pattern: Imperative Shell

//! Space-transfer XRPC helpers: typed methods over an authenticated [`OAuthClient`] for the
//! `com.atproto.space.*` calls an account migration makes (`listSpaces`, the two STAR exports
//! and their imports, and the per-space blob listing and fetch). Blob uploads ride the ordinary
//! `com.atproto.repo.uploadBlob` ([`crate::migration::upload_blob`]). No orchestration here;
//! the order the calls run in lives in the caller (obsign-core's `migration_orchestrator`).
//!
//! The archives are opaque bytes to this module: the wallet relays them from one host to the
//! other, and the importing host verifies them.

use serde::Deserialize;

use crate::error::{xrpc_json, xrpc_ok, PdsClientError};
use crate::oauth_client::OAuthClient;

/// The STAR archive media type both exports answer with and both imports take.
pub const STAR_CONTENT_TYPE: &str = "application/vnd.dasl.star";

/// One entry of `listSpaces`: a space the account holds a repo in or is the authority for.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SpaceView {
    /// The space-ref, `at://{authority}/space/{type}/{skey}`.
    pub space: String,
    /// The account's repo revision in the space, when it holds a repo there.
    #[serde(default)]
    pub repo_rev: Option<String>,
    /// The account's repo commit `data` digest in the space, when it holds a repo there.
    #[serde(default)]
    pub data: Option<LexBytes>,
    /// The space's revision; present only when the account is the space's authority.
    #[serde(default)]
    pub space_rev: Option<String>,
}

/// A lexicon `bytes` value on the JSON wire: `{"$bytes": "<base64>"}`.
#[derive(Debug, Clone, Deserialize)]
pub struct LexBytes {
    #[serde(rename = "$bytes")]
    pub base64: String,
}

/// Two hosts may disagree on base64 padding for the same bytes, so equality ignores it.
impl PartialEq for LexBytes {
    fn eq(&self, other: &Self) -> bool {
        self.base64.trim_end_matches('=') == other.base64.trim_end_matches('=')
    }
}

impl Eq for LexBytes {}

/// One page of `listSpaces`.
#[derive(Debug, Deserialize)]
pub struct SpacePage {
    pub spaces: Vec<SpaceView>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One page of a space's `listBlobs`.
#[derive(Debug, Deserialize)]
pub struct SpaceBlobPage {
    pub cids: Vec<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Whether `err` is a host saying it does not implement the method at all, as opposed to a
/// host that implements it and failed. A PDS without spaces (or a Custos with them switched
/// off) answers `501 MethodNotImplemented`; some front ends answer `404`.
pub fn is_method_unsupported(err: &PdsClientError) -> bool {
    match err {
        PdsClientError::XrpcError { status, error, .. } => {
            matches!(status, 404 | 501)
                || matches!(
                    error.as_deref(),
                    Some("MethodNotImplemented" | "XRPCNotSupported")
                )
        }
        _ => false,
    }
}

fn network(op: &str, e: impl std::fmt::Display) -> PdsClientError {
    PdsClientError::NetworkError {
        message: format!("{op} failed: {e}"),
    }
}

async fn get_bytes(client: &OAuthClient, op: &str, path: &str) -> Result<Vec<u8>, PdsClientError> {
    let resp = client.get(path).await.map_err(|e| network(op, e))?;
    let resp = xrpc_ok(op, resp, client.observer()).await?;
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| network(op, e))
}

async fn post_star(
    client: &OAuthClient,
    op: &str,
    path: &str,
    archive: Vec<u8>,
) -> Result<(), PdsClientError> {
    let resp = client
        .post_bytes(path, STAR_CONTENT_TYPE, archive)
        .await
        .map_err(|e| network(op, e))?;
    xrpc_ok(op, resp, client.observer()).await.map(|_| ())
}

/// `GET /xrpc/com.atproto.space.listSpaces`, one page.
pub async fn list_spaces(
    client: &OAuthClient,
    cursor: Option<&str>,
) -> Result<SpacePage, PdsClientError> {
    let mut path = "/xrpc/com.atproto.space.listSpaces?limit=100".to_string();
    if let Some(cursor) = cursor {
        path.push_str(&format!("&cursor={}", urlencoding::encode(cursor)));
    }
    let resp = client
        .get(&path)
        .await
        .map_err(|e| network("listSpaces", e))?;
    xrpc_json("listSpaces", resp, client.observer()).await
}

/// `GET /xrpc/com.atproto.space.exportSpaceMeta`: the authority's `atproto-space-meta` archive.
pub async fn export_space_meta(
    client: &OAuthClient,
    space: &str,
) -> Result<Vec<u8>, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.space.exportSpaceMeta?space={}",
        urlencoding::encode(space)
    );
    get_bytes(client, "exportSpaceMeta", &path).await
}

/// `POST /xrpc/com.atproto.space.importSpaceMeta` with an archive from [`export_space_meta`].
pub async fn import_space_meta(
    client: &OAuthClient,
    archive: Vec<u8>,
) -> Result<(), PdsClientError> {
    post_star(
        client,
        "importSpaceMeta",
        "/xrpc/com.atproto.space.importSpaceMeta",
        archive,
    )
    .await
}

/// `GET /xrpc/com.atproto.space.getRepo`: one account's `atproto-space-repo` archive.
///
/// Sent without `Accept-Signature`: the account reading its own repo needs no MAC.
pub async fn get_space_repo(
    client: &OAuthClient,
    space: &str,
    repo: &str,
) -> Result<Vec<u8>, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.space.getRepo?space={}&repo={}",
        urlencoding::encode(space),
        urlencoding::encode(repo)
    );
    get_bytes(client, "getSpaceRepo", &path).await
}

/// `POST /xrpc/com.atproto.space.importRepo` with an archive from [`get_space_repo`].
pub async fn import_space_repo(
    client: &OAuthClient,
    archive: Vec<u8>,
) -> Result<(), PdsClientError> {
    post_star(
        client,
        "importSpaceRepo",
        "/xrpc/com.atproto.space.importRepo",
        archive,
    )
    .await
}

/// `GET /xrpc/com.atproto.space.listBlobs`, one page of the blobs `repo`'s records in `space`
/// reference.
pub async fn list_space_blobs(
    client: &OAuthClient,
    space: &str,
    repo: &str,
    cursor: Option<&str>,
) -> Result<SpaceBlobPage, PdsClientError> {
    let mut path = format!(
        "/xrpc/com.atproto.space.listBlobs?space={}&repo={}&limit=1000",
        urlencoding::encode(space),
        urlencoding::encode(repo)
    );
    if let Some(cursor) = cursor {
        path.push_str(&format!("&cursor={}", urlencoding::encode(cursor)));
    }
    let resp = client
        .get(&path)
        .await
        .map_err(|e| network("listSpaceBlobs", e))?;
    xrpc_json("listSpaceBlobs", resp, client.observer()).await
}

/// Whether the host holds `cid` for `repo` in `space`: a body-less `HEAD` on
/// `com.atproto.space.getBlob`. A `listBlobs` listing can't answer this, because it names the
/// blobs the records reference, stored or not. `400`/`404` (`BlobNotFound`, whose envelope a
/// HEAD response carries no body for) read as absent; any other failure is an error.
pub async fn space_blob_present(
    client: &OAuthClient,
    space: &str,
    repo: &str,
    cid: &str,
) -> Result<bool, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
        urlencoding::encode(space),
        urlencoding::encode(repo),
        urlencoding::encode(cid)
    );
    let resp = client
        .head(&path)
        .await
        .map_err(|e| network("headSpaceBlob", e))?;
    if matches!(resp.status().as_u16(), 400 | 404) {
        return Ok(false);
    }
    xrpc_ok("headSpaceBlob", resp, client.observer())
        .await
        .map(|_| true)
}

/// `GET /xrpc/com.atproto.space.getBlob`: one blob a space record references.
pub async fn get_space_blob(
    client: &OAuthClient,
    space: &str,
    repo: &str,
    cid: &str,
) -> Result<Vec<u8>, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
        urlencoding::encode(space),
        urlencoding::encode(repo),
        urlencoding::encode(cid)
    );
    get_bytes(client, "getSpaceBlob", &path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_bytes_equality_ignores_padding() {
        let a = LexBytes {
            base64: "AAEC".into(),
        };
        let b = LexBytes {
            base64: "AAEC".into(),
        };
        let padded = LexBytes {
            base64: "AAE=".into(),
        };
        let unpadded = LexBytes {
            base64: "AAE".into(),
        };
        assert_eq!(a, b);
        assert_eq!(padded, unpadded);
        assert_ne!(a, unpadded);
    }

    #[test]
    fn space_view_reads_the_lexicon_shape() {
        let page: SpacePage = serde_json::from_value(serde_json::json!({
            "spaces": [
                { "space": "at://did:plc:a/space/app.example.group/one",
                  "repoRev": "3l", "data": { "$bytes": "AAEC" }, "spaceRev": "3m" },
                { "space": "at://did:plc:b/space/app.example.group/two" }
            ],
            "cursor": "next"
        }))
        .unwrap();
        assert_eq!(page.spaces.len(), 2);
        assert_eq!(page.spaces[0].data.as_ref().unwrap().base64, "AAEC");
        assert!(page.spaces[1].data.is_none() && page.spaces[1].space_rev.is_none());
        assert_eq!(page.cursor.as_deref(), Some("next"));
    }

    #[test]
    fn only_a_missing_method_reads_as_unsupported() {
        let xrpc = |status, error: Option<&str>| PdsClientError::XrpcError {
            status,
            error: error.map(str::to_string),
            message: String::new(),
        };
        assert!(is_method_unsupported(&xrpc(
            501,
            Some("MethodNotImplemented")
        )));
        assert!(is_method_unsupported(&xrpc(404, None)));
        assert!(is_method_unsupported(&xrpc(400, Some("XRPCNotSupported"))));
        assert!(!is_method_unsupported(&xrpc(
            500,
            Some("InternalServerError")
        )));
        assert!(!is_method_unsupported(&xrpc(400, Some("InvalidRequest"))));
        assert!(!is_method_unsupported(&PdsClientError::NetworkError {
            message: String::new()
        }));
    }
}
