// pattern: Imperative Shell
//
// Blob storage backend: filesystem I/O, CID computation, MIME type detection.
// Blobs are stored at `{data_dir}/blobs/{cid[0:2]}/{cid}` with 2-char prefix fanout.
//
// I/O is async (`tokio::fs`): blobs can be multiple MB, so the disk read/write must not
// park a Tokio worker thread. Callers are async handlers/sweeps that `.await` these.

use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlobStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result of storing a blob on disk.
pub struct StoredBlob {
    /// Content-addressable identifier (base32 CIDv1 with raw codec + SHA-256).
    pub cid: String,
    /// Resolved MIME type (e.g. "image/jpeg"), as reconciled by [`resolve_mime_type`].
    pub mime_type: String,
    /// Relative storage path under `data_dir` (e.g. "blobs/ba/bafy...").
    pub storage_path: String,
    /// Size in bytes.
    pub size_bytes: u64,
}

/// Resolve a blob's MIME type from the client-declared `Content-Type` reconciled against a
/// content sniff, matching the reference PDS (`sniffedMime ?? userSuggestedMime`).
///
/// A confident magic-byte match for a concrete binary/media format always wins — a client
/// cannot mislabel binary content (e.g. PNG bytes announced as `text/html`). `infer`'s
/// heuristic *text* matchers (`text/html`, `text/xml`, ...) are deliberately not treated as
/// confident: text-family formats (SVG, JSON, VTT, ...) have no reliable magic bytes, so a
/// valid client-declared `Content-Type` is authoritative for them. Falls back to
/// `application/octet-stream` when neither yields a usable type.
pub fn resolve_mime_type(declared: Option<&str>, content: &[u8]) -> String {
    if let Some(kind) = infer::get(content) {
        if kind.matcher_type() != infer::MatcherType::Text {
            return kind.mime_type().to_string();
        }
    }
    normalize_declared_mime(declared).unwrap_or_else(|| "application/octet-stream".to_string())
}

/// Normalize a client-declared `Content-Type` to a bare, validated `type/subtype` essence,
/// or `None` when it is absent or not a well-formed MIME type. Strips any parameters
/// (`; charset=...`), trims surrounding whitespace, and lowercases (MIME types are
/// case-insensitive).
fn normalize_declared_mime(declared: Option<&str>) -> Option<String> {
    let essence = declared?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    is_valid_mime_essence(&essence).then_some(essence)
}

/// Whether `s` is a syntactically valid `type/subtype` MIME essence: exactly one `/`, both
/// halves non-empty RFC-6838/RFC-2045 token chars, and ≤255 bytes.
fn is_valid_mime_essence(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    let mut parts = s.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(kind), Some(sub), None) => {
            !kind.is_empty()
                && !sub.is_empty()
                && kind.bytes().all(is_mime_token_byte)
                && sub.bytes().all(is_mime_token_byte)
        }
        _ => false,
    }
}

/// A MIME token byte: ASCII alphanumerics plus the small punctuation set MIME essences use
/// (notably `+` for `image/svg+xml`, `.` for `application/vnd.foo`).
fn is_mime_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
        )
}

/// Store a blob on disk and return its CID, MIME type, and storage path.
///
/// Content is written to `{data_dir}/blobs/{cid[0:2]}/{cid}`. The CID is a CIDv1 (raw codec,
/// SHA-256 multihash) encoded in base32 (`bafk...`). `mime_type` is stored verbatim — the
/// caller resolves it (see [`resolve_mime_type`]) so the scope check that gates the upload,
/// the persisted row, and the later `getBlob` response all agree on one type.
pub async fn store_blob(
    data_dir: &Path,
    content: &[u8],
    mime_type: &str,
) -> Result<StoredBlob, BlobStoreError> {
    // 1. Compute SHA-256 multihash.
    let cid = compute_cid(content);

    // 2. Build storage path: blobs/{prefix}/{cid}
    let prefix = &cid[..2.min(cid.len())];
    let rel_path = format!("blobs/{prefix}/{cid}");
    let abs_path = data_dir.join(&rel_path);

    // 3. Create parent directory and write.
    if let Some(parent) = abs_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&abs_path, content).await?;

    Ok(StoredBlob {
        cid,
        mime_type: mime_type.to_string(),
        storage_path: rel_path,
        size_bytes: content.len() as u64,
    })
}

/// Read a blob from disk by CID.
///
/// `storage_path` is the relative path stored in the DB (e.g. "blobs/ba/bafy...").
pub async fn read_blob(data_dir: &Path, storage_path: &str) -> Result<Vec<u8>, BlobStoreError> {
    let abs_path = data_dir.join(storage_path);
    Ok(tokio::fs::read(abs_path).await?)
}

/// Delete a blob from disk. Returns Ok(true) if the file existed, Ok(false) if not found.
///
/// Avoids TOCTOU by attempting the delete directly and matching on the error kind,
/// rather than checking `exists()` first.
pub async fn delete_blob_file(data_dir: &Path, storage_path: &str) -> Result<bool, BlobStoreError> {
    let abs_path = data_dir.join(storage_path);
    match tokio::fs::remove_file(&abs_path).await {
        Ok(()) => {
            // Best-effort prefix-directory cleanup: the blob file is already gone, so a failure to
            // read the directory or confirm it is empty must NOT turn a successful delete into an
            // error. Callers (blob_gc, account_delete) key the DB-row delete on this `Ok(true)`;
            // propagating a cleanup I/O error would strand the row pointing at a now-missing file.
            if let Some(parent) = abs_path.parent() {
                if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
                    if matches!(entries.next_entry().await, Ok(None)) {
                        tokio::fs::remove_dir(parent).await.ok();
                    }
                }
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BlobStoreError::Io(e)),
    }
}

/// Compute the CID the blob store would assign to `content` — a CIDv1 (raw codec, SHA-256)
/// in base32. This is the store's single content-identity function: the upload path names
/// files with it, and the blob mirror re-runs it to verify bytes against their claimed CID
/// before trusting them (before uploading a local file to the mirror bucket, and before
/// restoring a bucket copy onto the volume).
pub fn compute_cid(content: &[u8]) -> String {
    build_cid(Sha256::digest(content).as_slice())
}

/// Build a CIDv1 (raw codec, SHA-256 multihash) from a 32-byte SHA-256 hash.
///
/// CIDv1 binary layout:
///   <multicodec varint: 0x01 (cidv1)>
///   <multicodec varint: 0x55 (raw)>
///   <multihash: 0x12 (sha-256)><0x20 (32 bytes)><hash bytes>
///
/// Encoded in base32 with `bafk` prefix (standard for raw CIDv1 with SHA-256).
fn build_cid(hash: &[u8]) -> String {
    debug_assert_eq!(hash.len(), 32, "SHA-256 hash must be 32 bytes");

    let mut cid_bytes = Vec::with_capacity(36);
    // CIDv1
    cid_bytes.push(0x01);
    // raw codec
    cid_bytes.push(0x55);
    // multihash: sha-256
    cid_bytes.push(0x12);
    // multihash length: 32
    cid_bytes.push(0x20);
    // hash digest
    cid_bytes.extend_from_slice(hash);

    // Base32 encode (RFC 4648, no padding). multibase prefix 'b'.
    use data_encoding::Specification;
    let mut spec = Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.padding = None;
    let encoder = spec.encoding().expect("base32 spec must be valid");
    let encoded = encoder.encode(&cid_bytes);

    format!("b{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_and_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"hello, blob world!";

        let stored = store_blob(dir.path(), content, "application/octet-stream")
            .await
            .unwrap();

        assert!(stored.cid.starts_with("bafk"), "CID must be base32 CIDv1");
        assert_eq!(stored.mime_type, "application/octet-stream");
        assert!(stored.storage_path.starts_with("blobs/"));
        assert_eq!(stored.size_bytes, content.len() as u64);

        let read_back = read_blob(dir.path(), &stored.storage_path).await.unwrap();
        assert_eq!(read_back, content);
    }

    #[tokio::test]
    async fn store_blob_persists_the_resolved_mime_verbatim() {
        // store_blob does not sniff — it stores exactly the caller-resolved type.
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"<svg></svg>", "image/svg+xml")
            .await
            .unwrap();
        assert_eq!(stored.mime_type, "image/svg+xml");
    }

    #[tokio::test]
    async fn same_content_same_cid() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"deterministic";

        let a = store_blob(dir.path(), content, "application/octet-stream")
            .await
            .unwrap();
        // Second write is idempotent (same CID, same path).
        let b = store_blob(dir.path(), content, "application/octet-stream")
            .await
            .unwrap();

        assert_eq!(a.cid, b.cid);
        assert_eq!(a.storage_path, b.storage_path);
    }

    #[tokio::test]
    async fn different_content_different_cid() {
        let dir = tempfile::tempdir().unwrap();
        let a = store_blob(dir.path(), b"alpha", "application/octet-stream")
            .await
            .unwrap();
        let b = store_blob(dir.path(), b"bravo", "application/octet-stream")
            .await
            .unwrap();

        assert_ne!(a.cid, b.cid);
    }

    #[tokio::test]
    async fn prefix_fanout_creates_two_char_directory() {
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"fanout test", "application/octet-stream")
            .await
            .unwrap();

        // storage_path should be like "blobs/ba/bafk..."
        let parts: Vec<&str> = stored.storage_path.split('/').collect();
        assert_eq!(parts.len(), 3, "path must be blobs/prefix/cid");
        assert_eq!(parts[0], "blobs");
        assert_eq!(parts[1].len(), 2, "prefix must be 2 chars");
    }

    #[tokio::test]
    async fn delete_blob_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"delete me", "application/octet-stream")
            .await
            .unwrap();

        let deleted = delete_blob_file(dir.path(), &stored.storage_path)
            .await
            .unwrap();
        assert!(deleted);

        let exists = read_blob(dir.path(), &stored.storage_path).await.is_ok();
        assert!(!exists, "file must be gone after delete");
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let deleted = delete_blob_file(dir.path(), "blobs/xx/nonexistent")
            .await
            .unwrap();
        assert!(!deleted);
    }

    #[test]
    fn build_cid_produces_expected_prefix() {
        // SHA-256 of empty string
        let hash = Sha256::digest(b"");
        let cid = build_cid(hash.as_slice());
        assert!(cid.starts_with('b'), "must be multibase base32");
        assert!(
            cid.starts_with("bafk"),
            "raw CIDv1 + SHA-256 starts with bafk"
        );
    }

    /// Known-answer test: SHA-256 of empty string must produce a specific CID.
    /// This catches bugs in CID encoding (wrong codec, wrong multihash, base32 errors).
    #[test]
    fn build_cid_known_answer_empty_string() {
        let hash = Sha256::digest(b"");
        let cid = build_cid(hash.as_slice());
        // This value is computed once and frozen. If this test fails, the CID
        // encoding is broken and all existing blobs become unreachable.
        assert_eq!(
            cid, "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
            "CID for SHA-256 of empty string must match known value"
        );
    }

    #[tokio::test]
    async fn read_blob_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_blob(dir.path(), "blobs/xx/nonexistent").await;
        assert!(result.is_err(), "must return error for missing file");
    }

    #[tokio::test]
    async fn empty_content_stores_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"", "application/octet-stream")
            .await
            .unwrap();

        assert_eq!(stored.size_bytes, 0);
        assert_eq!(stored.mime_type, "application/octet-stream");

        let read_back = read_blob(dir.path(), &stored.storage_path).await.unwrap();
        assert!(read_back.is_empty());
    }

    // ── resolve_mime_type ─────────────────────────────────────────────────────

    #[test]
    fn resolve_prefers_binary_sniff_over_declared() {
        // A concrete magic-byte match wins even against a (mis)declared type: a client can't
        // relabel PNG bytes as text/html and have them served as HTML.
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert_eq!(resolve_mime_type(Some("text/html"), &png), "image/png");
        // JPEG likewise (SOI + EOI).
        let jpeg = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9,
        ];
        assert_eq!(resolve_mime_type(None, &jpeg), "image/jpeg");
    }

    #[test]
    fn resolve_uses_declared_when_content_is_unsniffable() {
        // A plain <svg> has no magic bytes `infer` recognizes, so the declared type is used —
        // this is the case that lets a blob:image/* scoped token accept an SVG avatar.
        assert_eq!(
            resolve_mime_type(
                Some("image/svg+xml"),
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"
            ),
            "image/svg+xml"
        );
        assert_eq!(
            resolve_mime_type(Some("application/json"), b"{\"hello\":\"world\"}"),
            "application/json"
        );
    }

    #[test]
    fn resolve_ignores_heuristic_text_sniff_in_favor_of_declared() {
        // An SVG carrying an XML prolog sniffs to text/xml (a heuristic Text match), which must
        // NOT override the client's declared image/svg+xml.
        assert_eq!(
            resolve_mime_type(Some("image/svg+xml"), b"<?xml version=\"1.0\"?><svg></svg>"),
            "image/svg+xml"
        );
    }

    #[test]
    fn resolve_strips_parameters_and_normalizes_case() {
        assert_eq!(
            resolve_mime_type(Some("image/svg+xml; charset=utf-8"), b"<svg></svg>"),
            "image/svg+xml"
        );
        assert_eq!(
            resolve_mime_type(Some("IMAGE/SVG+XML"), b"<svg></svg>"),
            "image/svg+xml"
        );
    }

    #[test]
    fn resolve_falls_back_to_octet_stream() {
        // No declared type and nothing to sniff.
        assert_eq!(
            resolve_mime_type(None, b"just some bytes"),
            "application/octet-stream"
        );
        // A malformed declared type is rejected rather than stored.
        assert_eq!(
            resolve_mime_type(Some("not-a-mime-type"), b"just some bytes"),
            "application/octet-stream"
        );
        assert_eq!(
            resolve_mime_type(Some(""), b"just some bytes"),
            "application/octet-stream"
        );
    }
}
