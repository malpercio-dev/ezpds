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
    /// Detected MIME type (e.g. "image/jpeg").
    pub mime_type: String,
    /// Relative storage path under `data_dir` (e.g. "blobs/ba/bafy...").
    pub storage_path: String,
    /// Size in bytes.
    pub size_bytes: u64,
}

/// Detect a blob MIME type from magic bytes, falling back to generic binary.
pub fn detect_mime_type(content: &[u8]) -> String {
    infer::get(content)
        .map(|t| t.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

/// Store a blob on disk and return its CID, MIME type, and storage path.
///
/// Content is written to `{data_dir}/blobs/{cid[0:2]}/{cid}`.
/// CID is a CIDv1 (raw codec, SHA-256 multihash) encoded in base32 (`bafk...`).
/// MIME type is detected from the first 8192 bytes via magic bytes (`infer` crate).
/// Falls back to `application/octet-stream` when no magic bytes match.
pub async fn store_blob(data_dir: &Path, content: &[u8]) -> Result<StoredBlob, BlobStoreError> {
    // 1. Detect MIME type from magic bytes; fall back to generic binary.
    let mime_type = detect_mime_type(content);

    // 2. Compute SHA-256 multihash.
    let hash = Sha256::digest(content);
    let cid = build_cid(hash.as_slice());

    // 3. Build storage path: blobs/{prefix}/{cid}
    let prefix = &cid[..2.min(cid.len())];
    let rel_path = format!("blobs/{prefix}/{cid}");
    let abs_path = data_dir.join(&rel_path);

    // 4. Create parent directory and write.
    if let Some(parent) = abs_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&abs_path, content).await?;

    Ok(StoredBlob {
        cid,
        mime_type,
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
            // Best-effort: clean up the prefix directory if empty.
            if let Some(parent) = abs_path.parent() {
                if tokio::fs::read_dir(parent)
                    .await?
                    .next_entry()
                    .await?
                    .is_none()
                {
                    tokio::fs::remove_dir(parent).await.ok();
                }
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BlobStoreError::Io(e)),
    }
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

        let stored = store_blob(dir.path(), content).await.unwrap();

        assert!(stored.cid.starts_with("bafk"), "CID must be base32 CIDv1");
        assert_eq!(stored.mime_type, "application/octet-stream"); // no magic bytes → fallback
        assert!(stored.storage_path.starts_with("blobs/"));
        assert_eq!(stored.size_bytes, content.len() as u64);

        let read_back = read_blob(dir.path(), &stored.storage_path).await.unwrap();
        assert_eq!(read_back, content);
    }

    #[tokio::test]
    async fn jpeg_mime_detected() {
        let dir = tempfile::tempdir().unwrap();
        // Minimal JPEG: SOI marker + EOI marker
        let jpeg_bytes = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0xFF, 0xD9,
        ];

        let stored = store_blob(dir.path(), &jpeg_bytes).await.unwrap();
        assert_eq!(stored.mime_type, "image/jpeg");
    }

    #[tokio::test]
    async fn png_mime_detected() {
        let dir = tempfile::tempdir().unwrap();
        // PNG magic bytes (8-byte signature)
        let png_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];

        let stored = store_blob(dir.path(), &png_bytes).await.unwrap();
        assert_eq!(stored.mime_type, "image/png");
    }

    #[tokio::test]
    async fn same_content_same_cid() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"deterministic";

        let a = store_blob(dir.path(), content).await.unwrap();
        // Second write is idempotent (same CID, same path).
        let b = store_blob(dir.path(), content).await.unwrap();

        assert_eq!(a.cid, b.cid);
        assert_eq!(a.storage_path, b.storage_path);
    }

    #[tokio::test]
    async fn different_content_different_cid() {
        let dir = tempfile::tempdir().unwrap();
        let a = store_blob(dir.path(), b"alpha").await.unwrap();
        let b = store_blob(dir.path(), b"bravo").await.unwrap();

        assert_ne!(a.cid, b.cid);
    }

    #[tokio::test]
    async fn prefix_fanout_creates_two_char_directory() {
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"fanout test").await.unwrap();

        // storage_path should be like "blobs/ba/bafk..."
        let parts: Vec<&str> = stored.storage_path.split('/').collect();
        assert_eq!(parts.len(), 3, "path must be blobs/prefix/cid");
        assert_eq!(parts[0], "blobs");
        assert_eq!(parts[1].len(), 2, "prefix must be 2 chars");
    }

    #[tokio::test]
    async fn delete_blob_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let stored = store_blob(dir.path(), b"delete me").await.unwrap();

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
        let stored = store_blob(dir.path(), b"").await.unwrap();

        assert_eq!(stored.size_bytes, 0);
        assert_eq!(stored.mime_type, "application/octet-stream");

        let read_back = read_blob(dir.path(), &stored.storage_path).await.unwrap();
        assert!(read_back.is_empty());
    }
}
