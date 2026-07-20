// pattern: Mixed (Functional Core sync/restore logic + error mapping; Imperative Shell commands)
//
// User-held blob backup: a content-addressed mirror of the account's blobs in the
// wallet's iCloud Drive ubiquity container (`Documents/blobs/{cid}`), the one backup
// layer that survives the PDS itself failing. Content addressing makes the mirror
// trustless — restored bytes re-hash to the same CID, so records never need rewriting.
//
// Four Tauri IPC commands:
//
//   get_blob_backup_status(did)         — location + opt-in flag + mirror size
//   set_blob_backup_enabled(did, bool)  — the explicit opt-in toggle
//   run_blob_backup(did)                — incremental sync pass (listBlobs → diff →
//                                         getBlob → verify CID → write → manifest)
//   restore_blob_backup(did)            — walk the manifest, uploadBlob each file
//
// The sync pass verifies every fetched blob against its CID (CIDv1, raw codec,
// SHA-256 multihash — the exact encoding the PDS's `blob_store::build_cid` emits)
// before writing, so corrupt bytes are never enshrined as the recovery copy — the
// client-side twin of the server's verify-on-serve. Both the sync and the restore
// degrade per-blob: one dead blob becomes a report entry, never an aborted run.
//
// On a real iOS device the mirror root is the app's iCloud Drive ubiquity container
// (user-visible in the Files app; iOS syncs it). Everywhere else (macOS host builds,
// the simulator, tests) it falls back to a local app-data directory so the surface
// stays exercisable, reported distinctly as `location: "local"`. The restore path
// treats an unreadable file (e.g. an undownloaded iCloud placeholder) as a per-blob
// failure with guidance, not a run-stopper.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity_store::IdentityStore;
use crate::oauth_client::OAuthClient;
use crate::pds_client::{self, PdsClient, PdsClientError};
use crate::session_provider::{SessionError, SessionProvider, UnlockReason};

/// Dev/test override for the backup root directory. When set, backups land there
/// (reported as `location: "local"`) regardless of platform — this is what lets the
/// unit tests and a desktop dev build drive the full flow without iCloud.
const BACKUP_DIR_ENV: &str = "EZPDS_BLOB_BACKUP_DIR";

/// Manifest schema version (bump on breaking layout changes).
const MANIFEST_VERSION: u32 = 1;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the blob-backup commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling
/// wallet error enums (`HandleChangeError`, `AppPasswordsError`, `SessionError`).
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum BlobBackupError {
    /// No backup location is available on this device (iOS with iCloud Drive off —
    /// the mirror must not silently land somewhere that doesn't survive the device).
    #[error("no backup location is available (is iCloud Drive enabled?)")]
    BackupUnavailable,
    /// The identity's session could not be resolved without a passwordless unlock —
    /// the frontend should run the biometric sovereign login and retry (restore only;
    /// the backup pass reads public sync endpoints and needs no session).
    #[error("identity is locked and needs a passwordless unlock")]
    SessionLocked { reason: UnlockReason },
    /// The hosting PDS or plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The DID is not registered in this wallet.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// A plc.directory read failed with an HTTP verdict (the hosting-PDS discovery).
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    /// A server-side step failed for a non-connectivity reason (an XRPC refusal, a
    /// session refresh verdict, unsupported host, or malformed response).
    #[error("server error: {message}")]
    ServerError {
        status: Option<u16>,
        message: String,
    },
    /// A network / transport call failed.
    #[error("network error: {message}")]
    NetworkError { message: String },
    /// Local file I/O on the mirror failed.
    #[error("storage error: {message}")]
    StorageError { message: String },
    /// The backup manifest exists but could not be read or parsed. Fail-closed: the
    /// file is preserved (it may name blobs the PDS has since lost), never rebuilt over.
    #[error("backup manifest is corrupt: {message}")]
    ManifestCorrupt { message: String },
    /// The opt-in flag could not be read from / written to the Keychain.
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

/// Map a session-lifecycle failure into the blob-backup surface. Exhaustive on purpose:
/// only a genuine transport failure becomes `NetworkError` — a server verdict, unsupported
/// host, or storage failure must not surface as "check your connection" (the same defect
/// class `classify_xrpc_error` exists to fix).
fn map_session_error(error: SessionError) -> BlobBackupError {
    match error {
        SessionError::NeedsUnlock { reason } => BlobBackupError::SessionLocked { reason },
        SessionError::RateLimited { retry_after } => BlobBackupError::RateLimited { retry_after },
        SessionError::IdentityNotFound => BlobBackupError::IdentityNotFound {
            message: "identity not found".to_string(),
        },
        SessionError::Offline { message } => BlobBackupError::NetworkError { message },
        SessionError::ServerFailure { status } => BlobBackupError::ServerError {
            status: Some(status),
            message: format!("session request failed with status {status}"),
        },
        SessionError::UnsupportedHost => BlobBackupError::ServerError {
            status: None,
            message: "the identity's hosting server does not support session refresh".to_string(),
        },
        SessionError::Keychain { message } => BlobBackupError::ServerError {
            status: None,
            message: format!("session keychain failure: {message}"),
        },
        SessionError::InvalidResponse { message } => BlobBackupError::ServerError {
            status: None,
            message: format!("invalid session response: {message}"),
        },
    }
}

/// Map a plc.directory / PDS read failure into the blob-backup surface: a throttle is
/// retryable (`RateLimited`), an HTTP verdict names the server's reason, and only a
/// transport failure is `NetworkError` (mirrors `handle_change::map_plc_fetch_error`).
fn map_fetch_error(context: &str, error: PdsClientError) -> BlobBackupError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            BlobBackupError::RateLimited { retry_after }
        }
        PdsClientError::DidNotFound => BlobBackupError::PlcDirectoryError {
            message: format!("{context}: DID not found in the PLC directory"),
        },
        PdsClientError::XrpcError {
            status, message, ..
        } => BlobBackupError::ServerError {
            status: Some(status),
            message: format!("{context}: {message}"),
        },
        PdsClientError::Unauthorized { message, .. } => BlobBackupError::ServerError {
            status: Some(401),
            message: format!("{context}: {message}"),
        },
        PdsClientError::InvalidResponse { message } => BlobBackupError::ServerError {
            status: None,
            message: format!("{context}: {message}"),
        },
        other => BlobBackupError::NetworkError {
            message: format!("{context}: {other}"),
        },
    }
}

// ── Types ────────────────────────────────────────────────────────────────────

/// One backed-up blob in the manifest: everything a restore needs to `uploadBlob`
/// the bytes back with their original MIME type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub cid: String,
    pub mime_type: String,
    pub size: u64,
    pub fetched_at: String,
}

/// The per-DID backup manifest, stored beside the blobs as
/// `manifests/{sanitized-did}.json`. Versioned like the other durable wallet records.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u32,
    did: String,
    #[serde(default)]
    last_backup_at: Option<String>,
    entries: Vec<ManifestEntry>,
}

impl Manifest {
    fn new(did: &str) -> Self {
        Self {
            version: MANIFEST_VERSION,
            did: did.to_string(),
            last_backup_at: None,
            entries: Vec::new(),
        }
    }
}

/// Where the mirror lives, as reported to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupLocation {
    /// The app's iCloud Drive ubiquity container (survives the device; Files-app visible).
    Icloud,
    /// A local app-data directory (dev/simulator/desktop fallback, or the env override).
    Local,
}

/// The status readout backing the Media Backup screen.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobBackupStatus {
    /// The user's explicit opt-in flag for the opportunistic pass on app open.
    pub enabled: bool,
    /// Where the mirror lives, or `None` when no location is available (iCloud off).
    pub location: Option<BackupLocation>,
    /// Blobs currently recorded in the manifest.
    pub backed_up_count: u64,
    /// Total manifest bytes — the mirror size shown before opting in (iCloud is a
    /// shared 5 GB free tier; video accounts get large).
    pub backed_up_bytes: u64,
    /// When the last sync pass completed (RFC 3339), if ever.
    pub last_backup_at: Option<String>,
}

/// A per-blob failure in a sync or restore run — the informed-skip record, so one
/// dead blob never parks the whole run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobFailure {
    pub cid: String,
    pub reason: String,
}

/// Report from one backup sync pass.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobBackupRunReport {
    /// CIDs the PDS listed for the account.
    pub listed: u64,
    /// Already present in the mirror (skipped — the pass is incremental).
    pub already_present: u64,
    /// Newly fetched, verified, and written this run.
    pub fetched: u64,
    /// Bytes fetched this run.
    pub fetched_bytes: u64,
    /// Per-blob failures (fetch errors, CID mismatches). The run continues past them.
    pub failed: Vec<BlobFailure>,
    /// Manifest totals after the run.
    pub backed_up_count: u64,
    pub backed_up_bytes: u64,
}

/// Report from one restore pass.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobRestoreReport {
    /// Entries in the manifest.
    pub manifest_count: u64,
    /// Blobs uploaded to the PDS this run.
    pub uploaded: u64,
    /// Per-blob failures (unreadable/undownloaded files, hash mismatches, upload
    /// refusals). The run continues past them.
    pub failed: Vec<BlobFailure>,
}

// ── CID computation (Functional Core) ────────────────────────────────────────

/// Compute the blob CID for `content`: CIDv1, raw codec, SHA-256 multihash, encoded
/// as multibase base32-lower — byte-for-byte the encoding the PDS's
/// `blob_store::build_cid` emits and `listBlobs`/blob refs carry (`bafk…`).
pub(crate) fn blob_cid(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    let mut cid_bytes = Vec::with_capacity(36);
    // CIDv1, raw codec, multihash sha-256, length 32.
    cid_bytes.extend_from_slice(&[0x01, 0x55, 0x12, 0x20]);
    cid_bytes.extend_from_slice(&digest);
    multibase::encode(multibase::Base::Base32Lower, cid_bytes)
}

/// Whether a server-supplied CID string is safe to use as a file name. Base32-lower
/// CIDs are `[a-z0-9]+`; anything else (path separators, dots) is refused before it
/// can touch the filesystem.
fn cid_is_safe_filename(cid: &str) -> bool {
    !cid.is_empty()
        && cid.len() <= 256
        && cid
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Render a DID as a filesystem-safe manifest file stem (`:` → `_`; any other
/// non-portable byte likewise).
fn sanitize_did(did: &str) -> String {
    did.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ── Mirror layout + manifest I/O ─────────────────────────────────────────────

fn blobs_dir(root: &Path) -> PathBuf {
    root.join("blobs")
}

fn blob_path(root: &Path, cid: &str) -> PathBuf {
    blobs_dir(root).join(cid)
}

fn manifest_path(root: &Path, did: &str) -> PathBuf {
    root.join("manifests")
        .join(format!("{}.json", sanitize_did(did)))
}

fn storage_error(context: &str, e: std::io::Error) -> BlobBackupError {
    BlobBackupError::StorageError {
        message: format!("{context}: {e}"),
    }
}

/// Load the DID's manifest. An absent file is an empty manifest; a present-but-
/// unreadable one is `ManifestCorrupt` and the file is preserved — it may be the only
/// record of blob MIME types for bytes the PDS has since lost, so it is never rebuilt
/// over (the fail-closed posture of `ceremony-staging`).
async fn load_manifest(root: &Path, did: &str) -> Result<Manifest, BlobBackupError> {
    let path = manifest_path(root, did);
    let raw = match tokio::fs::read(&path).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Manifest::new(did)),
        Err(e) => return Err(storage_error("failed to read backup manifest", e)),
    };
    serde_json::from_slice::<Manifest>(&raw).map_err(|e| BlobBackupError::ManifestCorrupt {
        message: e.to_string(),
    })
}

/// Persist the manifest atomically (temp file + rename in the same directory).
async fn save_manifest(root: &Path, did: &str, manifest: &Manifest) -> Result<(), BlobBackupError> {
    let path = manifest_path(root, did);
    let dir = path
        .parent()
        .expect("manifest path always has a parent directory")
        .to_path_buf();
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| storage_error("failed to create manifest directory", e))?;
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| BlobBackupError::StorageError {
        message: format!("failed to encode backup manifest: {e}"),
    })?;
    let tmp = dir.join(format!(".tmp-manifest-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, &json)
        .await
        .map_err(|e| storage_error("failed to write backup manifest", e))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| storage_error("failed to finalize backup manifest", e))
}

/// Write verified blob bytes atomically at their CID path (temp file + rename, so a
/// crash never leaves truncated bytes at a valid CID name — the wallet-side twin of
/// the PDS's crash-durable `store_blob`).
async fn write_blob(root: &Path, cid: &str, bytes: &[u8]) -> Result<(), BlobBackupError> {
    let dir = blobs_dir(root);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| storage_error("failed to create blobs directory", e))?;
    let tmp = dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| storage_error("failed to write blob", e))?;
    tokio::fs::rename(&tmp, blob_path(root, cid))
        .await
        .map_err(|e| storage_error("failed to finalize blob", e))
}

// ── Backup root resolution ───────────────────────────────────────────────────

/// The app's iCloud Drive ubiquity container `Documents/` directory, if available.
///
/// `URLForUbiquityContainerIdentifier(nil)` resolves the app's default container
/// (from the `com.apple.developer.ubiquity-container-identifiers` entitlement) and
/// extends the sandbox to it; iOS syncs anything written there and the mirror is
/// user-visible in the Files app. Returns `None` when the user has iCloud Drive off
/// (or the entitlement is absent). Called off the main thread by construction —
/// Tauri async commands run on a worker pool, and Apple documents the call as
/// potentially slow.
#[cfg(target_os = "ios")]
fn ubiquity_documents_dir() -> Option<PathBuf> {
    use objc2_foundation::NSFileManager;
    let manager = NSFileManager::defaultManager();
    let url = manager.URLForUbiquityContainerIdentifier(None)?;
    let path = url.path()?;
    Some(PathBuf::from(path.to_string()).join("Documents"))
}

#[cfg(not(target_os = "ios"))]
fn ubiquity_documents_dir() -> Option<PathBuf> {
    None
}

/// Resolve where the mirror lives, or `None` when no acceptable location exists.
///
/// Order: the env override (tests/dev) → the iCloud ubiquity container → on a real
/// iOS device, **nothing** (a silent local fallback would tell the user they hold a
/// device-loss-surviving copy when they don't) → elsewhere (macOS host, simulator),
/// a local app-data directory so the whole surface stays exercisable off-device.
#[cfg_attr(
    all(target_os = "ios", not(target_env = "sim")),
    allow(unused_variables)
)]
fn resolve_backup_root(app: &tauri::AppHandle) -> Option<(PathBuf, BackupLocation)> {
    if let Ok(dir) = std::env::var(BACKUP_DIR_ENV) {
        if !dir.is_empty() {
            return Some((PathBuf::from(dir), BackupLocation::Local));
        }
    }
    if let Some(dir) = ubiquity_documents_dir() {
        return Some((dir, BackupLocation::Icloud));
    }
    #[cfg(all(target_os = "ios", not(target_env = "sim")))]
    {
        None
    }
    #[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
    {
        use tauri::Manager;
        let dir = app.path().app_data_dir().ok()?.join("blob-backup");
        Some((dir, BackupLocation::Local))
    }
}

// ── Opt-in flag ──────────────────────────────────────────────────────────────

/// Per-DID Keychain account holding the opt-in flag (`"true"` / `"false"`).
/// Referenced by `IdentityStore::remove_identity` for cleanup.
pub(crate) fn backup_enabled_account(did: &str) -> String {
    format!("{did}:blob-backup-enabled")
}

fn load_enabled(did: &str) -> bool {
    crate::keychain::get_item(&backup_enabled_account(did))
        .map(|v| v == b"true")
        .unwrap_or(false)
}

fn store_enabled(did: &str, enabled: bool) -> Result<(), BlobBackupError> {
    let value: &[u8] = if enabled { b"true" } else { b"false" };
    crate::keychain::store_item(&backup_enabled_account(did), value).map_err(|e| {
        BlobBackupError::KeychainError {
            message: e.to_string(),
        }
    })
}

// ── Cores (testable without Tauri) ───────────────────────────────────────────

/// Build the status readout from the manifest on disk.
async fn status_core(
    root: Option<&Path>,
    location: Option<BackupLocation>,
    did: &str,
) -> Result<BlobBackupStatus, BlobBackupError> {
    let (backed_up_count, backed_up_bytes, last_backup_at) = match root {
        Some(root) => {
            let manifest = load_manifest(root, did).await?;
            (
                manifest.entries.len() as u64,
                manifest.entries.iter().map(|e| e.size).sum(),
                manifest.last_backup_at,
            )
        }
        None => (0, 0, None),
    };
    Ok(BlobBackupStatus {
        enabled: load_enabled(did),
        location,
        backed_up_count,
        backed_up_bytes,
        last_backup_at,
    })
}

/// One incremental sync pass: list the account's blobs on its PDS, fetch what the
/// mirror lacks, verify each against its CID, write, and record in the manifest.
/// Idempotent by construction (content-addressed, immutable files); degrades per-blob.
pub(crate) async fn run_backup_core(
    pds_client: &PdsClient,
    root: &Path,
    did: &str,
    pds_url: &str,
) -> Result<BlobBackupRunReport, BlobBackupError> {
    let mut manifest = load_manifest(root, did).await?;
    let mut known: HashMap<String, usize> = manifest
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.cid.clone(), i))
        .collect();

    // Enumerate every remote CID first (pages are small — bare CID strings).
    let mut remote_cids: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = pds_client
            .list_blobs(pds_url, did, cursor.as_deref())
            .await
            .map_err(|e| map_fetch_error("failed to list blobs", e))?;
        let page_len = page.cids.len();
        remote_cids.extend(page.cids);
        match page.cursor {
            // A cursor with an empty page would loop forever; treat it as the end.
            Some(next) if page_len > 0 => cursor = Some(next),
            _ => break,
        }
    }

    let mut report = BlobBackupRunReport {
        listed: remote_cids.len() as u64,
        already_present: 0,
        fetched: 0,
        fetched_bytes: 0,
        failed: Vec::new(),
        backed_up_count: 0,
        backed_up_bytes: 0,
    };

    for cid in &remote_cids {
        if !cid_is_safe_filename(cid) {
            report.failed.push(BlobFailure {
                cid: cid.clone(),
                reason: "server listed a malformed CID".to_string(),
            });
            continue;
        }

        // Present = recorded in the manifest AND the file is still there (a file the
        // user deleted in the Files app is re-fetched; an iCloud-evicted file reads
        // as absent and is harmlessly re-fetched too).
        let file_exists = tokio::fs::try_exists(blob_path(root, cid))
            .await
            .unwrap_or(false);
        if known.contains_key(cid.as_str()) && file_exists {
            report.already_present += 1;
            continue;
        }

        let (bytes, content_type) = match pds_client.fetch_blob_with_type(pds_url, did, cid).await {
            Ok(fetched) => fetched,
            Err(e) => {
                tracing::warn!(did = %did, cid = %cid, error = %e, "blob backup: fetch failed");
                report.failed.push(BlobFailure {
                    cid: cid.clone(),
                    reason: format!("fetch failed: {e}"),
                });
                continue;
            }
        };

        // Verify before writing — never back up bytes that don't re-hash to the CID
        // (the client-side twin of the PDS's verify-on-serve).
        let computed = blob_cid(&bytes);
        if &computed != cid {
            tracing::error!(did = %did, cid = %cid, computed = %computed, "blob backup: CID mismatch, refusing to mirror");
            report.failed.push(BlobFailure {
                cid: cid.clone(),
                reason: "server returned bytes that do not match the CID".to_string(),
            });
            continue;
        }

        if let Err(e) = write_blob(root, cid, &bytes).await {
            report.failed.push(BlobFailure {
                cid: cid.clone(),
                reason: e.to_string(),
            });
            continue;
        }

        let entry = ManifestEntry {
            cid: cid.clone(),
            mime_type: content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
            size: bytes.len() as u64,
            fetched_at: chrono::Utc::now().to_rfc3339(),
        };
        match known.get(cid.as_str()) {
            Some(&i) => manifest.entries[i] = entry,
            None => {
                known.insert(cid.clone(), manifest.entries.len());
                manifest.entries.push(entry);
            }
        }
        // Persist after every blob so an interrupted run resumes where it stopped.
        save_manifest(root, did, &manifest).await?;

        report.fetched += 1;
        report.fetched_bytes += bytes.len() as u64;
    }

    manifest.last_backup_at = Some(chrono::Utc::now().to_rfc3339());
    save_manifest(root, did, &manifest).await?;

    report.backed_up_count = manifest.entries.len() as u64;
    report.backed_up_bytes = manifest.entries.iter().map(|e| e.size).sum();
    Ok(report)
}

/// One restore pass: walk the manifest and `uploadBlob` each mirrored file back to
/// the DID's current PDS with its stored MIME type. Content addressing makes this
/// trustless — the PDS recomputes the same CID, so records never need rewriting.
/// Degrades per-blob (an undownloaded iCloud placeholder or corrupt file is a report
/// entry with guidance, never an aborted run).
pub(crate) async fn restore_core(
    client: &OAuthClient,
    root: &Path,
    did: &str,
) -> Result<BlobRestoreReport, BlobBackupError> {
    let manifest = load_manifest(root, did).await?;
    let mut report = BlobRestoreReport {
        manifest_count: manifest.entries.len() as u64,
        uploaded: 0,
        failed: Vec::new(),
    };

    for entry in &manifest.entries {
        if !cid_is_safe_filename(&entry.cid) {
            report.failed.push(BlobFailure {
                cid: entry.cid.clone(),
                reason: "manifest entry has a malformed CID".to_string(),
            });
            continue;
        }
        let bytes = match tokio::fs::read(blob_path(root, &entry.cid)).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.failed.push(BlobFailure {
                    cid: entry.cid.clone(),
                    reason: "file is not on this device — download it in the Files app and retry"
                        .to_string(),
                });
                continue;
            }
            Err(e) => {
                report.failed.push(BlobFailure {
                    cid: entry.cid.clone(),
                    reason: format!("failed to read mirrored file: {e}"),
                });
                continue;
            }
        };

        // Verify the local copy still re-hashes to its CID before uploading — a
        // corrupted mirror file must not be pushed back as the account's media.
        if blob_cid(&bytes) != entry.cid {
            report.failed.push(BlobFailure {
                cid: entry.cid.clone(),
                reason: "mirrored file no longer matches its CID (corrupt copy)".to_string(),
            });
            continue;
        }

        match pds_client::upload_blob(client, &entry.mime_type, bytes).await {
            Ok(_) => report.uploaded += 1,
            Err(e) => {
                tracing::warn!(did = %did, cid = %entry.cid, error = %e, "blob restore: upload failed");
                report.failed.push(BlobFailure {
                    cid: entry.cid.clone(),
                    reason: format!("upload failed: {e}"),
                });
            }
        }
    }

    Ok(report)
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Resolve the DID's full-access session (restore / refresh, or `SessionLocked`).
async fn full_access_session(
    pds_client: &PdsClient,
    did: &str,
) -> Result<crate::session_provider::ActiveSession, BlobBackupError> {
    let now =
        crate::sovereign_session::unix_timestamp().map_err(|_| BlobBackupError::NetworkError {
            message: "system clock is unavailable".to_string(),
        })?;
    SessionProvider
        .full_access_client(pds_client, &IdentityStore, did, now)
        .await
        .map_err(map_session_error)
}

/// Discover the DID's current hosting PDS endpoint via plc.directory.
async fn hosting_pds_url(pds_client: &PdsClient, did: &str) -> Result<String, BlobBackupError> {
    let (pds_url, _doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(|e| map_fetch_error("failed to discover hosting PDS", e))?;
    Ok(pds_url)
}

/// Tauri command: the Media Backup screen's status readout — mirror location (or its
/// absence), the opt-in flag, and the mirror's size (shown before opting in).
#[tauri::command]
pub async fn get_blob_backup_status(
    app: tauri::AppHandle,
    did: String,
) -> Result<BlobBackupStatus, BlobBackupError> {
    match resolve_backup_root(&app) {
        Some((root, location)) => status_core(Some(&root), Some(location), &did).await,
        None => status_core(None, None, &did).await,
    }
}

/// Tauri command: flip the explicit opt-in flag. Returns the refreshed status.
#[tauri::command]
pub async fn set_blob_backup_enabled(
    app: tauri::AppHandle,
    did: String,
    enabled: bool,
) -> Result<BlobBackupStatus, BlobBackupError> {
    store_enabled(&did, enabled)?;
    get_blob_backup_status(app, did).await
}

/// Tauri command: run one incremental backup sync pass for the identity. Reads only
/// public sync endpoints (`listBlobs`/`getBlob`), so it needs no session.
#[tauri::command]
pub async fn run_blob_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<BlobBackupRunReport, BlobBackupError> {
    let (root, _location) = resolve_backup_root(&app).ok_or(BlobBackupError::BackupUnavailable)?;
    let pds_client = state.pds_client();
    let pds_url = hosting_pds_url(pds_client, &did).await?;
    run_backup_core(pds_client, &root, &did, &pds_url).await
}

/// Tauri command: restore the mirrored blobs to the DID's current PDS. Requires a
/// full-access session (`uploadBlob`); a `SESSION_LOCKED` result cues the frontend
/// to run the biometric `sovereignLogin(did)` and retry.
#[tauri::command]
pub async fn restore_blob_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::oauth::AppState>,
    did: String,
) -> Result<BlobRestoreReport, BlobBackupError> {
    let (root, _location) = resolve_backup_root(&app).ok_or(BlobBackupError::BackupUnavailable)?;
    let session = full_access_session(state.pds_client(), &did).await?;
    restore_core(&session.client, &root, &did).await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;

    /// A JWT whose `exp` is far in the future — Bearer test clients need one, else
    /// `new_bearer` sets expires_at=0 and a proactive refresh fires before the
    /// request under test (same helper as the migration orchestrator's tests).
    fn make_bearer_jwt() -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"exp":9999999999}"#);
        format!("{}.{}.sig", header, payload)
    }

    // ── CID computation ────────────────────────────────────────────────────

    #[test]
    fn blob_cid_matches_known_vectors() {
        // Fixed vectors for CIDv1 (raw codec, SHA-256, base32-lower) — the exact
        // encoding the PDS's blob_store::build_cid emits.
        assert_eq!(
            blob_cid(b"hello world"),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
        assert_eq!(
            blob_cid(b""),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
    }

    #[test]
    fn cid_filename_guard_rejects_traversal() {
        assert!(cid_is_safe_filename(
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        ));
        assert!(!cid_is_safe_filename(""));
        assert!(!cid_is_safe_filename("../etc/passwd"));
        assert!(!cid_is_safe_filename("a/b"));
        assert!(!cid_is_safe_filename("UPPER"));
        assert!(!cid_is_safe_filename(".hidden"));
    }

    #[test]
    fn sanitize_did_makes_a_portable_file_stem() {
        assert_eq!(sanitize_did("did:plc:abc123"), "did_plc_abc123");
        assert_eq!(sanitize_did("did:web:example.com"), "did_web_example.com");
    }

    // ── Error mapping ──────────────────────────────────────────────────────

    #[test]
    fn needs_unlock_maps_to_session_locked() {
        let err = map_session_error(SessionError::NeedsUnlock {
            reason: UnlockReason::NoRefreshChain,
        });
        assert!(matches!(
            err,
            BlobBackupError::SessionLocked {
                reason: UnlockReason::NoRefreshChain
            }
        ));
    }

    #[test]
    fn fetch_error_mapping_keeps_the_server_reason() {
        let throttled = map_fetch_error(
            "ctx",
            PdsClientError::RateLimited {
                retry_after: Some("30".into()),
                message: "slow down".into(),
            },
        );
        assert!(
            matches!(throttled, BlobBackupError::RateLimited { retry_after: Some(ref s) } if s == "30")
        );

        let verdict = map_fetch_error(
            "ctx",
            PdsClientError::XrpcError {
                status: 503,
                error: None,
                message: "maintenance".into(),
            },
        );
        assert!(
            matches!(verdict, BlobBackupError::ServerError { status: Some(503), ref message } if message.contains("maintenance"))
        );

        let transport = map_fetch_error(
            "ctx",
            PdsClientError::NetworkError {
                message: "dns".into(),
            },
        );
        assert!(matches!(transport, BlobBackupError::NetworkError { .. }));
    }

    #[test]
    fn error_serialization_shape() {
        let err = BlobBackupError::BackupUnavailable;
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains(r#""code":"BACKUP_UNAVAILABLE""#));

        let err = BlobBackupError::SessionLocked {
            reason: UnlockReason::HostChanged,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains(r#""code":"SESSION_LOCKED""#));
        assert!(json.contains(r#""reason":"HOST_CHANGED""#));
    }

    // ── Backup sync pass ───────────────────────────────────────────────────

    #[tokio::test]
    async fn backup_pass_fetches_verifies_and_records() {
        let server = MockServer::start_async().await;
        let did = "did:plc:backuptest";
        let blob_a = b"first blob bytes".to_vec();
        let blob_b = b"second blob, an image".to_vec();
        let cid_a = blob_cid(&blob_a);
        let cid_b = blob_cid(&blob_b);

        // Two pages: [a] with a cursor, then [b] without.
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.listBlobs")
                    .query_param_missing("cursor");
                then.status(200)
                    .json_body(serde_json::json!({ "cids": [cid_a], "cursor": "page2" }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.listBlobs")
                    .query_param("cursor", "page2");
                then.status(200)
                    .json_body(serde_json::json!({ "cids": [cid_b] }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.getBlob")
                    .query_param("cid", &cid_a);
                then.status(200)
                    .header("content-type", "application/octet-stream")
                    .body(blob_a.clone());
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.getBlob")
                    .query_param("cid", &cid_b);
                then.status(200)
                    .header("content-type", "image/png")
                    .body(blob_b.clone());
            })
            .await;

        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        let report = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();

        assert_eq!(report.listed, 2);
        assert_eq!(report.fetched, 2);
        assert_eq!(report.already_present, 0);
        assert!(report.failed.is_empty());
        assert_eq!(report.fetched_bytes, (blob_a.len() + blob_b.len()) as u64,);

        // Bytes landed at their CID paths.
        assert_eq!(
            tokio::fs::read(blob_path(dir.path(), &cid_a))
                .await
                .unwrap(),
            blob_a
        );
        assert_eq!(
            tokio::fs::read(blob_path(dir.path(), &cid_b))
                .await
                .unwrap(),
            blob_b
        );

        // The manifest recorded both, with the served MIME type.
        let manifest = load_manifest(dir.path(), did).await.unwrap();
        assert_eq!(manifest.entries.len(), 2);
        let entry_b = manifest.entries.iter().find(|e| e.cid == cid_b).unwrap();
        assert_eq!(entry_b.mime_type, "image/png");
        assert!(manifest.last_backup_at.is_some());

        // A second pass is a no-op: everything already present, nothing re-fetched.
        let second = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert_eq!(second.already_present, 2);
        assert_eq!(second.fetched, 0);
        assert_eq!(second.backed_up_count, 2);
    }

    #[tokio::test]
    async fn backup_pass_refuses_bytes_that_do_not_match_the_cid() {
        let server = MockServer::start_async().await;
        let did = "did:plc:corrupttest";
        let good = b"good bytes".to_vec();
        let cid_good = blob_cid(&good);
        // The server lists a CID but serves DIFFERENT bytes for it (the MM-394 class
        // of fault: metadata present, bytes wrong).
        let cid_listed = blob_cid(b"the original bytes the server lost");

        server
            .mock_async(|when, then| {
                when.method(GET).path("/xrpc/com.atproto.sync.listBlobs");
                then.status(200)
                    .json_body(serde_json::json!({ "cids": [cid_listed, cid_good] }));
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.getBlob")
                    .query_param("cid", &cid_listed);
                then.status(200).body(b"corrupted replacement".to_vec());
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/xrpc/com.atproto.sync.getBlob")
                    .query_param("cid", &cid_good);
                then.status(200).body(good.clone());
            })
            .await;

        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        let report = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();

        // The corrupt blob is a per-blob failure; the good one still lands.
        assert_eq!(report.fetched, 1);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].cid, cid_listed);
        assert!(report.failed[0].reason.contains("do not match"));
        assert!(!tokio::fs::try_exists(blob_path(dir.path(), &cid_listed))
            .await
            .unwrap());
        assert!(tokio::fs::try_exists(blob_path(dir.path(), &cid_good))
            .await
            .unwrap());
        let manifest = load_manifest(dir.path(), did).await.unwrap();
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].cid, cid_good);
    }

    #[tokio::test]
    async fn backup_pass_refetches_a_deleted_file() {
        let server = MockServer::start_async().await;
        let did = "did:plc:refetch";
        let blob = b"bytes the user deleted locally".to_vec();
        let cid = blob_cid(&blob);

        server
            .mock_async(|when, then| {
                when.method(GET).path("/xrpc/com.atproto.sync.listBlobs");
                then.status(200)
                    .json_body(serde_json::json!({ "cids": [cid] }));
            })
            .await;
        let get_mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/xrpc/com.atproto.sync.getBlob");
                then.status(200).body(blob.clone());
            })
            .await;

        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert_eq!(get_mock.calls_async().await, 1);

        // Simulate the user deleting the file in the Files app; the manifest entry
        // remains but the pass must re-fetch the bytes.
        tokio::fs::remove_file(blob_path(dir.path(), &cid))
            .await
            .unwrap();
        let report = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert_eq!(report.fetched, 1);
        assert_eq!(get_mock.calls_async().await, 2);
    }

    #[tokio::test]
    async fn corrupt_manifest_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let did = "did:plc:corruptmanifest";
        let path = manifest_path(dir.path(), did);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"{not json").await.unwrap();

        let err = load_manifest(dir.path(), did).await.unwrap_err();
        assert!(matches!(err, BlobBackupError::ManifestCorrupt { .. }));
        // The corrupt file is preserved, never rebuilt over.
        assert!(tokio::fs::try_exists(&path).await.unwrap());
    }

    // ── Restore pass ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn restore_uploads_each_entry_with_its_stored_mime() {
        let server = MockServer::start_async().await;
        let did = "did:plc:restoretest";
        let blob = b"restore me".to_vec();
        let cid = blob_cid(&blob);

        let dir = tempfile::tempdir().unwrap();
        write_blob(dir.path(), &cid, &blob).await.unwrap();
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            did: did.to_string(),
            last_backup_at: None,
            entries: vec![
                ManifestEntry {
                    cid: cid.clone(),
                    mime_type: "image/jpeg".to_string(),
                    size: blob.len() as u64,
                    fetched_at: "2026-07-20T00:00:00Z".to_string(),
                },
                // A manifest entry whose file was never downloaded on this device.
                ManifestEntry {
                    cid: blob_cid(b"missing on this device"),
                    mime_type: "video/mp4".to_string(),
                    size: 3,
                    fetched_at: "2026-07-20T00:00:00Z".to_string(),
                },
            ],
        };
        save_manifest(dir.path(), did, &manifest).await.unwrap();

        let upload_mock = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.repo.uploadBlob")
                    .header("content-type", "image/jpeg")
                    .body(std::str::from_utf8(&blob).unwrap());
                then.status(200).json_body(serde_json::json!({
                    "blob": { "$type": "blob", "ref": { "$link": cid }, "mimeType": "image/jpeg", "size": blob.len() }
                }));
            })
            .await;

        let client =
            OAuthClient::new_bearer(make_bearer_jwt(), String::new(), server.base_url()).unwrap();
        let report = restore_core(&client, dir.path(), did).await.unwrap();

        assert_eq!(report.manifest_count, 2);
        assert_eq!(report.uploaded, 1);
        assert_eq!(upload_mock.calls_async().await, 1);
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].reason.contains("not on this device"));
    }

    #[tokio::test]
    async fn restore_refuses_a_corrupted_mirror_file() {
        let server = MockServer::start_async().await;
        let did = "did:plc:restorecorrupt";
        let cid = blob_cid(b"the original");

        let dir = tempfile::tempdir().unwrap();
        // The file at the CID path no longer hashes to the CID (bitrot / tampering).
        write_blob(dir.path(), &cid, b"rotten bytes").await.unwrap();
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            did: did.to_string(),
            last_backup_at: None,
            entries: vec![ManifestEntry {
                cid: cid.clone(),
                mime_type: "image/png".to_string(),
                size: 12,
                fetched_at: "2026-07-20T00:00:00Z".to_string(),
            }],
        };
        save_manifest(dir.path(), did, &manifest).await.unwrap();

        let upload_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/xrpc/com.atproto.repo.uploadBlob");
                then.status(200)
                    .json_body(serde_json::json!({ "blob": {} }));
            })
            .await;

        let client =
            OAuthClient::new_bearer(make_bearer_jwt(), String::new(), server.base_url()).unwrap();
        let report = restore_core(&client, dir.path(), did).await.unwrap();

        assert_eq!(report.uploaded, 0);
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].reason.contains("corrupt"));
        // The corrupt bytes were never pushed to the PDS.
        assert_eq!(upload_mock.calls_async().await, 0);
    }

    #[tokio::test]
    async fn restore_continues_past_an_upload_refusal() {
        let server = MockServer::start_async().await;
        let did = "did:plc:restorerefusal";
        let blob_a = b"first".to_vec();
        let blob_b = b"second".to_vec();
        let cid_a = blob_cid(&blob_a);
        let cid_b = blob_cid(&blob_b);

        let dir = tempfile::tempdir().unwrap();
        write_blob(dir.path(), &cid_a, &blob_a).await.unwrap();
        write_blob(dir.path(), &cid_b, &blob_b).await.unwrap();
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            did: did.to_string(),
            last_backup_at: None,
            entries: vec![
                ManifestEntry {
                    cid: cid_a.clone(),
                    mime_type: "text/plain".to_string(),
                    size: blob_a.len() as u64,
                    fetched_at: "2026-07-20T00:00:00Z".to_string(),
                },
                ManifestEntry {
                    cid: cid_b.clone(),
                    mime_type: "text/plain".to_string(),
                    size: blob_b.len() as u64,
                    fetched_at: "2026-07-20T00:00:00Z".to_string(),
                },
            ],
        };
        save_manifest(dir.path(), did, &manifest).await.unwrap();

        // First upload is refused (e.g. over quota), second succeeds.
        server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.repo.uploadBlob")
                    .body(std::str::from_utf8(&blob_a).unwrap());
                then.status(400).json_body(
                    serde_json::json!({ "error": "BlobTooLarge", "message": "over quota" }),
                );
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/xrpc/com.atproto.repo.uploadBlob")
                    .body(std::str::from_utf8(&blob_b).unwrap());
                then.status(200)
                    .json_body(serde_json::json!({ "blob": {} }));
            })
            .await;

        let client =
            OAuthClient::new_bearer(make_bearer_jwt(), String::new(), server.base_url()).unwrap();
        let report = restore_core(&client, dir.path(), did).await.unwrap();

        assert_eq!(report.uploaded, 1);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].cid, cid_a);
        assert!(report.failed[0].reason.contains("over quota"));
    }

    // ── Status + opt-in ────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_reports_manifest_totals_and_flag() {
        crate::keychain::clear_for_test();
        let dir = tempfile::tempdir().unwrap();
        let did = "did:plc:statustest";

        let empty = status_core(Some(dir.path()), Some(BackupLocation::Local), did)
            .await
            .unwrap();
        assert!(!empty.enabled);
        assert_eq!(empty.backed_up_count, 0);
        assert_eq!(empty.backed_up_bytes, 0);
        assert!(empty.last_backup_at.is_none());

        let manifest = Manifest {
            version: MANIFEST_VERSION,
            did: did.to_string(),
            last_backup_at: Some("2026-07-20T00:00:00Z".to_string()),
            entries: vec![
                ManifestEntry {
                    cid: "bafkaaa".into(),
                    mime_type: "image/png".into(),
                    size: 100,
                    fetched_at: "2026-07-20T00:00:00Z".into(),
                },
                ManifestEntry {
                    cid: "bafkbbb".into(),
                    mime_type: "video/mp4".into(),
                    size: 900,
                    fetched_at: "2026-07-20T00:00:00Z".into(),
                },
            ],
        };
        save_manifest(dir.path(), did, &manifest).await.unwrap();
        store_enabled(did, true).unwrap();

        let status = status_core(Some(dir.path()), Some(BackupLocation::Local), did)
            .await
            .unwrap();
        assert!(status.enabled);
        assert_eq!(status.backed_up_count, 2);
        assert_eq!(status.backed_up_bytes, 1000);
        assert_eq!(
            status.last_backup_at.as_deref(),
            Some("2026-07-20T00:00:00Z")
        );

        // No location at all (iOS with iCloud off): totals are zero, not an error.
        let unavailable = status_core(None, None, did).await.unwrap();
        assert!(unavailable.location.is_none());
        assert_eq!(unavailable.backed_up_count, 0);
    }

    #[test]
    fn enabled_flag_roundtrip() {
        crate::keychain::clear_for_test();
        let did = "did:plc:flagtest";
        assert!(!load_enabled(did));
        store_enabled(did, true).unwrap();
        assert!(load_enabled(did));
        store_enabled(did, false).unwrap();
        assert!(!load_enabled(did));
    }
}
