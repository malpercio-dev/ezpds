// pattern: Mixed (Functional Core CAR-validation + error mapping; Imperative Shell commands)
//
// User-held repo backup: a full-CAR snapshot of the account's ATProto repository (its
// signed commit + Merkle Search Tree + record blocks — every post, like, follow, and
// profile edit) mirrored into the wallet's iCloud Drive ubiquity container, the sibling of
// `blob_backup.rs`. The repo is otherwise the one account asset held ONLY on the PDS; this
// closes the last self-custody gap. A CAR *is* the portable, importable artifact
// (`com.atproto.repo.importRepo` / the migration `transfer_repo` leg consume exactly these
// bytes), so there is nothing to "generate" for a new provider — the file is the export.
//
// Four Tauri IPC commands + one `pub(crate)` migration helper:
//
//   get_repo_backup_status(did)          — location + opt-in flag + snapshot size/rev
//   set_repo_backup_enabled(did, bool)   — the explicit opt-in toggle
//   run_repo_backup(did)                 — discover PDS → getRepo → VALIDATE → atomic write
//   export_repo_backup(did)              — read + re-validate the stored CAR; hand out bytes
//   mirror_repo_car(root, did)           — the transfer_repo iCloud-mirror fallback source
//
// The snapshot is fetched over the public, unauthenticated `com.atproto.sync.getRepo`
// (`auth: none`, no session — a genuine advantage over the blob restore path, which needs a
// full-access session). Before a fetched CAR is ever enshrined it is validated client-side —
// the wallet's twin of the defensive checks the destination PDS's `car_import` applies:
// well-formed framing, every block's bytes re-hash to its CID (content-addressed = trustless),
// exactly one root, the root decodes as a signed commit (version 3) bound to this DID, and the
// MST walks intact from the commit. A corrupt or hostile fetch is rejected as `CAR_INVALID`,
// leaving the prior good snapshot untouched. No encryption: the repo is public data on an
// `auth: none` endpoint, the same posture already accepted for the blob mirror.
//
// The mirror root, `BackupLocation`, and the `EZPDS_BLOB_BACKUP_DIR` override are REUSED from
// `blob_backup` — both features write under the same iCloud ubiquity container (blob uses
// `blobs/` + `manifests/`; repo uses `repo/{sanitized-did}.{car,json}`), so there is no new
// entitlement and the "iCloud off on a real device = unavailable, never a silent local
// fallback" contract holds identically.

use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cid::{Cid, Version};
use ipld_core::ipld::Ipld;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blob_backup::{resolve_backup_root, sanitize_did, BackupLocation};
use crate::pds_client::{PdsClient, PdsClientError};

/// Manifest schema version (bump on breaking layout changes).
const MANIFEST_VERSION: u32 = 1;

// ── CAR / IPLD constants ─────────────────────────────────────────────────────

/// The `dag-cbor` multicodec — every commit, MST node, and record block in a repo CAR.
const DAG_CBOR: u64 = 0x71;
/// The `raw` multicodec. A repo CAR is all dag-cbor, but `raw` is tolerated for extra
/// unreachable leaf blocks so a valid CAR isn't failed for the wrong reason.
const RAW: u64 = 0x55;
/// The SHA2-256 multihash code; ATProto block CIDs use it exclusively.
const SHA2_256: u64 = 0x12;
/// SHA2-256 digests are always 32 bytes.
const SHA2_256_DIGEST_LEN: u8 = 32;
/// The fixed repo-format version every ATProto commit carries.
const REPO_VERSION: i128 = 3;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the repo-backup commands.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", ... }` to match the sibling wallet error
/// enums (`BlobBackupError`, `HandleChangeError`, `SessionError`). Note there is deliberately
/// **no `SESSION_LOCKED`** variant: backup reads a public endpoint and export reads local disk,
/// so neither path needs a full-access session.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(
    tag = "code",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum RepoBackupError {
    /// No backup location is available on this device (iOS with iCloud Drive off — the mirror
    /// must not silently land somewhere that doesn't survive the device).
    #[error("no backup location is available (is iCloud Drive enabled?)")]
    BackupUnavailable,
    /// The hosting PDS or plc.directory rate limited the request.
    #[error("rate limited")]
    RateLimited { retry_after: Option<String> },
    /// The DID is not registered in this wallet / not found in the PLC directory.
    #[error("identity not found: {message}")]
    IdentityNotFound { message: String },
    /// A plc.directory read failed with an HTTP verdict (the hosting-PDS discovery).
    #[error("PLC directory error: {message}")]
    PlcDirectoryError { message: String },
    /// A server-side step failed for a non-connectivity reason (an XRPC refusal or a malformed
    /// response).
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
    /// The backup manifest exists but could not be read or parsed. Fail-closed: the file is
    /// preserved (it records the snapshot's rev/rootCid), never rebuilt over blindly.
    #[error("backup manifest is corrupt: {message}")]
    ManifestCorrupt { message: String },
    /// The fetched (or stored) CAR failed validation — bad framing, a block that doesn't hash to
    /// its CID, not exactly one root, a commit that isn't version 3 / is bound to another DID /
    /// is unsigned, or a broken MST walk. The prior good snapshot (if any) is left in place.
    #[error("repo snapshot failed validation: {message}")]
    CarInvalid { message: String },
    /// The opt-in flag could not be read from / written to the Keychain.
    #[error("keychain error: {message}")]
    KeychainError { message: String },
}

/// Map a plc.directory / PDS read failure into the repo-backup surface: a throttle is retryable
/// (`RateLimited`), an HTTP verdict names the server's reason, and only a transport failure is
/// `NetworkError` (mirrors `blob_backup::map_fetch_error`, minus the session variants).
fn map_fetch_error(context: &str, error: PdsClientError) -> RepoBackupError {
    match error {
        PdsClientError::RateLimited { retry_after, .. } => {
            RepoBackupError::RateLimited { retry_after }
        }
        PdsClientError::DidNotFound => RepoBackupError::PlcDirectoryError {
            message: format!("{context}: DID not found in the PLC directory"),
        },
        PdsClientError::XrpcError {
            status, message, ..
        } => RepoBackupError::ServerError {
            status: Some(status),
            message: format!("{context}: {message}"),
        },
        PdsClientError::Unauthorized { message, .. } => RepoBackupError::ServerError {
            status: Some(401),
            message: format!("{context}: {message}"),
        },
        PdsClientError::InvalidResponse { message } => RepoBackupError::ServerError {
            status: None,
            message: format!("{context}: {message}"),
        },
        other => RepoBackupError::NetworkError {
            message: format!("{context}: {other}"),
        },
    }
}

fn storage_error(context: &str, e: std::io::Error) -> RepoBackupError {
    RepoBackupError::StorageError {
        message: format!("{context}: {e}"),
    }
}

// ── Types ────────────────────────────────────────────────────────────────────

/// The per-DID repo-backup manifest, stored beside the CAR as `repo/{sanitized-did}.json`.
/// A repo is one artifact (not a set of content-addressed files), so unlike the blob manifest
/// there is no entry list — just the snapshot's identity and size.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepoManifest {
    version: u32,
    did: String,
    /// The backed-up commit's root CID (base32 CIDv1 string).
    root_cid: String,
    /// The repo revision (TID) at snapshot time — drives the "unchanged rev" short-circuit.
    rev: String,
    /// The CAR length on disk.
    size_bytes: u64,
    /// When the last backup pass completed (RFC 3339), or `None` if never.
    #[serde(default)]
    last_backup_at: Option<String>,
}

/// The status readout backing the "Back up your posts" surface.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoBackupStatus {
    /// The user's explicit opt-in flag (drives the opportunistic pass on app open).
    pub enabled: bool,
    /// Where the mirror lives, or `None` when no location is available (iCloud off).
    pub location: Option<BackupLocation>,
    /// The backed-up commit root CID, or `None` if never backed up.
    pub root_cid: Option<String>,
    /// The backed-up repo revision, or `None` if never backed up.
    pub rev: Option<String>,
    /// The snapshot size on disk (always shown — iCloud's free tier is a shared 5 GB, and a
    /// snapshot over `importRepo`'s 100 MiB cap is a known limit for extreme accounts).
    pub size_bytes: u64,
    /// When the last backup pass completed (RFC 3339), if ever.
    pub last_backup_at: Option<String>,
}

/// Report from one backup pass.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoBackupRunReport {
    pub root_cid: String,
    pub rev: String,
    pub size_bytes: u64,
    /// `false` when the fetched `rev` matched the stored snapshot and the CAR was not rewritten
    /// (the idempotent no-op re-backup); the manifest timestamp still advances.
    pub updated: bool,
    pub last_backup_at: String,
}

/// The validated, re-exported snapshot handed to a caller for import (diagnostics, a future
/// disaster-recovery flow, or an "export my repo to a file" affordance). The CAR is base64 so it
/// crosses the IPC boundary as a compact string rather than a multi-MB JSON number array.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoExport {
    pub root_cid: String,
    pub rev: String,
    pub size_bytes: u64,
    pub last_backup_at: Option<String>,
    /// The full CARv1 snapshot, base64 (standard alphabet) encoded.
    pub car_base64: String,
}

// ── CAR validation (Functional Core) ─────────────────────────────────────────

/// The identity extracted from a validated CAR — the manifest's `rootCid` + `rev`.
#[derive(Debug)]
struct ValidatedCar {
    root_cid: String,
    rev: String,
}

/// Parse and validate a repository CAR for `expected_did`, the client-side twin of the
/// destination PDS's `car_import` checks. Applied to every fetched (and stored) CAR before it is
/// trusted, so a corrupt or hostile snapshot is never enshrined as the recovery copy.
///
/// Validation performed:
/// * the CAR's framing is structurally sound — the header and every block frame's declared length
///   fits the remaining input (a shorter-than-its-CID frame would underflow, a giant declared
///   length would drive an attacker-sized allocation), every block CID is CIDv1 (dag-cbor or raw)
///   with a 32-byte SHA2-256 multihash, and **every block's bytes hash to its CID** (the trustless
///   content-addressing property);
/// * the CAR declares exactly one root;
/// * the root block decodes as a **signed commit** (version 3, a `sig` field) whose `did` matches
///   `expected_did`;
/// * the **MST walks intact** from the commit's `data` link — every MST node and every record
///   block it references is present. The walk follows subtree + record-value links but deliberately
///   does NOT descend into record bodies: records legitimately link to blob CIDs that live outside
///   the repo CAR (blobs are backed up separately), so following them would reject any account with
///   media. This is the same reachable set the destination PDS's `export_into` traverses, without
///   depending on repo-engine or reimplementing MST *construction*.
fn validate_repo_car(
    car_bytes: &[u8],
    expected_did: &str,
) -> Result<ValidatedCar, RepoBackupError> {
    let invalid = |msg: String| RepoBackupError::CarInvalid { message: msg };

    // ── Header: length-prefixed dag-cbor `{ roots: [Cid], version: 1 }`. ──
    let (header_len, rest) = decode_varint(car_bytes)
        .ok_or_else(|| invalid("malformed CAR header length varint".to_string()))?;
    let header_len = usize::try_from(header_len)
        .map_err(|_| invalid("CAR header length overflows usize".to_string()))?;
    if header_len > rest.len() {
        return Err(invalid(
            "declared CAR header length exceeds input".to_string(),
        ));
    }
    let (header_bytes, mut rest) = rest.split_at(header_len);
    let header: Ipld = serde_ipld_dagcbor::from_slice(header_bytes)
        .map_err(|e| invalid(format!("CAR header is not dag-cbor: {e}")))?;
    let roots = match header {
        Ipld::Map(map) => match map.get("roots") {
            Some(Ipld::List(list)) => list
                .iter()
                .map(|item| match item {
                    Ipld::Link(cid) => Ok(*cid),
                    _ => Err(invalid("CAR root is not a CID link".to_string())),
                })
                .collect::<Result<Vec<Cid>, _>>()?,
            _ => return Err(invalid("CAR header has no roots array".to_string())),
        },
        _ => return Err(invalid("CAR header is not a map".to_string())),
    };
    if roots.len() != 1 {
        return Err(invalid(format!(
            "CAR must declare exactly one root, found {}",
            roots.len()
        )));
    }
    let root = roots[0];

    // ── Blocks: verify framing + hash every block into a content-addressed set. ──
    let mut blocks: HashMap<Cid, Vec<u8>> = HashMap::new();
    while !rest.is_empty() {
        let (frame_len, after) = decode_varint(rest)
            .ok_or_else(|| invalid("malformed CAR block frame length varint".to_string()))?;
        let frame_len = usize::try_from(frame_len)
            .map_err(|_| invalid("CAR block frame length overflows usize".to_string()))?;
        if frame_len > after.len() {
            return Err(invalid(
                "declared CAR block frame length exceeds remaining input".to_string(),
            ));
        }
        let (frame, next) = after.split_at(frame_len);

        // The CID must parse *within its frame* — reading it from the unbounded stream is exactly
        // how a short frame underflows its data length.
        let mut cid_reader = Cursor::new(frame);
        let cid = Cid::read_bytes(&mut cid_reader)
            .map_err(|e| invalid(format!("CAR block frame has an invalid CID: {e}")))?;
        let data = &frame[cid_reader.position() as usize..];

        if cid.version() != Version::V1 {
            return Err(invalid("CAR block CID is not CIDv1".to_string()));
        }
        if cid.codec() != DAG_CBOR && cid.codec() != RAW {
            return Err(invalid(
                "CAR block CID has an unsupported codec".to_string(),
            ));
        }
        if cid.hash().code() != SHA2_256 || cid.hash().size() != SHA2_256_DIGEST_LEN {
            return Err(invalid(
                "CAR block CID has an unsupported multihash (must be SHA2-256)".to_string(),
            ));
        }
        if cid.hash().digest() != Sha256::digest(data).as_slice() {
            return Err(invalid(
                "CAR block bytes do not hash to the block CID".to_string(),
            ));
        }

        blocks.insert(cid, data.to_vec());
        rest = next;
    }

    // ── Root commit: present, signed, version 3, bound to this DID. ──
    let root_bytes = blocks
        .get(&root)
        .ok_or_else(|| invalid("root commit block is absent from the CAR".to_string()))?;
    let commit: Ipld = serde_ipld_dagcbor::from_slice(root_bytes)
        .map_err(|e| invalid(format!("root commit is not dag-cbor: {e}")))?;
    let Ipld::Map(commit) = commit else {
        return Err(invalid("root commit is not a map".to_string()));
    };
    match commit.get("version") {
        Some(Ipld::Integer(v)) if *v == REPO_VERSION => {}
        _ => {
            return Err(invalid(
                "commit has an unsupported or missing version".to_string(),
            ))
        }
    }
    match commit.get("did") {
        Some(Ipld::String(did)) if did == expected_did => {}
        Some(Ipld::String(did)) => {
            return Err(invalid(format!(
                "commit is bound to DID {did}, expected {expected_did}"
            )))
        }
        _ => return Err(invalid("commit is missing a did field".to_string())),
    }
    // A signed commit carries a `sig`; content addressing binds the bytes to the root CID, so the
    // presence of the signature is what makes the snapshot a genuine commit (full cryptographic
    // verification would need the DID's signing key resolved from plc.directory — out of scope for
    // a self-verifying content-addressed snapshot, exactly as `car_import` treats it).
    if !matches!(commit.get("sig"), Some(Ipld::Bytes(_))) {
        return Err(invalid(
            "commit is not signed (missing sig field)".to_string(),
        ));
    }
    let rev = match commit.get("rev") {
        Some(Ipld::String(rev)) => rev.clone(),
        _ => return Err(invalid("commit is missing a rev field".to_string())),
    };
    let data_cid = match commit.get("data") {
        Some(Ipld::Link(cid)) => *cid,
        _ => {
            return Err(invalid(
                "commit is missing a data (MST root) link".to_string(),
            ))
        }
    };

    // ── MST walk: every node + record block reachable from the commit is present. ──
    walk_mst(&blocks, data_cid).map_err(invalid)?;

    Ok(ValidatedCar {
        root_cid: root.to_string(),
        rev,
    })
}

/// Walk the MST from its root, asserting every node and every referenced record block is present
/// in `blocks`. Follows the left subtree (`l`) and each entry's right subtree (`t`) recursively;
/// asserts each entry's value (`v`, a record block) is present but does NOT decode/descend into it
/// — records link to out-of-CAR blobs. Returns the offending block's description on the first gap.
fn walk_mst(blocks: &HashMap<Cid, Vec<u8>>, mst_root: Cid) -> Result<(), String> {
    let mut queue = vec![mst_root];
    let mut seen: HashSet<Cid> = HashSet::new();
    while let Some(cid) = queue.pop() {
        if !seen.insert(cid) {
            continue;
        }
        let bytes = blocks
            .get(&cid)
            .ok_or_else(|| format!("MST node {cid} is missing from the CAR"))?;
        let node: Ipld = serde_ipld_dagcbor::from_slice(bytes)
            .map_err(|e| format!("MST node {cid} is not dag-cbor: {e}"))?;
        let Ipld::Map(node) = node else {
            return Err(format!("MST node {cid} is not a map"));
        };
        // Left-most subtree (`null`/absent on a leaf-level node → skipped).
        if let Some(Ipld::Link(left)) = node.get("l") {
            queue.push(*left);
        }
        let entries = match node.get("e") {
            Some(Ipld::List(entries)) => entries,
            _ => return Err(format!("MST node {cid} has no entries array")),
        };
        for entry in entries {
            let Ipld::Map(entry) = entry else {
                return Err(format!("MST node {cid} has a non-map entry"));
            };
            match entry.get("v") {
                Some(Ipld::Link(value)) => {
                    if !blocks.contains_key(value) {
                        return Err(format!(
                            "record block {value} referenced by the MST is missing from the CAR"
                        ));
                    }
                }
                _ => return Err(format!("an MST entry in {cid} has no value link")),
            }
            // Right subtree of this entry (`null`/absent → skipped).
            if let Some(Ipld::Link(right)) = entry.get("t") {
                queue.push(*right);
            }
        }
    }
    Ok(())
}

/// Decode an unsigned LEB128 varint from the front of `input`, returning the value and the
/// remaining bytes. `None` on truncated input or a value overflowing u64 (ported from
/// `repo-engine`'s `car_import::decode_varint`).
fn decode_varint(input: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    for (i, &byte) in input.iter().enumerate() {
        let bits = u64::from(byte & 0x7f);
        let shift = 7 * i as u32;
        if shift >= 64 || (shift == 63 && bits > 1) {
            return None;
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Some((value, &input[i + 1..]));
        }
    }
    None
}

// ── Mirror layout + manifest I/O ─────────────────────────────────────────────

fn repo_dir(root: &Path) -> PathBuf {
    root.join("repo")
}

fn car_path(root: &Path, did: &str) -> PathBuf {
    repo_dir(root).join(format!("{}.car", sanitize_did(did)))
}

fn manifest_path(root: &Path, did: &str) -> PathBuf {
    repo_dir(root).join(format!("{}.json", sanitize_did(did)))
}

/// Load the DID's manifest. An absent file is `None` (never backed up); a present-but-unreadable
/// one is `ManifestCorrupt` and the file is preserved (fail-closed, never rebuilt over blindly).
async fn load_manifest(root: &Path, did: &str) -> Result<Option<RepoManifest>, RepoBackupError> {
    let path = manifest_path(root, did);
    let raw = match tokio::fs::read(&path).await {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(storage_error("failed to read repo backup manifest", e)),
    };
    serde_json::from_slice::<RepoManifest>(&raw)
        .map(Some)
        .map_err(|e| RepoBackupError::ManifestCorrupt {
            message: e.to_string(),
        })
}

/// Persist the manifest atomically (temp file + rename in the same directory).
async fn save_manifest(
    root: &Path,
    did: &str,
    manifest: &RepoManifest,
) -> Result<(), RepoBackupError> {
    let dir = repo_dir(root);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| storage_error("failed to create repo backup directory", e))?;
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| RepoBackupError::StorageError {
        message: format!("failed to encode repo backup manifest: {e}"),
    })?;
    let tmp = dir.join(format!(".tmp-manifest-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, &json)
        .await
        .map_err(|e| storage_error("failed to write repo backup manifest", e))?;
    tokio::fs::rename(&tmp, manifest_path(root, did))
        .await
        .map_err(|e| storage_error("failed to finalize repo backup manifest", e))
}

/// Write the validated CAR atomically (temp file + rename), so a crash never leaves a truncated
/// snapshot at the canonical path — the prior good snapshot survives an interrupted write.
async fn write_car(root: &Path, did: &str, bytes: &[u8]) -> Result<(), RepoBackupError> {
    let dir = repo_dir(root);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| storage_error("failed to create repo backup directory", e))?;
    let tmp = dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| storage_error("failed to write repo snapshot", e))?;
    tokio::fs::rename(&tmp, car_path(root, did))
        .await
        .map_err(|e| storage_error("failed to finalize repo snapshot", e))
}

// ── Opt-in flag ──────────────────────────────────────────────────────────────

/// Per-DID Keychain account holding the opt-in flag (`"true"` / `"false"`).
/// Referenced by `IdentityStore::remove_identity` for cleanup.
pub(crate) fn backup_enabled_account(did: &str) -> String {
    format!("{did}:repo-backup-enabled")
}

fn load_enabled(did: &str) -> bool {
    crate::keychain::get_item(&backup_enabled_account(did))
        .map(|v| v == b"true")
        .unwrap_or(false)
}

fn store_enabled(did: &str, enabled: bool) -> Result<(), RepoBackupError> {
    let value: &[u8] = if enabled { b"true" } else { b"false" };
    crate::keychain::store_item(&backup_enabled_account(did), value).map_err(|e| {
        RepoBackupError::KeychainError {
            message: e.to_string(),
        }
    })
}

// ── Per-DID lock ─────────────────────────────────────────────────────────────

/// Per-DID snapshot lock. The CAR + manifest are a read-modify-write pair, and two passes can
/// overlap for one DID (the opportunistic app-open pass racing a manual "Back up now", or an
/// export reading mid-backup) — serialize them so a reader never sees a half-written snapshot.
/// Process-global registry, the same shape as `blob_backup::mirror_lock`.
fn repo_lock(did: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let registry = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = registry.lock().expect("repo lock registry poisoned");
    map.entry(did.to_string()).or_default().clone()
}

// ── Cores (testable without Tauri) ───────────────────────────────────────────

/// Build the status readout from the manifest on disk.
async fn status_core(
    root: Option<&Path>,
    location: Option<BackupLocation>,
    did: &str,
) -> Result<RepoBackupStatus, RepoBackupError> {
    let manifest = match root {
        Some(root) => load_manifest(root, did).await?,
        None => None,
    };
    let (root_cid, rev, size_bytes, last_backup_at) = match manifest {
        Some(m) => (
            Some(m.root_cid),
            Some(m.rev),
            m.size_bytes,
            m.last_backup_at,
        ),
        None => (None, None, 0, None),
    };
    Ok(RepoBackupStatus {
        enabled: load_enabled(did),
        location,
        root_cid,
        rev,
        size_bytes,
        last_backup_at,
    })
}

/// One backup pass: fetch the full CAR over public `getRepo`, validate it, and atomically replace
/// the snapshot + manifest. Idempotent: when the fetched `rev` matches the stored snapshot and the
/// CAR file is still present, the (multi-MB) CAR rewrite is skipped and only the manifest timestamp
/// advances (`updated: false`). A CAR that fails validation is rejected as `CAR_INVALID` before any
/// write, leaving the prior good snapshot intact.
pub(crate) async fn run_backup_core(
    pds_client: &PdsClient,
    root: &Path,
    did: &str,
    pds_url: &str,
) -> Result<RepoBackupRunReport, RepoBackupError> {
    let lock = repo_lock(did);
    let _guard = lock.lock().await;

    let car = pds_client
        .fetch_repo_car(pds_url, did)
        .await
        .map_err(|e| map_fetch_error("failed to fetch repo snapshot", e))?;
    let validated = validate_repo_car(&car, did)?;

    let existing = load_manifest(root, did).await?;
    let car_present = tokio::fs::try_exists(car_path(root, did))
        .await
        .unwrap_or(false);
    let unchanged = car_present && existing.as_ref().is_some_and(|m| m.rev == validated.rev);

    let size_bytes = car.len() as u64;
    let now = chrono::Utc::now().to_rfc3339();

    if !unchanged {
        write_car(root, did, &car).await?;
    }
    let manifest = RepoManifest {
        version: MANIFEST_VERSION,
        did: did.to_string(),
        root_cid: validated.root_cid.clone(),
        rev: validated.rev.clone(),
        size_bytes,
        last_backup_at: Some(now.clone()),
    };
    save_manifest(root, did, &manifest).await?;

    Ok(RepoBackupRunReport {
        root_cid: validated.root_cid,
        rev: validated.rev,
        size_bytes,
        updated: !unchanged,
        last_backup_at: now,
    })
}

/// Read the stored CAR, **re-validate** it, and return its bytes (base64) + manifest metadata for a
/// caller to import. Re-validation guarantees a caller never imports a snapshot that rotted on disk.
async fn export_core(root: &Path, did: &str) -> Result<RepoExport, RepoBackupError> {
    let lock = repo_lock(did);
    let _guard = lock.lock().await;

    let manifest =
        load_manifest(root, did)
            .await?
            .ok_or_else(|| RepoBackupError::StorageError {
                message: "no repo snapshot has been backed up for this identity yet".to_string(),
            })?;
    let bytes = match tokio::fs::read(car_path(root, did)).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RepoBackupError::StorageError {
                message: "the repo snapshot file is missing — run a backup again".to_string(),
            })
        }
        Err(e) => return Err(storage_error("failed to read repo snapshot", e)),
    };
    let validated = validate_repo_car(&bytes, did)?;
    Ok(RepoExport {
        root_cid: validated.root_cid,
        rev: validated.rev,
        size_bytes: bytes.len() as u64,
        last_backup_at: manifest.last_backup_at,
        car_base64: BASE64.encode(&bytes),
    })
}

/// Migration-transfer fallback: read the DID's snapshot from the local mirror when the source PDS
/// can't serve `getRepo`, but only if it is trustworthy. The CAR must be locally readable and must
/// re-validate against `did` (single root, signed commit bound to the DID, intact MST, every block
/// hashing to its CID). Returns `None` — never an error — whenever the mirror can't supply a valid
/// snapshot (no file, an undownloaded iCloud placeholder, an I/O failure, or a validation failure),
/// so the migration simply surfaces the original source failure unchanged. Content addressing makes
/// the substitution trustless: the validated bytes are byte-identical to what the source PDS would
/// have served, so the destination `importRepo` accepts them and the commit is preserved verbatim.
/// The repo twin of `blob_backup::mirror_fallback_blob`; consumed by the migration orchestrator's
/// `transfer_repo` fallback wiring (added in a follow-on change).
// Exercised by this module's tests; the production consumer (the migration orchestrator's
// `transfer_repo` fallback) lands in a follow-on change, so the non-test lib build sees it as unused.
#[allow(dead_code)]
pub(crate) async fn mirror_repo_car(root: &Path, did: &str) -> Option<Vec<u8>> {
    let lock = repo_lock(did);
    let _guard = lock.lock().await;

    let bytes = match tokio::fs::read(car_path(root, did)).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::info!(did = %did, error = %e, "repo transfer: local mirror has no usable snapshot");
            return None;
        }
    };
    match validate_repo_car(&bytes, did) {
        Ok(_) => {
            tracing::info!(did = %did, "repo transfer: recovered the repo snapshot from the local mirror after a source getRepo failure");
            Some(bytes)
        }
        Err(e) => {
            tracing::error!(did = %did, error = %e, "repo transfer: mirrored snapshot failed validation; not using as fallback");
            None
        }
    }
}

// ── Tauri commands ───────────────────────────────────────────────────────────

/// Discover the DID's current hosting PDS endpoint via plc.directory.
async fn hosting_pds_url(pds_client: &PdsClient, did: &str) -> Result<String, RepoBackupError> {
    let (pds_url, _doc) = pds_client
        .discover_pds(did)
        .await
        .map_err(|e| map_fetch_error("failed to discover hosting PDS", e))?;
    Ok(pds_url)
}

/// One backup pass for `did`, resolving the mirror root, hosting PDS, and shared `PdsClient` from
/// the app handle. Shared body of the `run_repo_backup` command (and, later, a background
/// backup sweep): resolve root → discover PDS → fetch + validate + write. Reads only the public
/// `getRepo`, so it needs no session.
pub(crate) async fn run_backup_for_did(
    app: &tauri::AppHandle,
    did: &str,
) -> Result<RepoBackupRunReport, RepoBackupError> {
    use tauri::Manager;
    let (root, _location) = resolve_backup_root(app).ok_or(RepoBackupError::BackupUnavailable)?;
    let state = app.state::<crate::oauth::AppState>();
    let pds_client = state.pds_client();
    let pds_url = hosting_pds_url(pds_client, did).await?;
    run_backup_core(pds_client, &root, did, &pds_url).await
}

/// Tauri command: the backup surface's status readout — mirror location (or its absence), the
/// opt-in flag, and the snapshot's size + rev (shown before and after opting in).
#[tauri::command]
pub async fn get_repo_backup_status(
    app: tauri::AppHandle,
    did: String,
) -> Result<RepoBackupStatus, RepoBackupError> {
    match resolve_backup_root(&app) {
        Some((root, location)) => status_core(Some(&root), Some(location), &did).await,
        None => status_core(None, None, &did).await,
    }
}

/// Tauri command: flip the explicit opt-in flag. Returns the refreshed status.
#[tauri::command]
pub async fn set_repo_backup_enabled(
    app: tauri::AppHandle,
    did: String,
    enabled: bool,
) -> Result<RepoBackupStatus, RepoBackupError> {
    store_enabled(&did, enabled)?;
    get_repo_backup_status(app, did).await
}

/// Tauri command: run one backup pass for the identity. Reads only the public `getRepo`, so it
/// needs no session. Also invoked opportunistically (fire-and-forget) on app open for opted-in
/// identities.
#[tauri::command]
pub async fn run_repo_backup(
    app: tauri::AppHandle,
    did: String,
) -> Result<RepoBackupRunReport, RepoBackupError> {
    run_backup_for_did(&app, &did).await
}

/// Tauri command: read + re-validate the stored snapshot and return its bytes (base64) + metadata
/// for a caller to import. Reads local disk only — no session, no network.
#[tauri::command]
pub async fn export_repo_backup(
    app: tauri::AppHandle,
    did: String,
) -> Result<RepoExport, RepoBackupError> {
    let (root, _location) = resolve_backup_root(&app).ok_or(RepoBackupError::BackupUnavailable)?;
    export_core(&root, &did).await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use httpmock::prelude::*;
    use multihash::Multihash;

    // ── CAR construction helpers (build valid + deliberately-broken repo CARs by hand) ──

    fn block_cid(codec: u64, bytes: &[u8]) -> Cid {
        let mh = Multihash::<64>::wrap(SHA2_256, Sha256::digest(bytes).as_slice()).unwrap();
        Cid::new_v1(codec, mh)
    }

    fn dagcbor(ipld: &Ipld) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(ipld).unwrap()
    }

    /// Encode a u64 as an unsigned LEB128 varint (test-side mirror of `decode_varint`).
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// An MST node: optional left subtree + entries of `(key, value-CID, optional right subtree)`.
    fn mst_node(left: Option<Cid>, entries: Vec<(&[u8], Cid, Option<Cid>)>) -> Ipld {
        let mut node = BTreeMap::new();
        node.insert("l".to_string(), left.map(Ipld::Link).unwrap_or(Ipld::Null));
        let e = entries
            .into_iter()
            .map(|(key, value, right)| {
                let mut entry = BTreeMap::new();
                entry.insert("p".to_string(), Ipld::Integer(0));
                entry.insert("k".to_string(), Ipld::Bytes(key.to_vec()));
                entry.insert("v".to_string(), Ipld::Link(value));
                entry.insert("t".to_string(), right.map(Ipld::Link).unwrap_or(Ipld::Null));
                Ipld::Map(entry)
            })
            .collect();
        node.insert("e".to_string(), Ipld::List(e));
        Ipld::Map(node)
    }

    fn commit(did: &str, data: Cid, rev: &str) -> Ipld {
        let mut c = BTreeMap::new();
        c.insert("did".to_string(), Ipld::String(did.to_string()));
        c.insert("version".to_string(), Ipld::Integer(REPO_VERSION));
        c.insert("data".to_string(), Ipld::Link(data));
        c.insert("rev".to_string(), Ipld::String(rev.to_string()));
        c.insert("prev".to_string(), Ipld::Null);
        c.insert("sig".to_string(), Ipld::Bytes(vec![0u8; 64]));
        Ipld::Map(c)
    }

    fn build_car(roots: &[Cid], blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
        let mut header = BTreeMap::new();
        header.insert(
            "roots".to_string(),
            Ipld::List(roots.iter().map(|c| Ipld::Link(*c)).collect()),
        );
        header.insert("version".to_string(), Ipld::Integer(1));
        let header_bytes = dagcbor(&Ipld::Map(header));

        let mut out = varint(header_bytes.len() as u64);
        out.extend_from_slice(&header_bytes);
        for (cid, data) in blocks {
            let cid_bytes = cid.to_bytes();
            out.extend_from_slice(&varint((cid_bytes.len() + data.len()) as u64));
            out.extend_from_slice(&cid_bytes);
            out.extend_from_slice(data);
        }
        out
    }

    /// A valid empty-repo CAR (commit → empty MST node). Returns `(car, root_cid_string, rev)`.
    fn valid_empty_repo(did: &str, rev: &str) -> (Vec<u8>, String, String) {
        let mst_bytes = dagcbor(&mst_node(None, vec![]));
        let mst_cid = block_cid(DAG_CBOR, &mst_bytes);
        let commit_bytes = dagcbor(&commit(did, mst_cid, rev));
        let commit_cid = block_cid(DAG_CBOR, &commit_bytes);
        let car = build_car(
            &[commit_cid],
            &[(commit_cid, commit_bytes), (mst_cid, mst_bytes)],
        );
        (car, commit_cid.to_string(), rev.to_string())
    }

    /// A valid repo whose single record embeds a blob ref (a CID intentionally NOT in the CAR) —
    /// proves validation walks the MST but does not follow record→blob links.
    fn valid_repo_with_record_and_blob_ref(did: &str, rev: &str) -> Vec<u8> {
        // An out-of-CAR blob CID (raw codec, as blob CIDs are).
        let blob_cid = block_cid(RAW, b"blob bytes that live outside the repo CAR");
        let mut embed = BTreeMap::new();
        embed.insert("$type".to_string(), Ipld::String("blob".to_string()));
        embed.insert("ref".to_string(), Ipld::Link(blob_cid));
        embed.insert(
            "mimeType".to_string(),
            Ipld::String("image/png".to_string()),
        );
        embed.insert("size".to_string(), Ipld::Integer(42));
        let mut record = BTreeMap::new();
        record.insert(
            "$type".to_string(),
            Ipld::String("app.bsky.feed.post".to_string()),
        );
        record.insert("text".to_string(), Ipld::String("hello".to_string()));
        record.insert("image".to_string(), Ipld::Map(embed));
        let record_bytes = dagcbor(&Ipld::Map(record));
        let record_cid = block_cid(DAG_CBOR, &record_bytes);

        let mst_bytes = dagcbor(&mst_node(
            None,
            vec![(b"app.bsky.feed.post/a", record_cid, None)],
        ));
        let mst_cid = block_cid(DAG_CBOR, &mst_bytes);
        let commit_bytes = dagcbor(&commit(did, mst_cid, rev));
        let commit_cid = block_cid(DAG_CBOR, &commit_bytes);
        // blob_cid is deliberately absent from the block set.
        build_car(
            &[commit_cid],
            &[
                (commit_cid, commit_bytes),
                (mst_cid, mst_bytes),
                (record_cid, record_bytes),
            ],
        )
    }

    // ── Validation ──────────────────────────────────────────────────────────

    #[test]
    fn validates_an_empty_repo_and_extracts_root_and_rev() {
        let (car, root, rev) = valid_empty_repo("did:plc:repotest", "3laaaaaaaa2az");
        let validated = validate_repo_car(&car, "did:plc:repotest").unwrap();
        assert_eq!(validated.root_cid, root);
        assert_eq!(validated.rev, rev);
    }

    #[test]
    fn validates_a_repo_whose_record_links_an_absent_blob() {
        // The record embeds a blob CID that is NOT in the CAR (blobs are backed up separately);
        // validation must still pass because it does not follow record→blob links.
        let car = valid_repo_with_record_and_blob_ref("did:plc:media", "3lbbbbbbbb2az");
        validate_repo_car(&car, "did:plc:media").unwrap();
    }

    #[test]
    fn rejects_a_did_mismatch() {
        let (car, _, _) = valid_empty_repo("did:plc:realowner", "3lccccccc2az");
        let err = validate_repo_car(&car, "did:plc:someoneelse").unwrap_err();
        assert!(
            matches!(err, RepoBackupError::CarInvalid { ref message } if message.contains("expected did:plc:someoneelse"))
        );
    }

    #[test]
    fn rejects_a_broken_mst_walk() {
        // Commit references an MST root, but that node's block is omitted from the CAR.
        let rev = "3lddddddd2az";
        let mst_bytes = dagcbor(&mst_node(None, vec![]));
        let mst_cid = block_cid(DAG_CBOR, &mst_bytes);
        let commit_bytes = dagcbor(&commit("did:plc:dangling", mst_cid, rev));
        let commit_cid = block_cid(DAG_CBOR, &commit_bytes);
        // Only the commit block is present; the MST node is missing.
        let car = build_car(&[commit_cid], &[(commit_cid, commit_bytes)]);
        let err = validate_repo_car(&car, "did:plc:dangling").unwrap_err();
        assert!(
            matches!(err, RepoBackupError::CarInvalid { ref message } if message.contains("MST node") && message.contains("missing"))
        );
    }

    #[test]
    fn rejects_a_missing_record_block() {
        // The MST names a record value whose block is absent.
        let rev = "3leeeeeee2az";
        let ghost_record = block_cid(
            DAG_CBOR,
            &dagcbor(&Ipld::String("never stored".to_string())),
        );
        let mst_bytes = dagcbor(&mst_node(
            None,
            vec![(b"app.bsky.feed.post/x", ghost_record, None)],
        ));
        let mst_cid = block_cid(DAG_CBOR, &mst_bytes);
        let commit_bytes = dagcbor(&commit("did:plc:norecord", mst_cid, rev));
        let commit_cid = block_cid(DAG_CBOR, &commit_bytes);
        let car = build_car(
            &[commit_cid],
            &[(commit_cid, commit_bytes), (mst_cid, mst_bytes)],
        );
        let err = validate_repo_car(&car, "did:plc:norecord").unwrap_err();
        assert!(
            matches!(err, RepoBackupError::CarInvalid { ref message } if message.contains("record block") && message.contains("missing"))
        );
    }

    #[test]
    fn rejects_a_block_hash_mismatch() {
        let (mut car, _, _) = valid_empty_repo("did:plc:corrupt", "3lfffffff2az");
        // Append a frame whose CID (hash of "A") does not match its bytes ("B").
        let lying_cid = block_cid(DAG_CBOR, b"A");
        let cid_bytes = lying_cid.to_bytes();
        car.extend_from_slice(&varint((cid_bytes.len() + 1) as u64));
        car.extend_from_slice(&cid_bytes);
        car.push(b'B');
        let err = validate_repo_car(&car, "did:plc:corrupt").unwrap_err();
        assert!(
            matches!(err, RepoBackupError::CarInvalid { ref message } if message.contains("do not hash to the block CID"))
        );
    }

    #[test]
    fn rejects_more_than_one_root() {
        let (_, _, rev) = ("_", "_", "3lggggggg2az");
        let mst_bytes = dagcbor(&mst_node(None, vec![]));
        let mst_cid = block_cid(DAG_CBOR, &mst_bytes);
        let commit_bytes = dagcbor(&commit("did:plc:tworoots", mst_cid, rev));
        let commit_cid = block_cid(DAG_CBOR, &commit_bytes);
        // Two declared roots.
        let car = build_car(
            &[commit_cid, mst_cid],
            &[(commit_cid, commit_bytes), (mst_cid, mst_bytes)],
        );
        let err = validate_repo_car(&car, "did:plc:tworoots").unwrap_err();
        assert!(
            matches!(err, RepoBackupError::CarInvalid { ref message } if message.contains("exactly one root"))
        );
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = validate_repo_car(b"not a car at all", "did:plc:x").unwrap_err();
        assert!(matches!(err, RepoBackupError::CarInvalid { .. }));
    }

    // ── Error mapping / serialization ─────────────────────────────────────────

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
            matches!(throttled, RepoBackupError::RateLimited { retry_after: Some(ref s) } if s == "30")
        );

        let verdict = map_fetch_error(
            "ctx",
            PdsClientError::XrpcError {
                status: 503,
                error: None,
                message: "maintenance".into(),
            },
        );
        assert!(matches!(
            verdict,
            RepoBackupError::ServerError {
                status: Some(503),
                ..
            }
        ));

        let transport = map_fetch_error(
            "ctx",
            PdsClientError::NetworkError {
                message: "dns".into(),
            },
        );
        assert!(matches!(transport, RepoBackupError::NetworkError { .. }));
    }

    #[test]
    fn error_serialization_shape() {
        let json = serde_json::to_string(&RepoBackupError::BackupUnavailable).unwrap();
        assert!(json.contains(r#""code":"BACKUP_UNAVAILABLE""#));

        let json = serde_json::to_string(&RepoBackupError::CarInvalid {
            message: "bad".into(),
        })
        .unwrap();
        assert!(json.contains(r#""code":"CAR_INVALID""#));
        assert!(json.contains(r#""message":"bad""#));
    }

    // ── Backup pass (fetch → validate → write) ────────────────────────────────

    fn mock_get_repo(server: &MockServer, car: &[u8]) {
        server.mock(|when, then| {
            when.method(GET).path("/xrpc/com.atproto.sync.getRepo");
            then.status(200)
                .header("content-type", "application/vnd.ipld.car")
                .body(car);
        });
    }

    #[tokio::test]
    async fn backup_pass_fetches_validates_and_writes() {
        let did = "did:plc:backup";
        let (car, root, rev) = valid_empty_repo(did, "3lhhhhhhh2az");
        let server = MockServer::start_async().await;
        mock_get_repo(&server, &car);

        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        let report = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();

        assert_eq!(report.root_cid, root);
        assert_eq!(report.rev, rev);
        assert!(report.updated);
        assert_eq!(report.size_bytes, car.len() as u64);

        // The snapshot landed at its path, byte-for-byte.
        assert_eq!(
            tokio::fs::read(car_path(dir.path(), did)).await.unwrap(),
            car
        );
        // The manifest records the identity of the snapshot.
        let manifest = load_manifest(dir.path(), did).await.unwrap().unwrap();
        assert_eq!(manifest.root_cid, root);
        assert_eq!(manifest.rev, rev);
        assert!(manifest.last_backup_at.is_some());

        // Status surfaces it.
        let status = status_core(Some(dir.path()), Some(BackupLocation::Local), did)
            .await
            .unwrap();
        assert_eq!(status.root_cid.as_deref(), Some(root.as_str()));
        assert_eq!(status.size_bytes, car.len() as u64);
    }

    #[tokio::test]
    async fn re_backup_with_unchanged_rev_short_circuits_the_car_rewrite() {
        let did = "did:plc:idempotent";
        let (car, _, _) = valid_empty_repo(did, "3liiiiiii2az");
        let server = MockServer::start_async().await;
        mock_get_repo(&server, &car);

        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        let first = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert!(first.updated);

        // The CAR on disk is unchanged; a second pass with the same rev must not rewrite it, but
        // must still succeed and advance the manifest timestamp.
        let before = tokio::fs::metadata(car_path(dir.path(), did))
            .await
            .unwrap()
            .modified()
            .unwrap();
        let second = run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert!(!second.updated, "unchanged rev should short-circuit");
        assert_eq!(second.rev, first.rev);
        let after = tokio::fs::metadata(car_path(dir.path(), did))
            .await
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after, "the CAR file must not be rewritten");
    }

    #[tokio::test]
    async fn an_invalid_fetch_is_rejected_and_leaves_the_prior_snapshot_intact() {
        let did = "did:plc:guarded";
        let (good_car, good_root, _) = valid_empty_repo(did, "3ljjjjjjj2az");

        // First, a good backup.
        let good_server = MockServer::start_async().await;
        mock_get_repo(&good_server, &good_car);
        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        run_backup_core(&client, dir.path(), did, &good_server.base_url())
            .await
            .unwrap();

        // Now the PDS serves garbage. The pass must reject it as CAR_INVALID.
        let bad_server = MockServer::start_async().await;
        mock_get_repo(&bad_server, b"corrupt not-a-car bytes");
        let err = run_backup_core(&client, dir.path(), did, &bad_server.base_url())
            .await
            .unwrap_err();
        assert!(matches!(err, RepoBackupError::CarInvalid { .. }));

        // The prior good snapshot survives untouched.
        assert_eq!(
            tokio::fs::read(car_path(dir.path(), did)).await.unwrap(),
            good_car
        );
        let manifest = load_manifest(dir.path(), did).await.unwrap().unwrap();
        assert_eq!(manifest.root_cid, good_root);
    }

    // ── Export + mirror fallback ──────────────────────────────────────────────

    #[tokio::test]
    async fn export_returns_revalidated_bytes_and_metadata() {
        let did = "did:plc:export";
        let (car, root, rev) = valid_empty_repo(did, "3lkkkkkkk2az");
        let server = MockServer::start_async().await;
        mock_get_repo(&server, &car);
        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();
        run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();

        let export = export_core(dir.path(), did).await.unwrap();
        assert_eq!(export.root_cid, root);
        assert_eq!(export.rev, rev);
        assert_eq!(export.size_bytes, car.len() as u64);
        assert_eq!(BASE64.decode(export.car_base64).unwrap(), car);
    }

    #[tokio::test]
    async fn export_without_a_backup_is_a_storage_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = export_core(dir.path(), "did:plc:none").await.unwrap_err();
        assert!(matches!(err, RepoBackupError::StorageError { .. }));
    }

    #[tokio::test]
    async fn mirror_repo_car_returns_a_valid_snapshot_and_none_otherwise() {
        let did = "did:plc:mirror";
        let (car, _, _) = valid_empty_repo(did, "3lmmmmmmm2az");
        let server = MockServer::start_async().await;
        mock_get_repo(&server, &car);
        let dir = tempfile::tempdir().unwrap();
        let client = PdsClient::new();

        // No snapshot yet → None (fail-closed, so the migration surfaces its own source failure).
        assert!(mirror_repo_car(dir.path(), did).await.is_none());

        run_backup_core(&client, dir.path(), did, &server.base_url())
            .await
            .unwrap();
        assert_eq!(mirror_repo_car(dir.path(), did).await, Some(car));

        // A different DID must not be served this snapshot (the stored commit's did wouldn't match).
        assert!(mirror_repo_car(dir.path(), "did:plc:other").await.is_none());
    }

    #[tokio::test]
    async fn corrupt_manifest_fails_closed() {
        let did = "did:plc:manifest";
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(repo_dir(dir.path()))
            .await
            .unwrap();
        tokio::fs::write(manifest_path(dir.path(), did), b"{ not valid json")
            .await
            .unwrap();
        let err = status_core(Some(dir.path()), Some(BackupLocation::Local), did)
            .await
            .unwrap_err();
        assert!(matches!(err, RepoBackupError::ManifestCorrupt { .. }));
        // The corrupt file is preserved, not rebuilt over.
        assert!(tokio::fs::try_exists(manifest_path(dir.path(), did))
            .await
            .unwrap());
    }
}
