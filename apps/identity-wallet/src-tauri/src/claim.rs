// pattern: Functional Core (types and errors)
//
// Types: IdentityInfo, VerifiedClaimOp, OpDiff, ServiceChange, ClaimResult,
//        ClaimState, ResolveError, ClaimError
// These are all data structures with no side effects.

use serde::Serialize;

use crate::oauth_client::OAuthClient;
use crate::pds_client::PlcDidDocument;

// ── Output types ───────────────────────────────────────────────────────────

/// Identity information resolved from a handle or DID.
///
/// Returned by `resolve_identity` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    /// The DID (e.g., "did:plc:abc123...")
    pub did: String,
    /// The handle (e.g., "alice.test")
    pub handle: String,
    /// The PDS endpoint URL (e.g., "https://pds.example.com")
    pub pds_url: String,
    /// Current rotation keys from the DID document
    pub current_rotation_keys: Vec<String>,
    /// Whether the device key is a rotation key (true if device key == rotation_keys[0])
    pub device_key_is_root: bool,
}

/// Verified claim operation ready for submission.
///
/// Returned by `verify_claim` command.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedClaimOp {
    /// Diff of keys and services between current DID doc and proposed operation
    pub diff: OpDiff,
    /// Signed operation (ready for PLC submission)
    pub signed_op: String,
    /// Warnings from verification (e.g., "This operation will break X")
    pub warnings: Vec<String>,
}

/// Diff of changes between current DID document and proposed operation.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpDiff {
    /// Keys being added in this operation
    pub added_keys: Vec<String>,
    /// Keys being removed in this operation
    pub removed_keys: Vec<String>,
    /// Service endpoint changes (added/removed/modified)
    pub changed_services: Vec<ServiceChange>,
    /// Previous CID (content identifier) of the DID document
    pub prev_cid: String,
}

/// Change to a service endpoint in the DID document.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChange {
    /// Service ID (e.g., "atproto_pds")
    pub id: String,
    /// Type of change: "added", "removed", or "modified"
    pub change_type: String,
    /// Old endpoint URL (None if added)
    pub old_endpoint: Option<String>,
    /// New endpoint URL (None if removed)
    pub new_endpoint: Option<String>,
}

/// Result of a successful claim submission.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResult {
    /// Updated DID document after claim was applied
    pub updated_did_doc: serde_json::Value,
}

// ── State persisted across the claim flow ──────────────────────────────────

/// Claim flow state persisted in `AppState`.
///
/// This state is set by `resolve_identity` and used by subsequent
/// `start_pds_auth`, `request_claim_verification`, `sign_and_verify_claim`,
/// and `submit_claim` commands within the same claim flow session.
pub struct ClaimState {
    /// The DID being claimed (resolved by `resolve_identity`)
    pub did: String,
    /// The PDS endpoint URL (discovered by `resolve_identity`)
    pub pds_url: String,
    /// The DID document fetched from plc.directory (discovered by `resolve_identity`)
    pub did_doc: PlcDidDocument,
    /// OAuth client for the PDS (set after `start_pds_auth` succeeds)
    pub pds_oauth_client: Option<OAuthClient>,
    /// Verified signed operation (set after `sign_and_verify_claim` succeeds)
    pub verified_signed_op: Option<String>,
}

// ── Error types ────────────────────────────────────────────────────────────

/// Error returned by `resolve_identity` command.
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE" }` matching the
/// existing error pattern (CreateAccountError, DeviceKeyError, etc.).
#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolveError {
    /// Handle resolution failed (DNS and HTTP fallback both failed)
    HandleNotFound,
    /// DID not found in plc.directory (404 response)
    DidNotFound,
    /// PDS endpoint is unreachable
    PdsUnreachable,
    /// Network error during discovery (timeout, connection refused, etc.)
    NetworkError { message: String },
}

/// Error returned by claim flow commands (`verify_claim`, `request_claim_verification`, etc.).
///
/// Serializes as `{ "code": "SCREAMING_SNAKE_CASE", "message": "..." }` matching
/// the existing error pattern.
#[derive(Debug, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimError {
    /// PDS XRPC token request failed or returned invalid token
    InvalidToken,
    /// Claim verification failed (operation verification, signature validation, etc.)
    VerificationFailed { message: String },
    /// PLC directory operation submission failed
    PlcDirectoryError { message: String },
    /// User is not authorized for this operation
    Unauthorized,
    /// Network error during claim flow (timeout, connection refused, etc.)
    NetworkError { message: String },
}
