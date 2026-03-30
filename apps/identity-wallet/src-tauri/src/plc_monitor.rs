use serde::Serialize;

/// An unauthorized PLC operation detected by the monitor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnauthorizedChange {
    /// CID of the unauthorized operation.
    pub cid: String,
    /// ISO 8601 timestamp when plc.directory accepted the operation.
    /// Frontend computes recovery deadline as created_at + 72 hours.
    pub created_at: String,
    /// did:key URI of the key that signed this operation, if identified.
    /// None if the signing key could not be determined from known rotation keys.
    pub signing_key: Option<String>,
    /// The raw PLC operation JSON for display in alert detail.
    pub operation: serde_json::Value,
}

/// Result of checking a single identity's PLC status.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatus {
    pub did: String,
    pub alert_count: usize,
    pub unauthorized_changes: Vec<UnauthorizedChange>,
}

/// Errors from PLC monitoring operations.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MonitorError {
    #[error("Network error: {message}")]
    NetworkError { message: String },
    #[error("Identity store error: {message}")]
    IdentityStoreError { message: String },
    #[error("Failed to parse audit log: {message}")]
    ParseError { message: String },
}
