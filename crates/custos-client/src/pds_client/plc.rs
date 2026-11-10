// pattern: Imperative Shell

//! plc.directory reads and writes, and the audit-log rotation-key helper.

use super::*;

impl PdsClient {
    /// Fetch the PLC operation audit log for a DID.
    ///
    /// Calls `GET {plc_directory_url}/{did}/log/audit` and returns the raw JSON string.
    pub async fn fetch_audit_log(&self, did: &str) -> Result<String, PdsClientError> {
        let url = format!("{}/{}/log/audit", self.plc_directory_url, did);
        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("fetch_audit_log", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch audit log: {}", e),
            }
        })?;

        if resp.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }
        // A non-2xx is plc.directory's verdict (429 throttle, 5xx outage), not a
        // connectivity problem — classify by status so callers can say which it was.
        let resp = xrpc_ok("fetch_audit_log", resp, self.observer.as_ref()).await?;

        resp.text().await.map_err(|e| {
            self.note_transport_failure("fetch_audit_log", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to read audit log response: {}", e),
            }
        })
    }

    /// Fetch the PLC *data* document for a DID.
    ///
    /// Calls `GET {plc_directory_url}/{did}/data` — the PLC-native shape
    /// (`did, alsoKnownAs, rotationKeys, verificationMethods, services`). The W3C
    /// document (`GET /{did}`) carries no `rotationKeys` and must never be cached in its place.
    pub async fn fetch_plc_data_document(
        &self,
        did: &str,
    ) -> Result<serde_json::Value, PdsClientError> {
        let url = format!("{}/{}/data", self.plc_directory_url, did);
        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("fetch_plc_data_document", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch PLC data document: {}", e),
            }
        })?;

        if resp.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }
        // Same status-classification as `fetch_audit_log`: a 429/5xx from plc.directory
        // must not read as "check your connection".
        let resp = xrpc_ok("fetch_plc_data_document", resp, self.observer.as_ref()).await?;

        resp.json().await.map_err(|e| {
            self.note_transport_failure("fetch_plc_data_document", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to parse PLC data document: {}", e),
            }
        })
    }

    /// Submit a signed PLC operation to plc.directory.
    ///
    /// Calls `POST {plc_directory_url}/{did}` with the signed operation as JSON body.
    pub async fn post_plc_operation(
        &self,
        did: &str,
        operation: &serde_json::Value,
    ) -> Result<(), PdsClientError> {
        let url = format!("{}/{}", self.plc_directory_url, did);
        let resp = self
            .client
            .post(&url)
            .json(operation)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("post_plc_operation", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to post plc operation: {}", e),
                }
            })?;

        if resp.status().is_success() {
            Ok(())
        } else if resp.status().as_u16() == 429 {
            // A throttle is not a rejection of the operation — surface it as the retryable
            // condition it is, with the server's pacing hint.
            Err(classify_xrpc_response("post_plc_operation", resp, self.observer.as_ref()).await)
        } else {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            Err(PdsClientError::InvalidResponse {
                message: format!("plc.directory rejected operation: {}", body),
            })
        }
    }
}

// ============================================================================
// Public helpers
// ============================================================================

/// Extract rotation keys from the latest entry in a raw PLC audit log JSON string.
/// Returns an empty Vec if parsing fails or the log has no entries.
pub fn rotation_keys_from_audit_log(raw_json: &str) -> Vec<String> {
    let entries: Vec<serde_json::Value> = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    entries
        .last()
        .and_then(|entry| entry.get("operation"))
        .and_then(|op| op.get("rotationKeys"))
        .and_then(|keys| keys.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
