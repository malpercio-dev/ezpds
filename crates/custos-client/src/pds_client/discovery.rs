// pattern: Imperative Shell

//! Discovery: handle resolution, DID-doc → PDS endpoint, and authorization-server discovery.

use super::*;

// ── W3C DID Document (private, for parsing `GET /{did}` responses) ───────────

/// W3C DID Document as returned by `GET {plc_directory_url}/{did}`.
/// Different shape from PLC operations: `id` not `did`, arrays not HashMaps.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct W3cDidDocument {
    id: String,
    #[serde(default)]
    also_known_as: Vec<String>,
    #[serde(default)]
    verification_method: Vec<W3cVerificationMethod>,
    #[serde(default)]
    service: Vec<W3cService>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct W3cVerificationMethod {
    id: String,
    #[serde(default)]
    public_key_multibase: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct W3cService {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    service_endpoint: String,
}

impl W3cDidDocument {
    /// Convert to PlcDidDocument. `rotation_keys` will be empty — the caller
    /// must populate them from the audit log if needed.
    pub(super) fn into_plc_doc(self) -> PlcDidDocument {
        // Convert verification_method array to the { "atproto": "did:key:..." } shape
        let mut vm_map = serde_json::Map::new();
        for method in &self.verification_method {
            // Strip the "did:plc:...#" prefix from the id to get the key name
            let key_name = method
                .id
                .rsplit_once('#')
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| method.id.clone());
            if let Some(ref pkm) = method.public_key_multibase {
                vm_map.insert(key_name, serde_json::Value::String(pkm.clone()));
            }
        }

        // Convert service array to HashMap keyed by the id's fragment. Like the
        // verification-method ids above, service ids come in both W3C forms:
        // plc.directory serves the bare fragment ("#atproto_pds") while a did:web
        // document typically carries the absolute form ("did:web:host#atproto_pds").
        let services = self
            .service
            .into_iter()
            .map(|svc| {
                let key = svc
                    .id
                    .rsplit_once('#')
                    .map(|(_, name)| name.to_string())
                    .unwrap_or_else(|| svc.id.clone());
                let plc_svc = PlcService {
                    service_type: svc.service_type,
                    endpoint: svc.service_endpoint,
                };
                (key, plc_svc)
            })
            .collect();

        PlcDidDocument {
            did: self.id,
            also_known_as: self.also_known_as,
            rotation_keys: Vec::new(),
            verification_methods: serde_json::Value::Object(vm_map),
            services,
        }
    }
}
impl PdsClient {
    /// Resolve a handle to a DID via DNS TXT lookup with HTTP fallback.
    ///
    /// Attempts DNS TXT lookup for `_atproto.{handle}` first, then falls back to HTTP
    /// `/.well-known/atproto-did` if DNS fails or returns no records.
    /// Returns `HANDLE_NOT_FOUND` only when both methods fail.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, PdsClientError> {
        // Try DNS TXT lookup first
        let dns_error = match try_resolve_dns(handle, self.observer.as_ref()).await {
            Ok(Some(did)) => return Ok(did),
            Ok(None) => None,
            Err(e) => Some(e),
        };

        // Try HTTP well-known lookup
        let http_url = format!("https://{}/.well-known/atproto-did", handle);
        match try_resolve_http(&self.client, &http_url, self.observer.as_ref()).await {
            Ok(Some(did)) => return Ok(did),
            Ok(None) => {
                // Both DNS and HTTP failed; if DNS had a transport error, surface it
                if let Some(dns_err) = dns_error {
                    return Err(dns_err);
                }
            }
            Err(e) => return Err(e),
        }

        // Neither DNS nor HTTP succeeded (both returned "not found", no transport errors)
        Err(PdsClientError::HandleNotFound)
    }

    /// Fetch the DID document from plc.directory and extract the PDS endpoint.
    ///
    /// Fetches the DID document from plc.directory, extracts the atproto_pds service
    /// endpoint, and verifies it is reachable via a HEAD request.
    /// Returns `DID_NOT_FOUND` on 404, `PDS_UNREACHABLE` if the endpoint is down.
    pub async fn discover_pds(
        &self,
        did: &str,
    ) -> Result<(String, PlcDidDocument), PdsClientError> {
        // A did:web document lives at the domain itself, not plc.directory. Hostname-form
        // identifiers only (the shape apps compose): a colon would smuggle a port or
        // path segment into the URL, so those shapes are refused rather than misresolved.
        let url = if let Some(host) = did.strip_prefix("did:web:") {
            if host.is_empty() || host.contains([':', '/', '@']) {
                return Err(PdsClientError::InvalidResponse {
                    message: "unsupported did:web identifier".to_string(),
                });
            }
            format!("https://{}/.well-known/did.json", host.to_ascii_lowercase())
        } else {
            format!("{}/{}", self.plc_directory_url, did)
        };

        // Fetch the DID document from plc.directory
        let response = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("discover_pds", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch DID document: {}", e),
            }
        })?;

        if response.status().as_u16() == 404 {
            return Err(PdsClientError::DidNotFound);
        }

        // Parse W3C DID Document and convert to PlcDidDocument. Status-classified like the
        // other plc.directory reads: a throttle or outage verdict is preserved for callers
        // instead of flattening to a transport error. rotation_keys will be empty —
        // callers that need them must fetch the audit log.
        let w3c_doc: W3cDidDocument =
            xrpc_json("discover_pds", response, self.observer.as_ref()).await?;
        let doc = w3c_doc.into_plc_doc();

        // Extract the atproto_pds service
        let pds_service =
            doc.services
                .get("atproto_pds")
                .ok_or_else(|| PdsClientError::InvalidResponse {
                    message: "missing atproto_pds service".to_string(),
                })?;

        let pds_endpoint = &pds_service.endpoint;

        // Verify PDS reachability with a HEAD request (5-second timeout)
        self.client
            .head(pds_endpoint)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("discover_pds", Some(pds_endpoint), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to reach PDS endpoint: {}", e),
                }
            })?;

        Ok((pds_endpoint.to_string(), doc))
    }

    /// Discover the OAuth authorization server for a PDS.
    ///
    /// Follows RFC 9728 (OAuth Protected Resource Metadata):
    /// 1. Try `GET {pds_url}/.well-known/oauth-protected-resource` to find the
    ///    authorization server URL (e.g. Bluesky entryway at `bsky.social`)
    /// 2. Fetch `GET {auth_server}/.well-known/oauth-authorization-server`
    /// 3. Fall back to `GET {pds_url}/.well-known/oauth-authorization-server`
    ///    if the protected resource endpoint doesn't exist (self-hosted PDS)
    ///
    /// Validates that the metadata includes "code" in `response_types_supported`
    /// and "S256" in `code_challenge_methods_supported`.
    pub async fn discover_auth_server(
        &self,
        pds_url: &str,
    ) -> Result<AuthServerMetadata, PdsClientError> {
        // Step 1: Try protected resource metadata to find the auth server
        let auth_server_base = self.discover_protected_resource_auth_server(pds_url).await;

        let metadata_base = match &auth_server_base {
            Some(server) => {
                tracing::debug!(auth_server = %server, "using authorization server from protected resource metadata");
                server.as_str()
            }
            None => {
                tracing::debug!(pds_url = %pds_url, "no protected resource metadata, falling back to PDS directly");
                pds_url
            }
        };

        // Step 2: Fetch the OAuth authorization server metadata
        let url = format!("{}/.well-known/oauth-authorization-server", metadata_base);
        tracing::debug!(url = %url, "fetching OAuth authorization server metadata");

        let response = self.client.get(&url).send().await.map_err(|e| {
            tracing::error!(url = %url, error = %e, "OAuth metadata fetch failed");
            self.note_transport_failure("discover_auth_server", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch OAuth metadata: {}", e),
            }
        })?;

        if !response.status().is_success() {
            tracing::error!(url = %url, status = %response.status(), "OAuth metadata returned non-success");
            return Err(PdsClientError::InvalidResponse {
                message: format!(
                    "OAuth metadata fetch returned {} from {}",
                    response.status(),
                    metadata_base
                ),
            });
        }

        let metadata: AuthServerMetadata = response.json().await.map_err(|e| {
            tracing::error!(url = %url, error = %e, "OAuth metadata parsing failed");
            PdsClientError::InvalidResponse {
                message: format!("failed to parse OAuth metadata: {}", e),
            }
        })?;
        tracing::debug!(issuer = %metadata.issuer, "OAuth metadata parsed");

        // Validate required capabilities
        if !metadata
            .response_types_supported
            .contains(&"code".to_string())
        {
            return Err(PdsClientError::InvalidResponse {
                message: "OAuth metadata missing 'code' in response_types_supported".to_string(),
            });
        }

        if !metadata
            .code_challenge_methods_supported
            .contains(&"S256".to_string())
        {
            return Err(PdsClientError::InvalidResponse {
                message: "OAuth metadata missing 'S256' in code_challenge_methods_supported"
                    .to_string(),
            });
        }

        Ok(metadata)
    }

    /// Try to discover the authorization server URL from the PDS's protected
    /// resource metadata (RFC 9728). Returns `None` if the endpoint doesn't
    /// exist or can't be parsed — the caller should fall back to the PDS URL.
    pub(super) async fn discover_protected_resource_auth_server(
        &self,
        pds_url: &str,
    ) -> Option<String> {
        let url = format!("{}/.well-known/oauth-protected-resource", pds_url);
        tracing::debug!(url = %url, "checking protected resource metadata");

        let response = match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::debug!(url = %url, status = %r.status(), "protected resource metadata not available");
                return None;
            }
            Err(e) => {
                tracing::debug!(url = %url, error = %e, "protected resource metadata fetch failed");
                return None;
            }
        };

        #[derive(serde::Deserialize)]
        struct ProtectedResource {
            #[serde(default)]
            authorization_servers: Vec<String>,
        }

        match response.json::<ProtectedResource>().await {
            Ok(pr) => {
                let server = pr.authorization_servers.into_iter().next();
                if let Some(ref s) = server {
                    tracing::debug!(auth_server = %s, "found authorization server in protected resource metadata");
                }
                server
            }
            Err(e) => {
                tracing::debug!(url = %url, error = %e, "failed to parse protected resource metadata");
                None
            }
        }
    }
}

// ============================================================================
// Helper functions for resolve_handle
// ============================================================================

/// DNS TXT lookup for `_atproto.{handle}`. Returns `Ok(Some(did))` on success,
/// `Ok(None)` if no matching TXT record found, `Err` on transport failure.
///
/// `pub` (not just crate-private) so a caller's own handle-resolution pre-flight (e.g. a
/// change-handle DNS check) can report this vantage separately from the hosting PDS's own
/// resolution.
#[cfg(target_arch = "wasm32")]
pub async fn try_resolve_dns(
    _handle: &str,
    _observer: &dyn TransportObserver,
) -> Result<Option<String>, PdsClientError> {
    // No raw DNS from a browser: report it as the transport failure it is, so `resolve_handle`
    // still falls through to the HTTPS well-known lookup and a pre-flight never reads "no record".
    Err(PdsClientError::NetworkError {
        message: "DNS TXT lookup is not available on this target".to_string(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn try_resolve_dns(
    handle: &str,
    observer: &dyn TransportObserver,
) -> Result<Option<String>, PdsClientError> {
    let dns_name = format!("_atproto.{}", handle);
    tracing::debug!(dns_name = %dns_name, "attempting DNS TXT lookup");

    // Create a resolver using system DNS config (matches the PDS's own resolver setup).
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to create DNS resolver: {}", e),
        })?
        .build()
        .map_err(|e| PdsClientError::NetworkError {
            message: format!("failed to build DNS resolver: {}", e),
        })?;

    match resolver.txt_lookup(&dns_name).await {
        Ok(lookup) => {
            // Iterate through TXT records and find one starting with "did="
            for record in lookup.answers() {
                let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                    continue;
                };
                for part in txt.txt_data.iter() {
                    match std::str::from_utf8(part) {
                        Ok(s) => {
                            if let Some(did_value) = s.strip_prefix("did=") {
                                let did = did_value.trim().to_string();
                                tracing::debug!(did = %did, "DNS TXT resolved");
                                return Ok(Some(did));
                            }
                        }
                        Err(_) => {
                            // Non-UTF-8 bytes in TXT record; skip
                        }
                    }
                }
            }
            tracing::debug!(dns_name = %dns_name, "no did= TXT record found");
            Ok(None)
        }
        Err(e) => {
            // Check if it's a "no records found" error (normal for unregistered handles)
            // vs. a transport error (network failure)
            if e.is_no_records_found() {
                tracing::debug!(dns_name = %dns_name, "no DNS TXT records found");
                Ok(None)
            } else {
                tracing::warn!(dns_name = %dns_name, error = %e, "DNS TXT lookup failed");
                // Host is omitted: the DNS name embeds the handle, which the diagnostics log
                // must never capture. The fixed `"dns"` category is enough to show the class.
                observer.record_transport_category("resolve_handle_dns", None, "dns");
                Err(PdsClientError::NetworkError {
                    message: format!("DNS lookup failed: {}", e),
                })
            }
        }
    }
}

/// HTTP well-known fetch. `GET {url}` and return trimmed body on 2xx,
/// `Ok(None)` on 4xx (handle not found), `Err(NetworkError)` on transport or 5xx.
/// The caller constructs the full URL.
pub(super) async fn try_resolve_http(
    client: &reqwest::Client,
    url: &str,
    observer: &dyn TransportObserver,
) -> Result<Option<String>, PdsClientError> {
    tracing::debug!(url = %url, "attempting HTTP well-known lookup");
    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        tracing::debug!(url = %url, did = %body.trim(), "HTTP well-known resolved");
                        Ok(Some(body.trim().to_string()))
                    }
                    Err(e) => {
                        tracing::warn!(url = %url, error = %e, "HTTP well-known body read failed");
                        // Host omitted: the well-known URL's host IS the handle domain.
                        observer.record_transport("resolve_handle_http", None, &e);
                        Err(PdsClientError::NetworkError {
                            message: format!("failed to read response body: {}", e),
                        })
                    }
                }
            } else if response.status().is_client_error() {
                // 4xx = handle not found at this endpoint
                tracing::debug!(url = %url, status = %response.status(), "HTTP well-known not found");
                Ok(None)
            } else {
                // 5xx = temporary server error
                tracing::warn!(url = %url, status = %response.status(), "HTTP well-known server error");
                Err(PdsClientError::NetworkError {
                    message: format!("server error from {}: {}", url, response.status()),
                })
            }
        }
        Err(e) => {
            tracing::warn!(url = %url, error = %e, "HTTP well-known request failed");
            // Host omitted: the well-known URL's host IS the handle domain.
            observer.record_transport("resolve_handle_http", None, &e);
            Err(PdsClientError::NetworkError {
                message: format!("HTTP request failed: {}", e),
            })
        }
    }
}
