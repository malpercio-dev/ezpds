// pattern: Imperative Shell

//! OAuth against a discovered authorization server: PAR, token exchange, authorize URL.

use super::*;

/// Render a failed PAR response as the authorization server's own words.
///
/// A PAR rejection body is an RFC 6749 §5.2 `{error, error_description}` JSON object;
/// extracting it is what makes a policy rejection (e.g. `invalid_redirect_uri`)
/// diagnosable in the UI instead of an opaque status line. Falls back to the raw
/// status + body when the body isn't that shape.
pub(super) fn par_rejection_message(status: reqwest::StatusCode, body: &str) -> String {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        let code = json.get("error").and_then(|v| v.as_str());
        let description = json.get("error_description").and_then(|v| v.as_str());
        match (code, description) {
            (Some(c), Some(d)) => return format!("{c}: {d}"),
            (Some(c), None) => return c.to_string(),
            _ => {}
        }
    }
    format!("PAR returned {status}: {body}")
}

impl PdsClient {
    /// Perform a Pushed Authorization Request to an arbitrary PDS.
    ///
    /// Sends a PAR request with PKCE challenge, DPoP proof, and optional login_hint.
    pub async fn pds_par(
        &self,
        metadata: &AuthServerMetadata,
        request: PdsParRequest<'_>,
    ) -> Result<PdsParResponse, PdsClientError> {
        let par_url = metadata
            .pushed_authorization_request_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/par", metadata.issuer));

        let mut form_data = vec![
            ("response_type", "code".to_string()),
            ("code_challenge_method", "S256".to_string()),
            ("code_challenge", request.pkce_challenge.to_string()),
            ("state", request.state_param.to_string()),
            ("client_id", request.client_id.to_string()),
            ("redirect_uri", request.redirect_uri.to_string()),
            ("scope", "atproto transition:generic".to_string()),
            ("dpop_jkt", request.dpop_jkt.to_string()),
        ];

        if let Some(hint) = request.login_hint {
            form_data.push(("login_hint", hint.to_string()));
        }

        let response = self
            .client
            .post(&par_url)
            .header("DPoP", request.dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("pds_par", Some(&par_url), &e);
                PdsClientError::NetworkError {
                    message: format!("PAR request failed: {}", e),
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            // Surface the AS's own OAuth error — a PAR rejection (e.g. bsky.social's
            // invalid_redirect_uri) must reach the caller as more than a status code.
            return Err(PdsClientError::OauthFailed {
                message: par_rejection_message(status, &error_body),
            });
        }

        let json_resp =
            response
                .json::<PdsParResponse>()
                .await
                .map_err(|e| PdsClientError::OauthFailed {
                    message: format!("failed to parse PAR response: {}", e),
                })?;

        Ok(json_resp)
    }

    /// Exchange authorization code for tokens at an arbitrary PDS.
    ///
    /// Returns the raw response so the caller can handle nonce retry logic.
    /// Only transport-level failures are mapped to PdsClientError; HTTP error statuses
    /// are returned as-is for the caller to inspect.
    pub async fn pds_token_exchange(
        &self,
        metadata: &AuthServerMetadata,
        request: PdsTokenExchangeRequest<'_>,
    ) -> Result<reqwest::Response, PdsClientError> {
        let token_url = &metadata.token_endpoint;

        let form_data = vec![
            ("grant_type", "authorization_code"),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("code_verifier", request.pkce_verifier),
            ("client_id", request.client_id),
        ];

        self.client
            .post(token_url)
            .header("DPoP", request.dpop_proof)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("pds_token_exchange", Some(token_url), &e);
                PdsClientError::OauthFailed {
                    message: format!("token exchange request failed: {}", e),
                }
            })
    }

    /// Build the browser redirect URL for OAuth authorization.
    ///
    /// Constructs `{authorization_endpoint}?client_id=...&request_uri=...` with optional login_hint.
    pub fn build_pds_authorize_url(
        metadata: &AuthServerMetadata,
        request_uri: &str,
        login_hint: Option<&str>,
        client_id: &str,
    ) -> String {
        let mut url = format!(
            "{}?client_id={}&request_uri={}",
            metadata.authorization_endpoint,
            urlencoding::encode(client_id),
            urlencoding::encode(request_uri)
        );

        if let Some(hint) = login_hint {
            url.push_str(&format!("&login_hint={}", urlencoding::encode(hint)));
        }

        url
    }
}
