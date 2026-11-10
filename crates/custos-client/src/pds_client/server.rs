// pattern: Imperative Shell

//! Per-server calls: describeServer, sessions, repo/blob sync, signing-key reservation, account deletion.

use super::*;

impl PdsClient {
    /// Fetch the server description from a PDS.
    ///
    /// Gets `GET {pds_url}/xrpc/com.atproto.server.describeServer` (public, no auth).
    /// This is used as a destination reachability probe and to obtain the destination
    /// server's DID for service-auth requests.
    /// Maps connection failure / non-2xx to `PdsClientError::PdsUnreachable`.
    pub async fn describe_server(
        &self,
        pds_url: &str,
    ) -> Result<DescribeServerResponse, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.describeServer",
            pds_url.trim_end_matches('/')
        );

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("describeServer", Some(&url), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to reach PDS: {}", e),
                }
            })?;

        if !response.status().is_success() {
            return Err(PdsClientError::PdsUnreachable {
                reason: format!("describeServer returned {}", response.status()),
            });
        }

        let described = response
            .json::<DescribeServerResponse>()
            .await
            .map_err(|e| {
                self.note_transport_failure("describeServer", Some(&url), &e);
                PdsClientError::PdsUnreachable {
                    reason: format!("failed to parse describeServer response: {}", e),
                }
            })?;

        // Warm the caller's per-host capability cache from every describeServer call,
        // wherever it was made from. The probe and the cache are then the same fetch
        // rather than a second round trip.
        self.describe_observer
            .record_custos_capabilities(pds_url, described.custos.as_ref());

        Ok(described)
    }

    /// Create a full password session against a PDS (`com.atproto.server.createSession`).
    ///
    /// This is the source-PDS login for the claim (inbound-migration) flow. Unlike OAuth,
    /// a password `createSession` yields a **full-access** session (`com.atproto.access`), the
    /// only credential class that can drive PLC operations on a spec-strict PDS like bsky.social.
    /// The `identifier` is a handle, DID, or email; the `password` must be the account's
    /// real password (an app password is a lesser scope and is rejected the same way).
    ///
    /// The password is used for this single request and never persisted — the caller keeps only
    /// the returned JWTs (in an in-memory Bearer `OAuthClient`).
    ///
    /// `auth_factor_token` carries the email one-time code for accounts with 2FA enabled. Pass
    /// `None` on the first attempt; a 2FA account then answers with `AuthFactorTokenRequired`
    /// ([`PdsClientError::AuthFactorTokenRequired`]) and emails a code — retry with that code as
    /// `Some`. Any other 401 maps to [`PdsClientError::InvalidCredentials`] ("wrong password").
    pub async fn create_session(
        &self,
        pds_url: &str,
        identifier: &str,
        password: &str,
        auth_factor_token: Option<&str>,
    ) -> Result<CreateSessionResponse, PdsClientError> {
        // Never send the account password over a plaintext link. `pds_url` comes from the DID
        // document, so a misconfigured or hostile `http://` endpoint must be refused here.
        if !pds_url_is_secure(pds_url) {
            tracing::error!(pds_url = %pds_url, "refusing to send password to a non-HTTPS PDS");
            return Err(PdsClientError::InsecurePdsUrl {
                url: pds_url.to_string(),
            });
        }

        let url = format!(
            "{}/xrpc/com.atproto.server.createSession",
            pds_url.trim_end_matches('/')
        );

        let mut request_body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });
        if let Some(token) = auth_factor_token {
            request_body["authFactorToken"] = serde_json::Value::String(token.to_string());
        }

        let response = self
            .client
            .post(&url)
            .timeout(Duration::from_secs(30))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("createSession", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("createSession request failed: {}", e),
                }
            })?;

        let status = response.status();
        if status.as_u16() == 401 {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "(response body unreadable)".to_string());
            // An account with email 2FA answers a token-less attempt with `AuthFactorTokenRequired`
            // (and emails a code) — distinct from a wrong password, so the UI can prompt for the
            // code instead of blaming the password.
            if error_code_is(&body, "AuthFactorTokenRequired") {
                return Err(PdsClientError::AuthFactorTokenRequired);
            }
            return Err(PdsClientError::InvalidCredentials { message: body });
        }
        if !status.is_success() {
            // 401 is already handled above (wrong password / 2FA). Anything else — a 429 rate
            // limit, a 400 validation error — is classified so its real reason survives.
            return Err(
                classify_xrpc_response("createSession", response, self.observer.as_ref()).await,
            );
        }

        response.json::<CreateSessionResponse>().await.map_err(|e| {
            PdsClientError::InvalidResponse {
                message: format!("failed to parse createSession response: {}", e),
            }
        })
    }

    /// Rotate a Bearer session's access/refresh pair (`com.atproto.server.refreshSession`).
    ///
    /// The response shares `createSession`'s shape (`accessJwt`/`refreshJwt`/`did`), so this
    /// reuses [`CreateSessionResponse`] rather than a duplicate type. Sub/audience validation
    /// against the caller's expected DID and hosting server is *not* done here — that is
    /// session-lifecycle policy, not a client concern; see
    /// [`crate::sovereign_session::refresh_bearer_session`] for the validated wrapper.
    ///
    /// Non-success responses route through [`crate::error::classify_xrpc_response`], so a
    /// caller distinguishing "revoked" (discard the record) from "offline" (keep it) by
    /// status/variant should know: a 401 whose *body read itself* fails yields `NetworkError`
    /// (offline-shaped), not the classified 401. Narrow — bodies here are small and capped —
    /// and fails safe (a dead record just outlives one more refresh attempt), but a caller
    /// wanting a stricter "always discard on 401" guarantee has to special-case it.
    pub async fn refresh_session(
        &self,
        pds_url: &str,
        refresh_jwt: &str,
    ) -> Result<CreateSessionResponse, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.refreshSession",
            pds_url.trim_end_matches('/')
        );
        let response = self
            .client
            .post(&url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {refresh_jwt}"),
            )
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("refreshSession", Some(&url), &e);
                // Strip the URL before it becomes a message: a reqwest error's `Display`
                // embeds the full request URL, and this message reaches the frontend
                // verbatim as obsign-core's `SharedFailure::NetworkError` payload.
                let e = e.without_url();
                PdsClientError::NetworkError {
                    message: format!("refreshSession request failed: {}", e),
                }
            })?;

        if !response.status().is_success() {
            return Err(
                classify_xrpc_response("refreshSession", response, self.observer.as_ref()).await,
            );
        }

        response.json::<CreateSessionResponse>().await.map_err(|e| {
            PdsClientError::InvalidResponse {
                message: format!("failed to parse refreshSession response: {}", e),
            }
        })
    }

    /// Fetch the full repo as a CAR file (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.getRepo?did={did}` and returns the raw CAR bytes.
    /// No Authorization header is sent.
    pub async fn fetch_repo_car(
        &self,
        pds_url: &str,
        did: &str,
    ) -> Result<Vec<u8>, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getRepo?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );

        // A full repo CAR can be large; override the shared 30s client timeout so a slow bulk
        // download doesn't fail mid-stream.
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("getRepo", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to fetch repo CAR: {}", e),
                }
            })?;

        let resp = xrpc_ok("getRepo", resp, self.observer.as_ref()).await?;

        resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
            self.note_transport_failure("getRepo", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to read repo CAR bytes: {}", e),
            }
        })
    }

    /// Fetch the repo's current commit CID and rev (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.getLatestCommit?did={did}`. The answer is
    /// unsigned, so it is only fit for deciding whether a full [`Self::fetch_repo_car`] is needed,
    /// never for trusting repo contents.
    pub async fn fetch_latest_commit(
        &self,
        pds_url: &str,
        did: &str,
    ) -> Result<LatestCommit, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getLatestCommit?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );
        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("getLatestCommit", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to fetch latest commit: {}", e),
            }
        })?;
        xrpc_json("getLatestCommit", resp, self.observer.as_ref()).await
    }

    /// Fetch a blob by DID and CID (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}` and returns the raw blob bytes.
    /// No Authorization header is sent.
    pub async fn fetch_blob(
        &self,
        pds_url: &str,
        did: &str,
        cid: &str,
    ) -> Result<Vec<u8>, PdsClientError> {
        self.fetch_blob_with_type(pds_url, did, cid)
            .await
            .map(|(bytes, _)| bytes)
    }

    /// Fetch a blob by DID and CID, also returning the server's `Content-Type` (auth: none).
    ///
    /// Same call as [`fetch_blob`](Self::fetch_blob), but preserves the response's
    /// `Content-Type` header — the only place the blob's MIME type is available on the
    /// public sync surface (`listBlobs` yields bare CIDs). A blob-backup manifest can record
    /// it so a later `uploadBlob` restore replays the original type.
    pub async fn fetch_blob_with_type(
        &self,
        pds_url: &str,
        did: &str,
        cid: &str,
    ) -> Result<(Vec<u8>, Option<String>), PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did),
            urlencoding::encode(cid)
        );

        // Blobs (images/video) can be large; override the shared 30s client timeout for the download.
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("getBlob", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to fetch blob: {}", e),
                }
            })?;

        let resp = xrpc_ok("getBlob", resp, self.observer.as_ref()).await?;

        // Capture the header before the body read consumes the response.
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        resp.bytes()
            .await
            .map(|b| (b.to_vec(), content_type))
            .map_err(|e| {
                self.note_transport_failure("getBlob", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to read blob bytes: {}", e),
                }
            })
    }

    /// List a DID's blob CIDs on its PDS, one page (auth: none).
    ///
    /// Calls `GET {pds_url}/xrpc/com.atproto.sync.listBlobs?did={did}&cursor={cursor}`.
    /// This is the source-side listing a blob-backup sync pass paginates (distinct from the
    /// authenticated destination-side `listMissingBlobs` a migration drain uses); the
    /// response is bare CIDs plus an optional cursor.
    pub async fn list_blobs(
        &self,
        pds_url: &str,
        did: &str,
        cursor: Option<&str>,
    ) -> Result<ListedBlobs, PdsClientError> {
        let mut url = format!(
            "{}/xrpc/com.atproto.sync.listBlobs?did={}",
            pds_url.trim_end_matches('/'),
            urlencoding::encode(did)
        );
        if let Some(cur) = cursor {
            url.push_str(&format!("&cursor={}", urlencoding::encode(cur)));
        }

        let resp = self.client.get(&url).send().await.map_err(|e| {
            self.note_transport_failure("listBlobs", Some(&url), &e);
            PdsClientError::NetworkError {
                message: format!("failed to list blobs: {}", e),
            }
        })?;

        xrpc_json("listBlobs", resp, self.observer.as_ref()).await
    }

    /// Reserve a signing key on the PDS (auth: none, idempotent per DID).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.reserveSigningKey` with body `{"did": did}`,
    /// or an empty body when `did` is `None`. Returns the `signingKey` field from the response (a
    /// did:key string).
    ///
    /// `None` is the *anonymous* reservation, for a key that has to exist before the DID it will
    /// belong to does: a child-account mint has to name a repo-signing key inside the genesis op
    /// whose hash becomes the child's DID. Anonymous reservations are rate-limited per IP and are
    /// not idempotent — each call yields a fresh key.
    pub async fn reserve_signing_key(
        &self,
        pds_url: &str,
        did: Option<&str>,
    ) -> Result<String, PdsClientError> {
        let url = format!(
            "{}/xrpc/com.atproto.server.reserveSigningKey",
            pds_url.trim_end_matches('/')
        );

        let body = match did {
            Some(did) => serde_json::json!({ "did": did }),
            None => serde_json::json!({}),
        };
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("reserveSigningKey", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to reserve signing key: {}", e),
                }
            })?;

        let resp = xrpc_ok("reserveSigningKey", resp, self.observer.as_ref()).await?;

        #[derive(Deserialize)]
        struct ReserveSigningKeyResponse {
            #[serde(rename = "signingKey")]
            signing_key: String,
        }

        resp.json::<ReserveSigningKeyResponse>()
            .await
            .map(|r| r.signing_key)
            .map_err(|e| {
                self.note_transport_failure("reserveSigningKey", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("failed to parse reserve_signing_key response: {}", e),
                }
            })
    }

    /// Permanently delete an account on its PDS (auth: none — the credentials are in the body).
    ///
    /// Calls `POST {pds_url}/xrpc/com.atproto.server.deleteAccount` with `{ did, password, token }`,
    /// where `token` is the single-use code minted by `requestAccountDelete` and emailed to the
    /// account. Not session-authed, so no `OAuthClient` is needed — but a credential travels in
    /// the body either way, so the endpoint is refused over a non-HTTPS URL (loopback excepted),
    /// same guard as the password `createSession` path.
    ///
    /// `credential` selects the first factor. [`DeleteCredential::Proof`] additionally sends the
    /// off-lexicon `custos.proof` object, and sends `password` as the empty string — the vendored
    /// lexicon marks the field required, so it stays on the wire even for an account that has no
    /// password. Only a host advertising `walletAccountDelete` reads it.
    pub async fn delete_account(
        &self,
        pds_url: &str,
        did: &str,
        credential: &DeleteCredential,
        token: &str,
    ) -> Result<(), PdsClientError> {
        if !pds_url_is_secure(pds_url) {
            return Err(PdsClientError::InsecurePdsUrl {
                url: pds_url.to_string(),
            });
        }

        let url = format!(
            "{}/xrpc/com.atproto.server.deleteAccount",
            pds_url.trim_end_matches('/')
        );
        let mut body = serde_json::json!({
            "did": did,
            "password": credential.password_field(),
            "token": token,
        });
        if let DeleteCredential::Proof(proof) = credential {
            body["custos"] = serde_json::json!({ "proof": proof });
        }
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                self.note_transport_failure("deleteAccount", Some(&url), &e);
                PdsClientError::NetworkError {
                    message: format!("delete_account failed: {}", e),
                }
            })?;

        xrpc_ok("deleteAccount", resp, self.observer.as_ref())
            .await
            .map(|_| ())
    }
}
