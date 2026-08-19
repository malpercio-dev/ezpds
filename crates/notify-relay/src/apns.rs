// pattern: Mixed (Functional Core + I/O shell)
//
// The APNs leg: the only place the relay talks to anyone but an enrolled instance. Its
// whole job is to wrap bytes it cannot read in the envelope Apple insists on, and to
// translate Apple's answer back into a `PushOutcome` the instance can act on.
//
// Everything that decides *what* gets sent is pure — envelope assembly, the 4 KiB size
// check, JWT minting against an explicit clock, status classification — so the interesting
// behaviour is unit-tested without a socket, and the wiremock tests only have to prove the
// wiring. `send` is the single I/O function.
//
// The relay holds exactly one secret here: Apple's token-auth key, which belongs to the
// relay operator. No instance key and no device key ever passes through this module — the
// `enc`/`ct` pair is copied from the RPC into the envelope verbatim and never inspected.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

use crate::protocol::PushOutcome;

/// Apple's hard cap on the serialized notification body. Enforced here as well as by the
/// sender: the padding budget lives on the Custos side, and a sender that miscomputes it
/// should be told so, not have Apple reject the request on the relay's credentials.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

/// How long a minted provider token is reused. Apple refuses tokens younger than 20
/// minutes on refresh and older than 60; 50 leaves room for clock skew at both ends.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// Apple's production and sandbox provider hosts. Overridden wholesale by
/// `apns.endpoint` / `EZPDS_NOTIFY_APNS_URL`, which is how the tests point at wiremock.
const PRODUCTION_ENDPOINT: &str = "https://api.push.apple.com";
const SANDBOX_ENDPOINT: &str = "https://api.sandbox.push.apple.com";

/// Priority for a user-visible alert. Apple only accepts 10 or 5 for an alert push.
const ALERT_PRIORITY: u8 = 10;

/// Priority for a content-free ping. Apple *requires* 5 for a background push — a 10 is
/// rejected outright, not merely delivered eagerly.
const BACKGROUND_PRIORITY: u8 = 5;

/// Cap on how much of a refusal body is read for the operator log. Apple's `reason`
/// payloads are tens of bytes; anything past this is an endpoint that is not APNs.
const MAX_REASON_BYTES: usize = 1024;

/// Expiry applied when the sender names no `ttlSecs`. A notification banner an hour stale
/// is worse than no banner, and a zero expiration would tell Apple to drop it the instant
/// the device is unreachable — neither extreme is a good default.
const DEFAULT_TTL_SECS: u32 = 3600;

/// Refusals from constructing the client, all of them operator-facing startup errors.
#[derive(Debug, thiserror::Error)]
pub enum ApnsSetupError {
    #[error("failed to read the APNs key at {path}: {source}")]
    ReadKey {
        path: String,
        source: std::io::Error,
    },
    #[error("the APNs key at {path} is not a PKCS#8 P-256 private key (.p8): {source}")]
    ParseKey {
        path: String,
        source: p256::pkcs8::Error,
    },
    #[error("failed to build the APNs HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

/// One notification to hand to Apple. Borrowed throughout: every field is already owned by
/// either the handle row or the decoded RPC, and none of it outlives the push.
#[derive(Debug, Clone, Copy)]
pub struct PushRequest<'a> {
    /// The device's APNs token — resolved from the handle, never sent by the instance.
    pub device_token: &'a str,
    /// The bundle id this device registered under. Per-handle, not per-relay: one relay
    /// serves both official apps.
    pub topic: &'a str,
    /// Which of the instance's versioned sender keys sealed the payload. Echoed to the
    /// device untouched.
    pub kid: u32,
    /// Base64url HPKE encapsulated key, verbatim from the RPC.
    pub enc: &'a str,
    /// Base64url HPKE ciphertext, verbatim from the RPC.
    pub ct: &'a str,
    pub ttl_secs: Option<u32>,
    /// Metadata-minimizing ping mode: send a content-free `content-available` background
    /// push instead of the sealed envelope. `kid`/`enc`/`ct` are ignored — nothing of the
    /// notification, not even ciphertext, reaches Apple; the device fetches on wake.
    pub ping: bool,
}

/// The APNs client: an HTTP client, the operator's token-auth key, and the current
/// provider token. Shared across every push; `send` takes `&self`.
pub struct ApnsClient {
    http: reqwest::Client,
    /// Scheme and authority only, no trailing slash.
    endpoint: String,
    signing_key: SigningKey,
    key_id: String,
    team_id: String,
    /// The live provider token. A `std::sync::Mutex` is right here: the critical section
    /// is a clock comparison and at worst one ECDSA signature, never an await.
    token: Mutex<Option<CachedToken>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    value: String,
    minted_at: Instant,
}

impl ApnsClient {
    /// Build a client from the validated `[apns]` block. The key is read once at startup
    /// so a missing or malformed `.p8` is an immediate refusal to serve rather than a
    /// failure discovered on the first real notification.
    pub fn new(config: &crate::config::ApnsConfig) -> Result<Option<Self>, ApnsSetupError> {
        // Credentials are all-or-nothing, already enforced at config validation; absent
        // means the operator has not wired APNs up at all, which is a legal state for a
        // relay being brought up before its key exists.
        let (Some(key_path), Some(key_id), Some(team_id)) = (
            config.key_path.as_ref(),
            config.key_id.as_ref(),
            config.team_id.as_ref(),
        ) else {
            return Ok(None);
        };

        let path = key_path.display().to_string();
        let pem = std::fs::read_to_string(key_path).map_err(|source| ApnsSetupError::ReadKey {
            path: path.clone(),
            source,
        })?;
        let signing_key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|source| ApnsSetupError::ParseKey { path, source })?;

        let endpoint = config
            .endpoint
            .clone()
            .unwrap_or_else(|| default_endpoint(config.sandbox).to_owned());

        Ok(Some(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            signing_key,
            key_id: key_id.clone(),
            team_id: team_id.clone(),
            token: Mutex::new(None),
        }))
    }

    /// Deliver one notification, reporting what Apple made of it.
    ///
    /// Never returns `Err`: every failure mode — an oversized body, a refusal, an
    /// unreachable Apple — is a `PushOutcome` the instance is meant to act on, so it
    /// travels in the RPC response rather than as a transport error.
    pub async fn send(&self, request: &PushRequest<'_>) -> PushOutcome {
        let body = if request.ping {
            ping_envelope()
        } else {
            build_envelope(request.kid, request.enc, request.ct)
        };
        let Ok(body) = serialize_within_cap(&body) else {
            // Charged to the sender, not to Apple: the padding budget that should have
            // kept this under the cap is computed instance-side.
            tracing::warn!(
                topic = request.topic,
                "refusing a push whose serialized APNs body exceeds Apple's cap"
            );
            return PushOutcome::TooLarge;
        };

        let url = format!("{}/3/device/{}", self.endpoint, request.device_token);
        let expiration =
            unix_now().saturating_add(u64::from(request.ttl_secs.unwrap_or(DEFAULT_TTL_SECS)));

        let (push_type, priority) = if request.ping {
            ("background", BACKGROUND_PRIORITY)
        } else {
            ("alert", ALERT_PRIORITY)
        };
        let response = self
            .http
            .post(url)
            .header("authorization", format!("bearer {}", self.token()))
            .header("apns-topic", request.topic)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority.to_string())
            .header("apns-expiration", expiration.to_string())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let outcome = classify_status(status);
                if !matches!(outcome, PushOutcome::Delivered) {
                    // Apple names the precise refusal only in the body's `reason` string —
                    // the status alone conflates a relay misconfiguration (wrong key,
                    // sandbox/production mismatch) with a dead device token. Logged for
                    // the operator, never forwarded: the instance's contract stays the
                    // coarse `PushOutcome`, for the blast-radius reasons on
                    // `classify_status`.
                    let reason = bounded_body(response).await;
                    tracing::warn!(
                        status,
                        reason = %reason,
                        topic = request.topic,
                        "APNs refused a notification"
                    );
                }
                outcome
            }
            Err(e) => {
                // The relay's own connectivity, never the instance's fault and never
                // reflected in detail — the instance is told only that Apple was not
                // reached, and the operator gets the reason in the log.
                tracing::warn!(error = %e, "APNs request failed");
                PushOutcome::ApnsError
            }
        }
    }

    /// The live provider token, minting a fresh one when the cached one has aged out.
    fn token(&self) -> String {
        self.token_at(Instant::now(), unix_now())
    }

    /// `token` against an explicit clock, so caching and refresh are testable without
    /// waiting fifty minutes.
    fn token_at(&self, now: Instant, issued_at: u64) -> String {
        let mut cached = self
            .token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(live) = cached
            .as_ref()
            .filter(|t| now.saturating_duration_since(t.minted_at) < TOKEN_LIFETIME)
        {
            return live.value.clone();
        }
        let value = sign_jwt(&self.signing_key, &self.key_id, &self.team_id, issued_at);
        *cached = Some(CachedToken {
            value: value.clone(),
            minted_at: now,
        });
        value
    }
}

/// Read at most [`MAX_REASON_BYTES`] of a refusal body, marking truncation.
///
/// Apple's `reason` bodies are a few dozen bytes of JSON, but the endpoint is
/// operator-configurable (that is the test seam) — so a misdirected endpoint or an
/// interposed proxy could answer a refusal with an arbitrarily large error page, and an
/// unbounded read would amplify every refusal into memory and log volume.
async fn bounded_body(mut response: reqwest::Response) -> String {
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Ok(Some(chunk)) = response.chunk().await {
        let remaining = MAX_REASON_BYTES - body.len();
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let mut text = String::from_utf8_lossy(&body).into_owned();
    if truncated {
        text.push_str(" [truncated]");
    }
    text
}

// ── Functional Core ───────────────────────────────────────────────────────

/// Apple's host for a given sandbox setting.
fn default_endpoint(sandbox: bool) -> &'static str {
    if sandbox {
        SANDBOX_ENDPOINT
    } else {
        PRODUCTION_ENDPOINT
    }
}

/// Seconds since the Unix epoch. A clock before the epoch is impossible in practice and
/// clamps to 0 rather than panicking.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Base64url without padding, the encoding every part of a JWS uses.
fn b64url(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// The APNs body, built from the shared protocol definition so the sender's padding
/// arithmetic is computed against exactly these bytes.
fn build_envelope(kid: u32, enc: &str, ct: &str) -> serde_json::Value {
    crate::protocol::apns_envelope(kid, enc, ct)
}

/// The ping-mode body: a content-free background wake and nothing else. No `ezpds` block,
/// no alert, no `mutable-content` — the relay carries only the fact that *something*
/// happened, which is the whole point of ping mode. Lives here rather than in the shared
/// protocol because the sender never has to model these bytes: there is no ciphertext to
/// pad, and every ping body is byte-identical.
fn ping_envelope() -> serde_json::Value {
    serde_json::json!({ "aps": { "content-available": 1 } })
}

/// Serialize the envelope, refusing anything Apple would reject on size.
///
/// The cap is on the **serialized body**, which is the same quantity the sender's padding
/// buckets are defined against — so a body that lands here oversized means the sender's
/// arithmetic and this check disagree, which is exactly what `tooLarge` reports.
fn serialize_within_cap(body: &serde_json::Value) -> Result<Vec<u8>, ()> {
    let bytes = serde_json::to_vec(body).map_err(|_| ())?;
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(());
    }
    Ok(bytes)
}

/// Mint an APNs provider token: an ES256 JWS over `{iss: team_id, iat}` with the key id in
/// the header. Apple wants no `exp` — the token's age *is* its expiry, which is why the
/// cache refreshes on a timer rather than on a claim.
fn sign_jwt(key: &SigningKey, key_id: &str, team_id: &str, issued_at: u64) -> String {
    // Built through serde rather than string interpolation: `key_id`/`team_id` are
    // operator-supplied, and a stray quote in either would otherwise emit a JWT that is
    // not JSON at all.
    let header = serde_json::json!({ "alg": "ES256", "kid": key_id });
    let claims = serde_json::json!({ "iss": team_id, "iat": issued_at });
    let signing_input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    // ES256's signature encoding is the raw r‖s pair, which is precisely what
    // `Signature::to_bytes` produces — no DER to unwrap.
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&signature.to_bytes()))
}

/// Translate an APNs HTTP status into the outcome the instance acts on.
///
/// This mapping is the whole back-channel: it is the only thing that tells a Custos
/// instance to delete a registration, to back off, or to try again later.
///
/// **Only 410 prunes.** `Unregistered` is a destructive instruction — on receipt the
/// instance deletes the device's registration, and that device goes dark until it
/// re-registers on next launch — and 410 is the one status that is unambiguous evidence
/// the token itself is dead.
///
/// Every other refusal reports `apnsError`, which is deliberately the conservative
/// reading of an ambiguous one. Apple returns **400** for `BadDeviceToken` *and* for
/// `BadTopic`, `DeviceTokenNotForTopic`, and `PayloadTooLarge`, separated only by a
/// `reason` string in the response body — so a 400 is as likely to mean "this relay is
/// misconfigured" as "this device is gone". Treating it as a prune would let one wrong
/// topic in the operator's allowlist, or one bad `.p8`, fan out a delete-your-registration
/// instruction to every enrolled instance at once; recovery would need every device on
/// every instance to re-register. Read as `apnsError` instead, the same misconfiguration
/// stays loudly broken and is fixed by correcting the relay. A permanently-bad token costs
/// a retry per notification until the device re-registers, which is the far cheaper way to
/// be wrong. **403** (a provider token Apple rejects) is the same shape of question with
/// the same answer: it is a fact about the relay's credentials, never about the device.
fn classify_status(status: u16) -> PushOutcome {
    match status {
        200 => PushOutcome::Delivered,
        410 => PushOutcome::Unregistered,
        // 400/403/404/413, 429, and every 5xx alike: Apple did not take the notification,
        // and nothing here is evidence about the device the instance should act on.
        _ => PushOutcome::ApnsError,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    /// A throwaway P-256 key written out in the PKCS#8 PEM shape Apple ships a `.p8` in.
    fn test_key_pem() -> String {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        secret
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode test key")
            .to_string()
    }

    /// A client with a throwaway key, pointed at `endpoint`. The `TempDir` holds the key
    /// file alive for the client's lifetime and must outlive it.
    pub(crate) fn client_for(endpoint: &str) -> (tempfile::TempDir, ApnsClient) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("apns.p8");
        std::fs::write(&key_path, test_key_pem()).expect("write key");

        let config = crate::config::ApnsConfig {
            key_path: Some(key_path),
            key_id: Some("KEYID12345".to_owned()),
            team_id: Some("TEAM123456".to_owned()),
            topics: Vec::new(),
            sandbox: false,
            endpoint: Some(endpoint.to_owned()),
        };
        let client = ApnsClient::new(&config)
            .expect("build client")
            .expect("credentials are present");
        (dir, client)
    }

    #[test]
    fn absent_credentials_yield_no_client_rather_than_an_error() {
        let built = ApnsClient::new(&crate::config::ApnsConfig::default()).expect("no error");
        assert!(
            built.is_none(),
            "a relay may legally run before its APNs key exists"
        );
    }

    #[test]
    fn a_malformed_key_is_refused_at_construction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("apns.p8");
        std::fs::write(&key_path, "not a pem file").expect("write");

        let config = crate::config::ApnsConfig {
            key_path: Some(key_path),
            key_id: Some("KEYID12345".to_owned()),
            team_id: Some("TEAM123456".to_owned()),
            ..crate::config::ApnsConfig::default()
        };
        assert!(
            matches!(
                ApnsClient::new(&config),
                Err(ApnsSetupError::ParseKey { .. })
            ),
            "a bad key must fail at startup, not on the first notification"
        );
    }

    /// The pruning policy, pinned. `Unregistered` deletes a registration on the instance,
    /// so widening the set of statuses that produce it is a decision that must be made
    /// deliberately — not one that can be reached by editing a match arm.
    #[test]
    fn only_a_410_is_read_as_a_dead_device() {
        assert_eq!(classify_status(200), PushOutcome::Delivered);
        assert_eq!(classify_status(410), PushOutcome::Unregistered);

        // 400 is `BadDeviceToken` *and* `BadTopic` *and* `PayloadTooLarge`, and 403 is a
        // provider-token fault: all of them are as likely to be a relay misconfiguration
        // as a dead device, and a misconfiguration read as a prune would tell every
        // enrolled instance to delete every registration it has.
        for status in [400, 403, 404, 413, 429, 500, 502, 503] {
            assert_eq!(
                classify_status(status),
                PushOutcome::ApnsError,
                "status {status} must not be read as evidence the device is gone"
            );
        }
    }

    #[test]
    fn the_envelope_carries_a_content_free_alert_beside_the_sealed_block() {
        let envelope = build_envelope(7, "ENC", "CT");
        assert_eq!(envelope["aps"]["alert"]["title"], "Custos");
        assert_eq!(envelope["aps"]["alert"]["body"], "Encrypted notification");
        assert_eq!(
            envelope["aps"]["mutable-content"], 1,
            "without mutable-content the extension never runs and the device shows the placeholder"
        );
        assert_eq!(envelope["ezpds"]["v"], 1);
        assert_eq!(envelope["ezpds"]["kid"], 7);
        assert_eq!(envelope["ezpds"]["enc"], "ENC");
        assert_eq!(envelope["ezpds"]["ct"], "CT");
    }

    /// The ping body is the metadata-minimizing contract: no ciphertext, no alert, nothing
    /// but the wake bit. An `ezpds` key here would put sealed material on a push whose whole
    /// point is that the relay forwards nothing of the notification at all.
    #[test]
    fn the_ping_envelope_carries_only_the_wake_bit() {
        let envelope = ping_envelope();
        assert_eq!(
            envelope,
            serde_json::json!({ "aps": { "content-available": 1 } }),
            "a ping body must be exactly the content-available wake and nothing else"
        );
    }

    /// The cap is inclusive: a body of exactly 4096 bytes is what a sender aiming at the
    /// largest padding bucket produces, and rejecting it would make the buckets unusable.
    #[test]
    fn the_size_cap_admits_exactly_four_kibibytes_and_refuses_one_more() {
        for (overhead, expectation) in [(0usize, true), (1, false)] {
            let base = serialize_within_cap(&build_envelope(1, "e", ""))
                .expect("an empty payload is small")
                .len();
            let filler = "c".repeat(MAX_PAYLOAD_BYTES - base + overhead);
            let body = build_envelope(1, "e", &filler);
            let serialized = serde_json::to_vec(&body).expect("serialize");
            assert_eq!(
                serialized.len(),
                MAX_PAYLOAD_BYTES + overhead,
                "test fixture must land exactly on the boundary"
            );
            assert_eq!(
                serialize_within_cap(&body).is_ok(),
                expectation,
                "a {}-byte body",
                serialized.len()
            );
        }
    }

    #[test]
    fn a_provider_token_is_three_signed_base64url_parts() {
        let (_dir, client) = client_for("http://127.0.0.1:1");
        let token = client.token_at(Instant::now(), 1_700_000_000);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWS is header.claims.signature: {token}");

        let header: serde_json::Value = serde_json::from_slice(
            &data_encoding::BASE64URL_NOPAD
                .decode(parts[0].as_bytes())
                .expect("header is base64url"),
        )
        .expect("header is JSON");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID12345");

        let claims: serde_json::Value = serde_json::from_slice(
            &data_encoding::BASE64URL_NOPAD
                .decode(parts[1].as_bytes())
                .expect("claims are base64url"),
        )
        .expect("claims are JSON");
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["iat"], 1_700_000_000);

        assert_eq!(
            data_encoding::BASE64URL_NOPAD
                .decode(parts[2].as_bytes())
                .expect("signature is base64url")
                .len(),
            64,
            "ES256 signs as a fixed 64-byte r‖s pair, not DER"
        );
    }

    /// Apple refuses a token refreshed sooner than twenty minutes, so reuse is not an
    /// optimisation — a relay that minted one per push would be rate-limited off.
    #[test]
    fn a_token_is_reused_until_it_ages_out_and_then_reminted() {
        let (_dir, client) = client_for("http://127.0.0.1:1");
        let start = Instant::now();

        let first = client.token_at(start, 1_700_000_000);
        assert_eq!(
            client.token_at(
                start + TOKEN_LIFETIME - Duration::from_secs(1),
                1_700_001_000
            ),
            first,
            "a token still inside its window must be reused verbatim"
        );

        let refreshed = client.token_at(start + TOKEN_LIFETIME, 1_700_003_000);
        assert_ne!(refreshed, first, "a token past its window must be reminted");

        let claims: serde_json::Value = serde_json::from_slice(
            &data_encoding::BASE64URL_NOPAD
                .decode(refreshed.split('.').nth(1).expect("claims").as_bytes())
                .expect("base64url"),
        )
        .expect("JSON");
        assert_eq!(
            claims["iat"], 1_700_003_000,
            "the reminted token must carry the fresh issue time"
        );
    }

    // ── Against a stand-in APNs ───────────────────────────────────────────
    //
    // The mock speaks HTTP/1.1 and the real thing speaks HTTP/2, and ALPN only bridges
    // that gap when reqwest is *built* with its `http2` feature — without it the client
    // never offers h2 and Apple (h2-only) refuses the connection, a failure this suite is
    // structurally blind to. So these tests prove the wiring — that Apple receives the
    // headers and body the design specifies, and that its answer reaches the instance as
    // the right outcome — while the protocol itself is pinned by the workspace reqwest
    // feature list in the root Cargo.toml.

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "0123456789abcdef";

    async fn mock_apns(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/3/device/{TOKEN}")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        server
    }

    fn request<'a>(ct: &'a str, ttl_secs: Option<u32>) -> PushRequest<'a> {
        PushRequest {
            device_token: TOKEN,
            topic: "org.obsign.identitywallet",
            kid: 3,
            enc: "ENCAPSULATED",
            ct,
            ttl_secs,
            ping: false,
        }
    }

    #[tokio::test]
    async fn a_delivered_push_carries_the_headers_and_envelope_apple_is_told_to_expect() {
        let server = mock_apns(200).await;
        let (_dir, client) = client_for(&server.uri());

        let before = unix_now();
        let outcome = client.send(&request("CIPHERTEXT", Some(90))).await;
        assert_eq!(outcome, PushOutcome::Delivered);

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1);
        let sent = &requests[0];

        let header = |name: &str| {
            sent.headers
                .get(name)
                .unwrap_or_else(|| panic!("missing {name} header"))
                .to_str()
                .expect("ascii header")
                .to_owned()
        };
        assert_eq!(
            header("apns-topic"),
            "org.obsign.identitywallet",
            "the topic comes from the handle row — one relay serves both official apps"
        );
        assert_eq!(header("apns-push-type"), "alert");
        assert_eq!(header("apns-priority"), "10");
        assert!(
            header("authorization").starts_with("bearer "),
            "provider tokens use the lowercase `bearer` scheme Apple documents"
        );

        let expiration: u64 = header("apns-expiration")
            .parse()
            .expect("numeric expiration");
        assert!(
            (before + 90..=unix_now() + 90).contains(&expiration),
            "apns-expiration must be now + ttlSecs, got {expiration}"
        );

        let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("JSON body");
        assert_eq!(body["aps"]["mutable-content"], 1);
        assert_eq!(body["ezpds"]["kid"], 3);
        assert_eq!(body["ezpds"]["enc"], "ENCAPSULATED");
        assert_eq!(
            body["ezpds"]["ct"], "CIPHERTEXT",
            "the sealed payload must reach Apple byte-for-byte as the instance sent it"
        );
    }

    /// Ping mode over the wire: Apple must receive a background push at priority 5 whose
    /// body carries no `ezpds` key — not even the ciphertext the sender handed over.
    #[tokio::test]
    async fn a_ping_push_is_a_content_free_background_push() {
        let server = mock_apns(200).await;
        let (_dir, client) = client_for(&server.uri());

        let outcome = client
            .send(&PushRequest {
                ping: true,
                ..request("CIPHERTEXT-THE-RELAY-MUST-DROP", Some(90))
            })
            .await;
        assert_eq!(outcome, PushOutcome::Delivered);

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1);
        let sent = &requests[0];

        assert_eq!(
            sent.headers["apns-push-type"].to_str().unwrap(),
            "background"
        );
        assert_eq!(
            sent.headers["apns-priority"].to_str().unwrap(),
            "5",
            "Apple rejects a background push at any priority but 5"
        );

        let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("JSON body");
        assert!(
            body.get("ezpds").is_none(),
            "a ping body must carry no ciphertext at all: {body}"
        );
        assert_eq!(body["aps"]["content-available"], 1);
        assert!(
            body["aps"].get("alert").is_none(),
            "a ping is silent by design; an alert would need content to show"
        );
    }

    #[tokio::test]
    async fn an_omitted_ttl_falls_back_to_the_default_expiry() {
        let server = mock_apns(200).await;
        let (_dir, client) = client_for(&server.uri());

        let before = unix_now();
        client.send(&request("CIPHERTEXT", None)).await;

        let requests = server.received_requests().await.expect("recorded requests");
        let expiration: u64 = requests[0].headers["apns-expiration"]
            .to_str()
            .expect("ascii")
            .parse()
            .expect("numeric");
        assert!(
            (before + u64::from(DEFAULT_TTL_SECS)..=unix_now() + u64::from(DEFAULT_TTL_SECS))
                .contains(&expiration),
            "a push with no ttlSecs must still get a bounded expiry, got {expiration}"
        );
    }

    /// The pruning back-channel. A 410 is the only way an instance learns a device token
    /// has died, so this mapping is what keeps registrations from accumulating forever.
    #[tokio::test]
    async fn a_410_reports_the_device_as_unregistered() {
        let server = mock_apns(410).await;
        let (_dir, client) = client_for(&server.uri());
        assert_eq!(
            client.send(&request("CIPHERTEXT", None)).await,
            PushOutcome::Unregistered
        );
    }

    #[tokio::test]
    async fn apple_side_failures_and_throttling_report_an_upstream_error() {
        for status in [429, 500, 503] {
            let server = mock_apns(status).await;
            let (_dir, client) = client_for(&server.uri());
            assert_eq!(
                client.send(&request("CIPHERTEXT", None)).await,
                PushOutcome::ApnsError,
                "status {status} is retryable upstream trouble, not a dead device"
            );
        }
    }

    /// The size check runs before the request is built, so an oversized payload never
    /// reaches Apple on the relay operator's credentials.
    #[tokio::test]
    async fn an_oversized_payload_is_refused_without_contacting_apple() {
        let server = mock_apns(200).await;
        let (_dir, client) = client_for(&server.uri());

        let overhead = serialize_within_cap(&build_envelope(3, "ENCAPSULATED", ""))
            .expect("empty payload")
            .len();
        let too_big = "c".repeat(MAX_PAYLOAD_BYTES - overhead + 1);

        assert_eq!(
            client.send(&request(&too_big, None)).await,
            PushOutcome::TooLarge
        );
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded requests")
                .is_empty(),
            "an oversized push must not be sent at all"
        );
    }

    /// A relay minting a provider token per push would be throttled off by Apple, so
    /// reuse across pushes is a correctness property, not an optimisation.
    #[tokio::test]
    async fn one_provider_token_is_reused_across_pushes() {
        let server = mock_apns(200).await;
        let (_dir, client) = client_for(&server.uri());

        for _ in 0..3 {
            client.send(&request("CIPHERTEXT", None)).await;
        }

        let requests = server.received_requests().await.expect("recorded requests");
        let tokens: std::collections::HashSet<&str> = requests
            .iter()
            .map(|r| r.headers["authorization"].to_str().expect("ascii"))
            .collect();
        assert_eq!(
            tokens.len(),
            1,
            "three pushes inside the token window must share one provider token"
        );
    }
}
