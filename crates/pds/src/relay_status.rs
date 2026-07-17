// pattern: Imperative Shell (fetch) wrapping a Functional Core (parse)
//
//! Client for `com.atproto.sync.getHostStatus` — asking an upstream relay/BGS what it knows about
//! this PDS: how far its cursor has advanced through our firehose, how many of our accounts it has
//! indexed, and the lifecycle status it assigns us. Backs `GET /v1/admin/relay-status`, the
//! operator's "is my server actually federating right now" readout.
//!
//! Because we *own* the PDS we skip the approximation a third-party observer must make: the
//! endpoint reads our exact sequencer head from `firehose.current_seq()` rather than probing
//! `subscribeRepos` in a timed window. This module only fetches the *relay's* side of the compare.
//!
//! **Total, never fatal.** Every failure path — transport error, timeout, non-2xx, unparseable
//! body — becomes a [`RelayReport`] variant rather than an error, so the admin readout always
//! renders the literal truth of what the relay said (or that it said nothing).

use serde::Deserialize;

/// The relay's answer for our hostname. Every field but `hostname` is optional in the lexicon
/// (`com.atproto.sync.getHostStatus`): a relay that has our host row but has not processed any of
/// our events yet reports no `seq`, and so on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStatus {
    /// The relay's cursor into *our* firehose seq-space — the last seq it consumed from us. The
    /// lexicon notes this may lag the relay's live cursor (a persisted, not in-memory, value).
    pub seq: Option<u64>,
    /// How many of our accounts the relay has indexed.
    pub account_count: Option<u64>,
    /// Lifecycle status the relay assigns our host (`active`/`idle`/`offline`/`throttled`/
    /// `banned`). Kept as the raw string, not an enum, so an unknown value from a newer relay is
    /// reported verbatim rather than dropped — this readout reports literal truth.
    pub status: Option<String>,
}

/// The outcome of asking a relay about our host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReport {
    /// The relay answered with a host-status body.
    Found(HostStatus),
    /// The relay answered but has no record of this host — it has never crawled us
    /// (`HostNotFound`). Distinct from [`Unreachable`](Self::Unreachable): the relay is up, it
    /// simply is not indexing us yet.
    NotFound,
    /// The relay could not be reached, or returned an error/unparseable response. Carries a short
    /// human reason for the operator readout.
    Unreachable(String),
}

/// The wire shape of a `getHostStatus` success body. `hostname` is required by the lexicon but we
/// ignore it (we asked about our own host); every other field is optional.
#[derive(Deserialize)]
struct HostStatusBody {
    #[serde(default)]
    seq: Option<i64>,
    #[serde(default, rename = "accountCount")]
    account_count: Option<i64>,
    #[serde(default)]
    status: Option<String>,
}

/// The wire shape of an XRPC error body (`{ "error": "HostNotFound", "message": "…" }`).
#[derive(Deserialize)]
struct XrpcError {
    error: Option<String>,
}

/// Parse a `getHostStatus` success body into a [`HostStatus`].
///
/// Signed wire integers are clamped to `u64`: a relay should never send a negative `seq`/count, so
/// a negative is coerced to 0 rather than rejected — one odd field must not fail the whole readout.
fn parse_host_status(body: &[u8]) -> Result<HostStatus, serde_json::Error> {
    let parsed: HostStatusBody = serde_json::from_slice(body)?;
    Ok(HostStatus {
        seq: parsed.seq.map(|s| s.max(0) as u64),
        account_count: parsed.account_count.map(|c| c.max(0) as u64),
        status: parsed.status,
    })
}

/// Pull the XRPC `error` name out of a 4xx body, if the body is a well-formed XRPC error.
fn parse_xrpc_error_name(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<XrpcError>(body)
        .ok()
        .and_then(|e| e.error)
}

/// Classify a transport-level failure into a short operator-facing reason.
fn transport_reason(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "relay did not respond in time".to_string()
    } else if e.is_connect() {
        "could not connect to the relay".to_string()
    } else {
        "could not reach the relay".to_string()
    }
}

/// GET `com.atproto.sync.getHostStatus?hostname=<hostname>` from one relay base URL.
///
/// `relay_base_url` is a normalised relay base (scheme + authority, no trailing slash); `hostname`
/// is the bare host the relay knows us by (the same value the crawler advertises via
/// `requestCrawl`). Best-effort: every failure becomes a [`RelayReport`], never an `Err`.
pub async fn fetch_host_status(
    client: &reqwest::Client,
    relay_base_url: &str,
    hostname: &str,
) -> RelayReport {
    let endpoint = format!("{relay_base_url}/xrpc/com.atproto.sync.getHostStatus");
    // Build the URL with the hostname as a percent-encoded query param. A malformed relay base
    // (from config) surfaces as unreachable rather than panicking.
    let url = match reqwest::Url::parse_with_params(&endpoint, &[("hostname", hostname)]) {
        Ok(url) => url,
        Err(_) => return RelayReport::Unreachable("relay URL is not valid".to_string()),
    };
    let resp = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => return RelayReport::Unreachable(transport_reason(&e)),
    };

    let status = resp.status();
    if status.is_success() {
        return match resp.bytes().await {
            Ok(bytes) => match parse_host_status(&bytes) {
                Ok(host_status) => RelayReport::Found(host_status),
                Err(_) => {
                    RelayReport::Unreachable("relay returned an unreadable host-status body".into())
                }
            },
            Err(_) => RelayReport::Unreachable("relay response body could not be read".into()),
        };
    }

    if status.is_client_error() {
        // Reachable relay, client-error response. `HostNotFound` means it has simply never crawled
        // us — a normal "not federating yet" state, not an outage. Any other 4xx is a real problem
        // worth surfacing verbatim.
        let error_name = resp
            .bytes()
            .await
            .ok()
            .as_deref()
            .and_then(parse_xrpc_error_name);
        return match error_name.as_deref() {
            Some("HostNotFound") => RelayReport::NotFound,
            Some(name) => RelayReport::Unreachable(format!("relay rejected the query: {name}")),
            None => RelayReport::Unreachable(format!("relay returned HTTP {}", status.as_u16())),
        };
    }

    RelayReport::Unreachable(format!("relay returned HTTP {}", status.as_u16()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_reads_all_fields() {
        let hs = parse_host_status(
            br#"{"hostname":"pds.example.com","seq":42,"accountCount":3,"status":"active"}"#,
        )
        .unwrap();
        assert_eq!(
            hs,
            HostStatus {
                seq: Some(42),
                account_count: Some(3),
                status: Some("active".to_string()),
            }
        );
    }

    #[test]
    fn parse_tolerates_missing_optional_fields() {
        // A relay that has our host row but processed no events yet: only `hostname`.
        let hs = parse_host_status(br#"{"hostname":"pds.example.com"}"#).unwrap();
        assert_eq!(
            hs,
            HostStatus {
                seq: None,
                account_count: None,
                status: None,
            }
        );
    }

    #[test]
    fn parse_clamps_negative_integers_to_zero() {
        let hs = parse_host_status(br#"{"hostname":"h","seq":-1,"accountCount":-5}"#).unwrap();
        assert_eq!(hs.seq, Some(0));
        assert_eq!(hs.account_count, Some(0));
    }

    #[test]
    fn parse_preserves_unknown_status_verbatim() {
        // A newer relay could report a status value we don't know; report it, don't drop it.
        let hs = parse_host_status(br#"{"hostname":"h","status":"quarantined"}"#).unwrap();
        assert_eq!(hs.status, Some("quarantined".to_string()));
    }

    #[test]
    fn xrpc_error_name_is_extracted() {
        assert_eq!(
            parse_xrpc_error_name(br#"{"error":"HostNotFound","message":"nope"}"#),
            Some("HostNotFound".to_string())
        );
        assert_eq!(parse_xrpc_error_name(b"not json"), None);
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("test http client")
    }

    #[tokio::test]
    async fn fetch_returns_found_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getHostStatus"))
            .and(query_param("hostname", "pds.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hostname": "pds.example.com",
                "seq": 100,
                "accountCount": 2,
                "status": "active"
            })))
            .mount(&server)
            .await;

        let report = fetch_host_status(&client(), &server.uri(), "pds.example.com").await;
        assert_eq!(
            report,
            RelayReport::Found(HostStatus {
                seq: Some(100),
                account_count: Some(2),
                status: Some("active".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn fetch_returns_not_found_on_host_not_found_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getHostStatus"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "HostNotFound",
                "message": "host not found"
            })))
            .mount(&server)
            .await;

        let report = fetch_host_status(&client(), &server.uri(), "unknown.example.com").await;
        assert_eq!(report, RelayReport::NotFound);
    }

    #[tokio::test]
    async fn fetch_returns_unreachable_on_other_client_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getHostStatus"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "InvalidRequest",
                "message": "bad hostname"
            })))
            .mount(&server)
            .await;

        let report = fetch_host_status(&client(), &server.uri(), "bad").await;
        assert!(
            matches!(report, RelayReport::Unreachable(reason) if reason.contains("InvalidRequest")),
            "a non-HostNotFound 4xx should surface verbatim, not read as NotFound"
        );
    }

    #[tokio::test]
    async fn fetch_returns_unreachable_on_server_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.sync.getHostStatus"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let report = fetch_host_status(&client(), &server.uri(), "h").await;
        assert!(matches!(report, RelayReport::Unreachable(reason) if reason.contains("503")));
    }

    #[tokio::test]
    async fn fetch_returns_unreachable_when_relay_is_down() {
        // Nothing listening on this port → connect error, not a panic.
        let report = fetch_host_status(&client(), "http://127.0.0.1:1", "h").await;
        assert!(matches!(report, RelayReport::Unreachable(_)));
    }
}
