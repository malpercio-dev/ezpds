// pattern: Mixed (unavoidable)
//
// Minimal S3-compatible object client for the blob mirror: AWS Signature Version 4 request
// signing (pure helpers, pinned against the worked examples in the AWS documentation) around
// a small Imperative Shell of four operations — put/get/delete object and paginated
// ListObjectsV2. Hand-rolled rather than pulling an S3 SDK: the mirror needs exactly these
// four calls over bytes it already holds in memory, and the workspace's dependency-hygiene
// posture (single-major guard-bans, reviewed license surface) prices a full SDK tree far
// above ~300 lines of well-specified signing code.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum S3Error {
    #[error("invalid endpoint URL: {0}")]
    Endpoint(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("unexpected status {status} from {operation}: {body}")]
    Status {
        operation: &'static str,
        status: u16,
        body: String,
    },
    #[error("unparseable ListObjectsV2 response: {0}")]
    ListParse(String),
}

/// Connection parameters for one bucket. `secret_access_key` is held as a plain `String`
/// here because every signing pass reads it; the config layer's `Sensitive` wrapper already
/// keeps it out of `Debug` output upstream, and this struct deliberately derives nothing.
pub struct S3Client {
    http: reqwest::Client,
    /// Scheme + authority of the configured endpoint (no trailing slash, no path).
    endpoint_scheme: String,
    endpoint_host: String,
    bucket: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    force_path_style: bool,
}

impl S3Client {
    /// Build a client for one bucket. Fails only on an unparseable endpoint URL.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        access_key_id: &str,
        secret_access_key: &str,
        force_path_style: bool,
    ) -> Result<Self, S3Error> {
        let url = url::Url::parse(endpoint).map_err(|e| S3Error::Endpoint(e.to_string()))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(S3Error::Endpoint(format!(
                "scheme must be http or https, got {:?}",
                url.scheme()
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| S3Error::Endpoint("endpoint has no host".to_string()))?;
        let endpoint_host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        // Blobs are up to 50 MiB; give a single transfer minutes, not the 10 s the general
        // API client uses. The sweep runs in a background task, so a slow transfer stalls
        // nothing but its own pass.
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()?;
        Ok(Self {
            http,
            endpoint_scheme: url.scheme().to_string(),
            endpoint_host,
            bucket: bucket.to_string(),
            region: region.to_string(),
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_access_key.to_string(),
            force_path_style,
        })
    }

    /// The `Host` header value and URI path prefix for this bucket, per addressing style.
    fn host_and_base_path(&self) -> (String, String) {
        if self.force_path_style {
            (self.endpoint_host.clone(), format!("/{}", self.bucket))
        } else {
            (
                format!("{}.{}", self.bucket, self.endpoint_host),
                String::new(),
            )
        }
    }

    /// Store `body` at `key` with the given Content-Type. Overwrites are fine — the mirror
    /// only ever writes content-addressed bytes, so a re-put is byte-identical.
    pub async fn put_object(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), S3Error> {
        let response = self.send("PUT", key, &[], body, Some(content_type)).await?;
        expect_success("PUT object", response).await.map(|_| ())
    }

    /// Fetch the object at `key`. `Ok(None)` when the key does not exist.
    pub async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, S3Error> {
        let response = self.send("GET", key, &[], Vec::new(), None).await?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let response = expect_success("GET object", response).await?;
        Ok(Some(response.bytes().await?.to_vec()))
    }

    /// Delete the object at `key`. Deleting a missing key is a success (S3 semantics).
    pub async fn delete_object(&self, key: &str) -> Result<(), S3Error> {
        let response = self.send("DELETE", key, &[], Vec::new(), None).await?;
        // S3 returns 204 for deletes, including of keys that never existed.
        if response.status().as_u16() == 404 {
            return Ok(());
        }
        expect_success("DELETE object", response).await.map(|_| ())
    }

    /// List every key under `prefix`, following ListObjectsV2 continuation tokens until the
    /// listing is complete.
    pub async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, S3Error> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut query: Vec<(String, String)> = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.to_string()),
            ];
            if let Some(token) = &continuation {
                query.push(("continuation-token".to_string(), token.clone()));
            }
            let response = self.send("GET", "", &query, Vec::new(), None).await?;
            let response = expect_success("ListObjectsV2", response).await?;
            let body = response.text().await?;
            let page = parse_list_response(&body)?;
            keys.extend(page.keys);
            match page.next_continuation_token {
                Some(token) => continuation = Some(token),
                None => return Ok(keys),
            }
        }
    }

    /// Build, sign, and send one request. `key` is the object key ("" for a bucket-level
    /// operation); `query` is the unencoded query pairs.
    async fn send(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<reqwest::Response, S3Error> {
        let (host, base_path) = self.host_and_base_path();
        // Canonical URI: each path segment URI-encoded, '/' preserved. Bucket names and CID
        // keys contain no reserved characters in practice, but encode anyway so an unusual
        // key prefix cannot desynchronise the signature from the request line.
        let path = format!("{base_path}/{key}");
        let canonical_uri: String = path
            .split('/')
            .map(uri_encode)
            .collect::<Vec<_>>()
            .join("/");
        let canonical_query = canonical_query_string(query);

        let payload_hash = hex(&Sha256::digest(&body));
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();

        let auth = SigningInput {
            method,
            canonical_uri: &canonical_uri,
            canonical_query: &canonical_query,
            host: &host,
            payload_hash: &payload_hash,
            amz_date: &amz_date,
            date: &date,
            region: &self.region,
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
        }
        .authorization_header();

        let url = format!(
            "{}://{}{}{}",
            self.endpoint_scheme,
            host,
            canonical_uri,
            if canonical_query.is_empty() {
                String::new()
            } else {
                format!("?{canonical_query}")
            }
        );

        let mut request = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).expect("static method token"),
                &url,
            )
            .header("Host", &host)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", auth);
        if let Some(ct) = content_type {
            request = request.header("Content-Type", ct);
        }
        if !body.is_empty() {
            request = request.body(body);
        }
        Ok(request.send().await?)
    }
}

/// Turn a non-2xx response into an [`S3Error::Status`] carrying a truncated body for logs.
async fn expect_success(
    operation: &'static str,
    response: reqwest::Response,
) -> Result<reqwest::Response, S3Error> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let mut body = response.text().await.unwrap_or_default();
    body.truncate(512);
    Err(S3Error::Status {
        operation,
        status,
        body,
    })
}

/// The pure inputs to one SigV4 signature. Split out so the signing math is testable against
/// the AWS documentation's worked examples with fixed dates and keys.
struct SigningInput<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    canonical_query: &'a str,
    host: &'a str,
    payload_hash: &'a str,
    amz_date: &'a str,
    date: &'a str,
    region: &'a str,
    access_key_id: &'a str,
    secret_access_key: &'a str,
}

/// The fixed signed-header set: `host` plus the two required `x-amz-*` headers. Content-Type
/// is deliberately sent unsigned — SigV4 requires signing only `host` and `x-amz-*` headers,
/// and a fixed set keeps the canonical form independent of which optional headers a call adds.
const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

impl SigningInput<'_> {
    fn canonical_request(&self) -> String {
        format!(
            "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\n{}\n{}",
            self.method,
            self.canonical_uri,
            self.canonical_query,
            self.host,
            self.payload_hash,
            self.amz_date,
            SIGNED_HEADERS,
            self.payload_hash,
        )
    }

    fn scope(&self) -> String {
        format!("{}/{}/s3/aws4_request", self.date, self.region)
    }

    fn string_to_sign(&self) -> String {
        format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.amz_date,
            self.scope(),
            hex(&Sha256::digest(self.canonical_request().as_bytes())),
        )
    }

    fn signature(&self) -> String {
        let key = hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(
                    &hmac_sha256(
                        format!("AWS4{}", self.secret_access_key).as_bytes(),
                        self.date.as_bytes(),
                    ),
                    self.region.as_bytes(),
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        hex(&hmac_sha256(&key, self.string_to_sign().as_bytes()))
    }

    fn authorization_header(&self) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id,
            self.scope(),
            SIGNED_HEADERS,
            self.signature(),
        )
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SigV4 URI encoding: RFC 3986 unreserved characters (`A–Z a–z 0–9 - . _ ~`) pass through,
/// everything else is `%XX` (uppercase hex) per UTF-8 byte. Used for both path segments and
/// query keys/values (the caller keeps `/` out by encoding per segment).
fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The canonical (and actual — the request uses the same string) query string: pairs
/// URI-encoded then sorted by encoded key.
fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// One page of a ListObjectsV2 response.
struct ListPage {
    keys: Vec<String>,
    next_continuation_token: Option<String>,
}

/// Extract `<Key>` values and the continuation token from a ListObjectsV2 XML body.
///
/// Deliberately a text scan, not an XML parser: the response grammar is flat and fixed, the
/// values we extract (content-addressed keys, an opaque token) are entity-unescaped below,
/// and the workspace carries no XML dependency. A body without a `<ListBucketResult` root is
/// rejected so an HTML error page can never parse as an empty listing.
fn parse_list_response(body: &str) -> Result<ListPage, S3Error> {
    if !body.contains("<ListBucketResult") {
        return Err(S3Error::ListParse(format!(
            "missing ListBucketResult root in: {}",
            &body[..body.len().min(256)]
        )));
    }
    let keys = extract_all(body, "Key").map(|k| xml_unescape(&k)).collect();
    // IsTruncated + NextContinuationToken travel together; trust the token's presence.
    let next_continuation_token = if body.contains("<IsTruncated>true</IsTruncated>") {
        extract_all(body, "NextContinuationToken")
            .next()
            .map(|t| xml_unescape(&t))
    } else {
        None
    };
    Ok(ListPage {
        keys,
        next_continuation_token,
    })
}

/// Iterate the text content of every `<tag>…</tag>` occurrence in `body`.
fn extract_all<'a>(body: &'a str, tag: &'a str) -> impl Iterator<Item = String> + 'a {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = body;
    std::iter::from_fn(move || {
        let start = rest.find(&open)? + open.len();
        let end = rest[start..].find(&close)? + start;
        let value = rest[start..end].to_string();
        rest = &rest[end + close.len()..];
        Some(value)
    })
}

/// Undo the five standard XML entity escapes (`&amp;` last, so `&amp;lt;` round-trips).
fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of an empty payload — the `x-amz-content-sha256` of every body-less request.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The AWS SigV4 documentation's worked "GET Object" example (examplebucket, 2013-05-24).
    /// The canonical form differs from ours only by its extra signed `range` header, so the
    /// example is reproduced literally rather than through [`SigningInput`]; it pins the
    /// derivation chain (signing key, string-to-sign, hex) that `SigningInput` shares.
    #[test]
    fn sigv4_signing_key_matches_aws_documentation_example() {
        let canonical_request = format!(
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n\
             x-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:20130524T000000Z\n\n\
             host;range;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let key = hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(
                    &hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", b"20130524"),
                    b"us-east-1",
                ),
                b"s3",
            ),
            b"aws4_request",
        );
        assert_eq!(
            hex(&hmac_sha256(&key, string_to_sign.as_bytes())),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        );
    }

    /// The AWS documentation's "GET Bucket Lifecycle"-family list example
    /// (`?max-keys=2&prefix=J`) uses exactly our signed-header set, so it exercises
    /// [`SigningInput`] end to end.
    #[test]
    fn sigv4_list_signature_matches_aws_documentation_example() {
        let input = SigningInput {
            method: "GET",
            canonical_uri: "/",
            canonical_query: "max-keys=2&prefix=J",
            host: "examplebucket.s3.amazonaws.com",
            payload_hash: EMPTY_SHA256,
            amz_date: "20130524T000000Z",
            date: "20130524",
            region: "us-east-1",
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        assert_eq!(
            input.signature(),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        );
        assert!(input.authorization_header().starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        ));
    }

    #[test]
    fn uri_encode_passes_unreserved_and_encodes_the_rest() {
        assert_eq!(uri_encode("bafkrei-abc_123.~"), "bafkrei-abc_123.~");
        assert_eq!(uri_encode("a b+c/d"), "a%20b%2Bc%2Fd");
        assert_eq!(uri_encode("token=="), "token%3D%3D");
    }

    #[test]
    fn canonical_query_string_sorts_by_encoded_key() {
        let query = vec![
            ("prefix".to_string(), "blobs/".to_string()),
            ("list-type".to_string(), "2".to_string()),
        ];
        assert_eq!(
            canonical_query_string(&query),
            "list-type=2&prefix=blobs%2F"
        );
    }

    #[test]
    fn parse_list_response_extracts_keys_and_token() {
        let body = r#"<?xml version="1.0"?>
            <ListBucketResult>
              <IsTruncated>true</IsTruncated>
              <Contents><Key>blobs/bafkreiaaa</Key><Size>1</Size></Contents>
              <Contents><Key>blobs/bafkreibbb</Key><Size>2</Size></Contents>
              <NextContinuationToken>1ueGcxLPRx1Tr&amp;fV==</NextContinuationToken>
            </ListBucketResult>"#;
        let page = parse_list_response(body).unwrap();
        assert_eq!(page.keys, vec!["blobs/bafkreiaaa", "blobs/bafkreibbb"]);
        assert_eq!(
            page.next_continuation_token.as_deref(),
            Some("1ueGcxLPRx1Tr&fV==")
        );
    }

    #[test]
    fn parse_list_response_final_page_has_no_token() {
        let body = "<ListBucketResult><IsTruncated>false</IsTruncated>\
                    <Contents><Key>blobs/bafkreiccc</Key></Contents></ListBucketResult>";
        let page = parse_list_response(body).unwrap();
        assert_eq!(page.keys, vec!["blobs/bafkreiccc"]);
        assert!(page.next_continuation_token.is_none());
    }

    #[test]
    fn parse_list_response_rejects_non_listing_bodies() {
        assert!(parse_list_response("<html>502 Bad Gateway</html>").is_err());
    }

    #[test]
    fn client_addressing_styles() {
        let virtual_hosted = S3Client::new(
            "https://t3.storage.dev",
            "custos-blobs",
            "auto",
            "AKIA",
            "secret",
            false,
        )
        .unwrap();
        assert_eq!(
            virtual_hosted.host_and_base_path(),
            ("custos-blobs.t3.storage.dev".to_string(), String::new())
        );

        let path_style = S3Client::new(
            "http://127.0.0.1:9000",
            "custos-blobs",
            "auto",
            "AKIA",
            "secret",
            true,
        )
        .unwrap();
        assert_eq!(
            path_style.host_and_base_path(),
            ("127.0.0.1:9000".to_string(), "/custos-blobs".to_string())
        );
    }

    #[test]
    fn client_rejects_bad_endpoints() {
        assert!(S3Client::new("not a url", "b", "auto", "a", "s", true).is_err());
        assert!(S3Client::new("ftp://example.com", "b", "auto", "a", "s", true).is_err());
    }
}
