// pattern: Imperative Shell
//
// DNS abstractions for handle management.
//
// DnsProvider — manages DNS records for handles:
//   - create_record: called when handles are registered (POST /v1/handles).
//   - delete_record: called when handles are removed (DELETE /v1/handles/:handle).
//   For v0.1, AppState carries `dns_provider: None`; operators manage DNS manually.
//   Real provider implementations (Cloudflare, Route53) are wired in when configured.
//
// TxtResolver — resolves DNS TXT records for handle lookup fallback
//   (GET /xrpc/com.atproto.identity.resolveHandle).
//   HickoryTxtResolver is the production implementation; tests inject mocks.

use std::future::Future;
use std::pin::Pin;

/// Error returned by a [`DnsProvider`] operation.
#[derive(Debug, thiserror::Error)]
#[error("DNS provider error: {0}")]
pub struct DnsError(pub String);

/// Abstraction over DNS TXT record resolution.
///
/// Used by `resolveHandle` to perform the DNS-based handle fallback lookup.
/// `AppState.txt_resolver` holds `None` when DNS resolution is not needed (tests
/// exercising only the local-DB path, or configurations without DNS fallback).
///
/// Object-safe: uses `Pin<Box<dyn Future>>` so `dyn TxtResolver` works with `Arc`.
pub trait TxtResolver: Send + Sync {
    /// Look up TXT records for `name` (e.g. `"_atproto.alice.example.com"`).
    ///
    /// Returns the string values from all TXT records, or an empty vec if the
    /// name does not exist. The caller is responsible for filtering by prefix
    /// (e.g. `did=`).
    fn txt_lookup<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>>;
}

/// Production [`TxtResolver`] backed by `hickory-resolver` using the system DNS config.
pub struct HickoryTxtResolver {
    inner: hickory_resolver::TokioResolver,
}

impl HickoryTxtResolver {
    /// Create a resolver using system `/etc/resolv.conf` (or platform equivalent).
    pub fn from_system_conf() -> anyhow::Result<Self> {
        Ok(Self {
            inner: hickory_resolver::Resolver::builder_tokio()
                .map_err(|e| anyhow::anyhow!("failed to read system DNS config: {e}"))?
                .build()
                .map_err(|e| anyhow::anyhow!("failed to build DNS resolver: {e}"))?,
        })
    }
}

impl TxtResolver for HickoryTxtResolver {
    fn txt_lookup<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let lookup = match self.inner.txt_lookup(name).await {
                Ok(l) => l,
                // NXDOMAIN / NODATA — the name doesn't exist; this is the normal case for
                // handles that are not registered in DNS. Treat as empty, not as an error,
                // so the resolver falls through to the next step (HTTP well-known → 404).
                Err(e) if e.is_no_records_found() => return Ok(vec![]),
                Err(e) => return Err(DnsError(e.to_string())),
            };

            let mut results = Vec::new();
            for record in lookup.answers() {
                let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
                    continue;
                };
                if let Some(combined) = combine_txt_chunks(&txt.txt_data, name) {
                    results.push(combined);
                }
            }
            Ok(results)
        })
    }
}

/// Abstraction over DNS record management.
///
/// Object-safe: uses `Pin<Box<dyn Future>>` so `dyn DnsProvider` works with `Arc`.
pub trait DnsProvider: Send + Sync {
    /// Create a DNS record pointing `name` (a subdomain label, e.g. `"alice"`) to
    /// `target` (an IP address or hostname the PDS is reachable at).
    ///
    /// The provider is responsible for constructing the full qualified name from
    /// `name` and its configured zone.
    fn create_record<'a>(
        &'a self,
        name: &'a str,
        target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DnsError>> + Send + 'a>>;

    /// Delete the DNS record for `name` (a subdomain label, e.g. `"alice"`).
    ///
    /// Called when a handle is deleted. The provider is responsible for locating
    /// and removing the record within its configured zone.
    ///
    /// Callers are responsible for extracting the label portion from the full handle
    /// before invoking this method (e.g. pass `"alice"`, not `"alice.example.com"`).
    fn delete_record<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DnsError>> + Send + 'a>>;
}

/// Concatenate a single TXT record's character-string chunks into its full value.
///
/// RFC 1035 splits a TXT value longer than 255 bytes across multiple chunks; clients must
/// join them to recover the original string. `name` is only used for the non-UTF-8 warning.
/// Returns `None` if every chunk was empty or invalid.
fn combine_txt_chunks(chunks: &[Box<[u8]>], name: &str) -> Option<String> {
    let mut combined = String::new();
    for part in chunks.iter() {
        match std::str::from_utf8(part) {
            Ok(s) => combined.push_str(s),
            Err(_) => {
                tracing::warn!(name, "TXT record contains non-UTF-8 bytes; skipping part");
            }
        }
    }
    (!combined.is_empty()).then_some(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(bytes: &[u8]) -> Box<[u8]> {
        bytes.to_vec().into_boxed_slice()
    }

    #[test]
    fn combine_txt_chunks_joins_multiple_chunks_of_one_record() {
        let chunks = [chunk(b"did=did:plc:abc"), chunk(b"defghijklmnop")];
        assert_eq!(
            combine_txt_chunks(&chunks, "_atproto.alice.example.com"),
            Some("did=did:plc:abcdefghijklmnop".to_string())
        );
    }

    #[test]
    fn combine_txt_chunks_single_chunk() {
        let chunks = [chunk(b"did=did:plc:abc")];
        assert_eq!(
            combine_txt_chunks(&chunks, "_atproto.alice.example.com"),
            Some("did=did:plc:abc".to_string())
        );
    }

    #[test]
    fn combine_txt_chunks_skips_non_utf8_and_keeps_valid_parts() {
        let chunks = [
            chunk(b"did=did:plc:abc"),
            chunk(&[0xff, 0xfe]),
            chunk(b"xyz"),
        ];
        assert_eq!(
            combine_txt_chunks(&chunks, "_atproto.alice.example.com"),
            Some("did=did:plc:abcxyz".to_string())
        );
    }

    #[test]
    fn combine_txt_chunks_all_invalid_returns_none() {
        let chunks = [chunk(&[0xff, 0xfe])];
        assert_eq!(
            combine_txt_chunks(&chunks, "_atproto.alice.example.com"),
            None
        );
    }
}
