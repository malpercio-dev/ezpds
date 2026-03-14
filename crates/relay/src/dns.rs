// DNS provider abstraction for subdomain record management.
//
// Implementations create DNS records when handles are registered (POST /v1/handles).
// For v0.1, AppState carries `dns_provider: None` and no records are created
// automatically — operators manage DNS manually.
//
// MM-142 wires in real provider implementations (Cloudflare, Route53).

use std::future::Future;
use std::pin::Pin;

/// Error returned by a [`DnsProvider`] operation.
#[derive(Debug, thiserror::Error)]
#[error("DNS provider error: {0}")]
pub struct DnsError(pub String);

/// Abstraction over DNS record management.
///
/// Object-safe: uses `Pin<Box<dyn Future>>` so `dyn DnsProvider` works with `Arc`.
pub trait DnsProvider: Send + Sync {
    /// Create a DNS record pointing `name` (a subdomain label, e.g. `"alice"`) to
    /// `target` (an IP address or hostname the relay is reachable at).
    ///
    /// The provider is responsible for constructing the full qualified name from
    /// `name` and its configured zone.
    fn create_record<'a>(
        &'a self,
        name: &'a str,
        target: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DnsError>> + Send + 'a>>;
}
