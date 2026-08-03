// pattern: Imperative Shell
//
// Gathers: the `custos` extension of a host's describeServer response
// Processes: normalizes the host key and answers capability questions
// Returns: a per-host capability set, cached for the process lifetime

//! What the identity's host can do, cached per host.
//!
//! Obsign works against any spec-compliant PDS. Most of what it offers — the claim
//! ceremony, PLC monitoring, the recovery override, repo and media backup, endpoint
//! repair — is standard AT Protocol and needs nothing from the host but conformance. A
//! smaller set of features needs Custos, and until now the wallet discovered that by
//! calling a `/v1/*` route and interpreting the failure, which cannot distinguish "this
//! host does not offer that" from "that host is having a bad day".
//!
//! Custos answers the question directly: `com.atproto.server.describeServer` carries a
//! `custos` object naming the capabilities that deployment actually offers. This module
//! is the wallet's reader for it.
//!
//! **Absence is not an error.** The reference PDS and rsky-pds return strictly the
//! lexicon fields; millipds adds a top-level `version` with unrelated semantics. A
//! response with no `custos` object yields [`ServerCapabilities::none`] — no capabilities,
//! standard-lexicon behavior — which is the correct reading for every implementation that
//! is not Custos, and for a Custos deployment running with a capability switched off.
//!
//! **A gate reads as a feature question, never a vendor question.** There is deliberately
//! no `is_custos()`: a self-hosted Custos may run without escrow, and a future
//! implementation could adopt a single capability. Ask [`ServerCapabilities::has`].
//!
//! **Cache shape.** A process-global per-host map (`OnceLock<Mutex<HashMap>>`, the
//! unit-of-global shape `IdentityStore` uses) keyed by a trailing-slash/case-normalized
//! host. Every successful `PdsClient::describe_server` calls [`record`], so migration
//! prepare, handle change, consent, and sovereign login all warm it for free; [`probe`] is
//! the cached read that describes the host only when nothing is known. A *failed* probe
//! yields [`ServerCapabilities::none`] and is not cached — see [`probe`] — and [`forget`]
//! drops a host when the user re-points the wallet.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use crate::pds_client::{CustosExtension, PdsClient};

/// The capability names Custos advertises. Wire contract — these strings are matched
/// verbatim against `custos.capabilities`, and the server's `crates/pds/src/capabilities.rs`
/// is their source of truth.
pub mod capability {
    /// Custos-native identity creation (mobile signup + client-authored did:plc genesis).
    pub const CREATE_CEREMONY: &str = "createCeremony";
    /// Server-held encrypted Shamir Share 2, released through the recovery gate.
    pub const ESCROW: &str = "escrow";
    /// Passwordless full-access sessions from a rotation-key-signed proof.
    pub const SOVEREIGN_SESSIONS: &str = "sovereignSessions";
    /// The auth.md agent registration + owner-confirmed claim ceremony.
    pub const AGENTS: &str = "agents";
    /// Device-key-signed approval of an OAuth authorization from the wallet.
    pub const WALLET_CONSENT: &str = "walletConsent";
    /// Custos-managed hosting of an account's did:web document.
    pub const DID_WEB_HOSTING: &str = "didWebHosting";
    /// An account can be created with no password at all.
    pub const OPTIONAL_PASSWORD: &str = "optionalPassword";
    /// `deleteAccount` accepts a device-key-signed proof in place of the account password.
    pub const WALLET_ACCOUNT_DELETE: &str = "walletAccountDelete";
}

/// One host's advertised capabilities, as read from its describeServer response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    /// Whether the host actually answered. False means the question was never asked — no
    /// PDS configured, unreachable, or an unparseable response — and the empty capability
    /// list below carries no information.
    ///
    /// Most gates should ignore this and simply read [`has`](Self::has): "advertises
    /// nothing" and "could not be asked" both mean *do not offer this optional feature*,
    /// which degrades safely. It exists for the gates that do not merely withhold a
    /// feature but **tell the user something about their server** — the create-flow gate
    /// states that the host cannot create identities, and saying that because the network
    /// blinked would be a false accusation the user cannot distinguish from a real one.
    pub reached: bool,
    /// The host's self-reported Custos version, if it reported one. Informational only —
    /// never parsed for comparison. Gate on capability names, not on version arithmetic.
    pub version: Option<String>,
    /// Every capability name the host advertised, including ones this build does not know.
    /// Passing unknown names through keeps a newer server's answer intact for diagnostics.
    pub capabilities: Vec<String>,
}

impl ServerCapabilities {
    /// A host that was never successfully asked: unreachable, unparseable, or not yet
    /// configured. Advertises nothing *and* reports `reached: false`.
    ///
    /// Distinct from a host that answered with no `custos` object — that is a real answer
    /// (see the [`From`] impl), and only it may be reported to the user as a fact about
    /// their server.
    pub fn none() -> Self {
        Self::default()
    }

    /// Does this host advertise `capability`? The only question a gate should ask.
    pub fn has(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|name| name == capability)
    }

    /// Can a brand-new identity be created here, device key in the genesis rotation keys?
    /// When false, the honest offer is to *import* an identity hosted elsewhere.
    pub fn create_ceremony(&self) -> bool {
        self.has(capability::CREATE_CEREMONY)
    }

    /// Will this host hold the account's encrypted recovery share and release it through
    /// the recovery gate? When false, recovery is entirely self-held.
    pub fn escrow(&self) -> bool {
        self.has(capability::ESCROW)
    }

    /// Can a full-access session be minted from a device-key proof, with no password?
    /// When false, a session here needs the account's password.
    pub fn sovereign_sessions(&self) -> bool {
        self.has(capability::SOVEREIGN_SESSIONS)
    }

    /// Does this host implement the auth.md agent surface?
    pub fn agents(&self) -> bool {
        self.has(capability::AGENTS)
    }

    /// Can an OAuth authorization be approved with a device-key signature from the wallet?
    pub fn wallet_consent(&self) -> bool {
        self.has(capability::WALLET_CONSENT)
    }

    /// Does this host serve an opted-in account's did:web document?
    pub fn did_web_hosting(&self) -> bool {
        self.has(capability::DID_WEB_HOSTING)
    }

    /// May an account be created here without a password? When false — including for a host that
    /// could not be asked — the create flow must still collect one, which is the safe direction:
    /// a password sent to a host that would have allowed omitting it still creates a working
    /// account, whereas omitting it against a host that requires one fails the ceremony outright.
    pub fn optional_password(&self) -> bool {
        self.has(capability::OPTIONAL_PASSWORD)
    }

    /// Will this host accept a device-key-signed proof in place of the account password when
    /// permanently deleting an account? When false — including for a host that could not be asked —
    /// removal must collect a password, which is the safe direction: an account that has one is
    /// removed exactly as before, and an account that has none learns it cannot be removed here
    /// rather than silently sending a credential the server will refuse.
    pub fn wallet_account_delete(&self) -> bool {
        self.has(capability::WALLET_ACCOUNT_DELETE)
    }
}

impl From<Option<&CustosExtension>> for ServerCapabilities {
    fn from(extension: Option<&CustosExtension>) -> Self {
        // Both arms describe a host that answered describeServer, so both are `reached`.
        // An absent `custos` object is a real answer — "this host advertises nothing", the
        // correct reading of every implementation that is not Custos — and must not be
        // conflated with never having got an answer at all.
        Self {
            reached: true,
            version: extension.and_then(|extension| extension.version.clone()),
            capabilities: extension
                .map(|extension| extension.capabilities.clone())
                .unwrap_or_default(),
        }
    }
}

/// Per-host cache, keyed by [`host_key`]. Process-lifetime: a deployment's capability set
/// changes only when its operator reconfigures and restarts it, which is orders of
/// magnitude rarer than the gates that read this, and [`forget`] handles the case where
/// the user deliberately re-points the wallet at a host.
fn cache() -> &'static Mutex<HashMap<String, ServerCapabilities>> {
    static CACHE: OnceLock<Mutex<HashMap<String, ServerCapabilities>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Normalize a PDS base URL into a cache key, so `https://Pds.Example.com/` and
/// `https://pds.example.com` are one host rather than two entries that can disagree.
fn host_key(pds_url: &str) -> String {
    pds_url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Record what a host advertised. Called from every successful `describe_server`, so the
/// cache warms from calls the wallet was making anyway.
pub fn record(pds_url: &str, extension: Option<&CustosExtension>) {
    let capabilities = ServerCapabilities::from(extension);
    tracing::debug!(
        pds_url = %pds_url,
        version = ?capabilities.version,
        capabilities = ?capabilities.capabilities,
        "recorded host capabilities"
    );
    if let Ok(mut cache) = cache().lock() {
        cache.insert(host_key(pds_url), capabilities);
    }
}

/// What this host advertised the last time it was described, if it has been described.
pub fn cached(pds_url: &str) -> Option<ServerCapabilities> {
    cache()
        .lock()
        .ok()
        .and_then(|cache| cache.get(&host_key(pds_url)).cloned())
}

/// Drop every cached answer. Tests share one process (and httpmock reuses server ports across
/// tests), so a verdict recorded for one test's mock host can otherwise be read by a later test
/// that happens to be handed the same address.
#[cfg(test)]
pub fn clear_for_test() {
    if let Ok(mut cache) = cache().lock() {
        cache.clear();
    }
}

/// Drop a host's cached answer, forcing the next [`probe`] to re-ask. Called when the user
/// re-points the wallet at a PDS, so a re-configured (or newly reachable) host is re-read.
pub fn forget(pds_url: &str) {
    if let Ok(mut cache) = cache().lock() {
        cache.remove(&host_key(pds_url));
    }
}

/// The cached capabilities for `pds_url`, describing the server once if it has not been
/// described yet.
///
/// A host that cannot be reached, or whose response cannot be parsed, yields
/// [`ServerCapabilities::none`] and is **not** cached — the answer is "we could not ask",
/// and caching it would freeze a transient outage into a permanent verdict. Callers gating
/// optional features degrade to standard-lexicon behavior, which is safe; a caller that
/// must distinguish "unreachable" from "not offered" reads
/// [`ServerCapabilities::reached`], which is false in exactly that case.
pub async fn probe(client: &PdsClient, pds_url: &str) -> ServerCapabilities {
    if let Some(cached) = cached(pds_url) {
        return cached;
    }

    match client.describe_server(pds_url).await {
        // `describe_server` records into the cache on success; re-read it so this returns
        // exactly what was stored rather than a parallel copy.
        Ok(_) => cached(pds_url).unwrap_or_else(ServerCapabilities::none),
        Err(e) => {
            tracing::warn!(
                pds_url = %pds_url,
                error = %e,
                "capability probe failed; treating host as advertising nothing"
            );
            ServerCapabilities::none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(version: &str, capabilities: &[&str]) -> CustosExtension {
        CustosExtension {
            version: Some(version.to_string()),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        }
    }

    #[test]
    fn absent_extension_means_no_capabilities() {
        let capabilities = ServerCapabilities::from(None::<&CustosExtension>);
        // Every capability is withheld, but the host DID answer — so this is not the same
        // value as `none()`, which means the question was never put to it. Only this one
        // may be reported to the user as a fact about their server.
        assert!(capabilities.reached);
        assert_ne!(capabilities, ServerCapabilities::none());
        assert!(!ServerCapabilities::none().reached);
        assert!(!capabilities.create_ceremony());
        assert!(!capabilities.escrow());
        assert!(!capabilities.sovereign_sessions());
        assert!(!capabilities.agents());
        assert!(!capabilities.wallet_consent());
        assert!(!capabilities.did_web_hosting());
        assert_eq!(capabilities.version, None);
    }

    #[test]
    fn named_accessors_read_the_advertised_set() {
        let capabilities = ServerCapabilities::from(Some(&extension(
            "0.8.1",
            &["createCeremony", "escrow", "sovereignSessions"],
        )));
        assert!(capabilities.create_ceremony());
        assert!(capabilities.escrow());
        assert!(capabilities.sovereign_sessions());
        // Advertising some capabilities never implies the rest.
        assert!(!capabilities.agents());
        assert!(!capabilities.wallet_consent());
        assert!(!capabilities.did_web_hosting());
        assert_eq!(capabilities.version.as_deref(), Some("0.8.1"));
    }

    #[test]
    fn unknown_capability_names_are_preserved_not_rejected() {
        let capabilities =
            ServerCapabilities::from(Some(&extension("9.9.9", &["escrow", "someFutureThing"])));
        assert!(capabilities.escrow());
        assert!(capabilities.has("someFutureThing"));
        assert!(capabilities
            .capabilities
            .contains(&"someFutureThing".to_string()));
    }

    #[test]
    fn a_missing_version_is_tolerated() {
        let capabilities = ServerCapabilities::from(Some(&CustosExtension {
            version: None,
            capabilities: vec!["escrow".to_string()],
        }));
        assert_eq!(capabilities.version, None);
        assert!(capabilities.escrow());
    }

    #[test]
    fn host_key_normalizes_trailing_slash_and_case() {
        assert_eq!(
            host_key("https://Pds.Example.com/"),
            host_key("https://pds.example.com")
        );
        assert_eq!(
            host_key("  https://pds.example.com  "),
            "https://pds.example.com"
        );
    }

    #[test]
    fn cache_round_trips_and_forgets_by_normalized_host() {
        let url = "https://cache-round-trip.example.com";
        forget(url);
        assert_eq!(cached(url), None);

        record(url, Some(&extension("0.8.1", &["escrow"])));
        let stored = cached("https://Cache-Round-Trip.example.com/").expect("cached entry");
        assert!(stored.escrow());
        assert_eq!(stored.version.as_deref(), Some("0.8.1"));

        forget("https://CACHE-ROUND-TRIP.example.com");
        assert_eq!(cached(url), None);
    }

    #[test]
    fn recording_an_absent_extension_caches_the_empty_answer() {
        // A reference-PDS-shaped response is a real answer ("no capabilities"), not a
        // failure to answer: it is cached like any other, so the next gate does not re-ask.
        let url = "https://reference-pds.example.com";
        forget(url);
        record(url, None);
        let cached = cached(url).expect("a real answer is cached");
        assert!(cached.capabilities.is_empty());
        // Cached as *reached*: the distinction has to survive the cache, or the first gate
        // to read it back would mistake a reference PDS for a host it could not contact.
        assert!(cached.reached);
        forget(url);
    }

    #[test]
    fn an_unreachable_host_is_not_a_host_that_advertises_nothing() {
        // The two look identical through `has`, and both correctly withhold every feature.
        // They must stay distinguishable for the one caller that tells the user *why*.
        let unreachable = ServerCapabilities::none();
        let reached_but_bare = ServerCapabilities::from(None::<&CustosExtension>);

        assert!(!unreachable.create_ceremony());
        assert!(!reached_but_bare.create_ceremony());
        assert!(!unreachable.reached);
        assert!(reached_but_bare.reached);
    }
}
