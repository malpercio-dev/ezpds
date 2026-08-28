// pattern: Functional Core
//
// Derives the `custos` capability set advertised by `describeServer` from the validated
// server configuration. Pure: config in, capability names out. No I/O, no state.

//! The advertised Custos capability set.
//!
//! `com.atproto.server.describeServer` returns strictly the lexicon's fields on the
//! reference PDS and on rsky-pds; millipds already ships an off-spec `version` field.
//! Custos adds one distinctively-named extension object — `custos` — carrying the
//! running version and the capabilities this deployment actually offers, so a client
//! can feature-gate by asking "does this host advertise X?" instead of calling a
//! `/v1/*` route and interpreting the failure. A client that does not know the field
//! ignores it (Lexicon objects are open); a host that does not send it has no Custos
//! capabilities, which is exactly right for every other implementation.
//!
//! **Named capabilities, never an `isCustos` boolean.** A self-hosted Custos can run
//! without the pieces that need a master key, a future implementation could adopt a
//! single capability, and every gate reads as a question about a feature rather than
//! about a vendor.
//!
//! **Advertisement must be truthful.** Each entry's `enabled` predicate is the *same*
//! condition the routes themselves enforce — a capability is advertised only when a
//! client calling it would actually succeed. Adding a capability here without wiring
//! it to the real gate turns this endpoint into a lie a client cannot detect.
//!
//! [`CAPABILITIES`] is the single source of truth: the wire names, the operator
//! controls, and the one-line summaries are all read from it — by `describeServer`, by
//! the generated operator reference page, and by the documentation-drift gate
//! (`just capability-docs-check`). Adding an entry here fails that gate until the
//! operator documentation describes the new capability and how it is controlled.

use common::Config;

/// One advertised capability: its wire name, the operator controls that decide whether
/// it is offered, a one-line summary, and the predicate that reads the live config.
///
/// `control` and `summary` are documentation surface rather than runtime inputs: the
/// generated operator reference page renders them, and `just capability-docs-check` holds
/// the hand-written operator page to them. They are deliberately declared here — beside
/// the predicate they describe — so a change to how a capability is gated cannot land
/// without the documentation moving in the same edit.
#[allow(dead_code)]
pub struct Capability {
    /// The camelCase name that appears in `custos.capabilities`. Stable wire contract.
    pub name: &'static str,
    /// The configuration that decides whether this capability is offered, as a
    /// space-separated list of config field paths — or `always` when the capability is
    /// inherent to running Custos and has no operator switch. Documented per capability
    /// on the operator capabilities page, which the drift gate holds to this list.
    pub control: &'static str,
    /// One-line description of what the capability lets a client do.
    pub summary: &'static str,
    /// Reads the live configuration. Must mirror the gate the routes themselves apply.
    pub enabled: fn(&Config) -> bool,
}

/// Sentinel `control` value for a capability with no operator switch.
pub const CONTROL_ALWAYS: &str = "always";

/// Every capability Custos knows how to advertise, in advertisement order.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        name: "createCeremony",
        control: "signing_key_master_key",
        summary: "Custos-native identity creation: the mobile signup, per-account repo signing key issuance, and the client-authored did:plc genesis ceremony.",
        // The ceremony issues and stores a per-account repo signing key wrapped under the
        // master KEK; without a master key `/v1/repo-signing-key` and `/v1/dids` answer 503.
        enabled: |config| config.signing_key_master_key.is_some(),
    },
    Capability {
        name: "escrow",
        control: "signing_key_master_key",
        summary: "Custos holds the account's encrypted Shamir Share 2 and releases it through the delayed, notified recovery gate.",
        // The share envelope is stored wrapped under the master KEK; without a master key
        // the deposit and release routes answer 503.
        enabled: |config| config.signing_key_master_key.is_some(),
    },
    Capability {
        name: "sovereignSessions",
        control: CONTROL_ALWAYS,
        summary: "Passwordless full-access sessions minted from a fresh proof signed by one of the identity's current PLC rotation keys.",
        enabled: |_| true,
    },
    Capability {
        name: "agents",
        control: "agent_auth.service_auth_enabled agent_auth.anonymous_enabled agent_auth.trusted_issuers",
        summary: "The auth.md agent surface: agent registration, the owner-confirmed claim ceremony, and agent-derived access tokens.",
        // Every registration flow is opt-in and off by default; with none enabled there is
        // no way for an agent to register at all, so the capability is not offered.
        enabled: |config| {
            config.agent_auth.service_auth_enabled
                || config.agent_auth.anonymous_enabled
                || !config.agent_auth.trusted_issuers.is_empty()
        },
    },
    Capability {
        name: "walletConsent",
        control: CONTROL_ALWAYS,
        summary: "OAuth authorization can be approved in the identity wallet with a device-key-signed decision instead of a browser password.",
        enabled: |_| true,
    },
    Capability {
        name: "optionalPassword",
        control: "accounts.password_optional",
        summary: "An account can be created here with no password at all, authenticating thereafter with its device key.",
        // Mirrors the gate `create_did`/`createAccount` apply to an omitted password. A client
        // that reads this and omits the field must actually succeed, so the predicate is the
        // config flag itself — never a broader "this is Custos" condition.
        enabled: |config| config.accounts.password_optional,
    },
    Capability {
        name: "walletAccountDelete",
        control: CONTROL_ALWAYS,
        summary: "An account can be permanently deleted with a device-key-signed proof from one of its current rotation keys instead of the account password.",
        // The proof branch of `deleteAccount` has no operator switch of its own: it is the same
        // key-sovereign trust model as `sovereignSessions`, and withholding it would leave an
        // account created with no password permanently undeletable. Advertised separately rather
        // than folded into `sovereignSessions` so a client asks about the surface it needs.
        enabled: |_| true,
    },
    Capability {
        name: "didWebHosting",
        control: CONTROL_ALWAYS,
        summary: "Custos serves an opted-in account's did:web document at the account's own domain and propagates edits to relays.",
        enabled: |_| true,
    },
    Capability {
        name: "appPasswordPersonalDetails",
        control: CONTROL_ALWAYS,
        summary: "An app password can be minted with the personal-details grant, letting its sessions read and set the full-access-only preferences (e.g. the birth date age checks require).",
        // The grant is a stored property of the credential (V063) with no operator switch;
        // the preference routes honor the resulting token claim unconditionally (ADR-0033).
        enabled: |_| true,
    },
    Capability {
        name: "spaces",
        control: "spaces.enabled signing_key_master_key",
        summary: "The Atproto Spaces alpha surface: permissioned space repos with DPoP-bound space credentials, oplog/CAR sync, and simplespace management.",
        // Two conditions, both required. `spaces.enabled` is the operator switch: off (the
        // default while the protocol is pre-launch alpha), the routes are not registered at
        // all. The master key is the gate on an enabled surface being *whole*: writes
        // succeed without one, but every sync serving (`getLatestCommit`/`listRepoOps`/
        // `getRepo`) mints a per-serving signed commit from the account's KEK-wrapped repo
        // signing key and answers 503 without it. A deployment no syncer can sync from does
        // not offer spaces.
        enabled: |config| config.spaces.enabled && config.signing_key_master_key.is_some(),
    },
    Capability {
        name: "waitlist",
        control: "waitlist.enabled",
        summary: "Public interest-signup waitlist: unauthenticated email (+ optional atproto handle) signups a marketing page can post to, readable back by the operator.",
        // The public signup route 404s unless the waitlist is enabled; the admin
        // readout stays available regardless (it reads data already collected).
        enabled: |config| config.waitlist.enabled,
    },
];

/// The capability names this deployment offers, in [`CAPABILITIES`] order.
pub fn advertised(config: &Config) -> Vec<&'static str> {
    CAPABILITIES
        .iter()
        .filter(|capability| (capability.enabled)(config))
        .map(|capability| capability.name)
        .collect()
}

/// The self-identifying version string: `custos vX.Y.Z`.
///
/// millipds ships the same `<software> v<version>` shape in both `describeServer` and
/// `_health`, and it is what third-party atproto diagnostic tooling reads; the reference
/// PDS returns a bare commit hash with no software name. This is the closest thing the
/// ecosystem has to a convention, so Custos follows it rather than inventing a shape.
pub const IDENTIFYING_VERSION: &str = concat!("custos v", env!("CARGO_PKG_VERSION"));

/// The bare semantic version carried by the `custos` extension object.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate's shared test configuration: no master key, no agent flows enabled.
    async fn base_config() -> Config {
        (*crate::app::test_state().await.config).clone()
    }

    fn with_master_key(mut config: Config) -> Config {
        config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new([3u8; 32])));
        config
    }

    #[test]
    fn capability_names_are_unique_and_camel_case() {
        let mut seen = Vec::new();
        for capability in CAPABILITIES {
            assert!(
                !seen.contains(&capability.name),
                "duplicate capability name: {}",
                capability.name
            );
            seen.push(capability.name);
            let mut chars = capability.name.chars();
            assert!(
                chars.next().is_some_and(|c| c.is_ascii_lowercase()),
                "capability name must start lowercase: {}",
                capability.name
            );
            assert!(
                capability.name.chars().all(|c| c.is_ascii_alphanumeric()),
                "capability name must be camelCase alphanumeric: {}",
                capability.name
            );
        }
    }

    #[test]
    fn every_capability_declares_a_control_and_summary() {
        for capability in CAPABILITIES {
            assert!(
                !capability.control.trim().is_empty(),
                "{} declares no control",
                capability.name
            );
            assert!(
                !capability.summary.trim().is_empty(),
                "{} declares no summary",
                capability.name
            );
            assert!(
                !capability.summary.contains('\n'),
                "{}'s summary must stay one line (the docs generator reads it verbatim)",
                capability.name
            );
        }
    }

    #[tokio::test]
    async fn master_key_capabilities_are_withheld_without_a_master_key() {
        let config = base_config().await;
        assert!(config.signing_key_master_key.is_none());
        let advertised = advertised(&config);
        assert!(!advertised.contains(&"createCeremony"));
        assert!(!advertised.contains(&"escrow"));
        assert!(!advertised.contains(&"spaces"));
        // The capabilities that need no master key are unaffected.
        assert!(advertised.contains(&"sovereignSessions"));
        assert!(advertised.contains(&"walletConsent"));
        assert!(advertised.contains(&"walletAccountDelete"));
        assert!(advertised.contains(&"didWebHosting"));
    }

    #[tokio::test]
    async fn master_key_capabilities_are_offered_with_a_master_key() {
        let advertised = advertised(&with_master_key(base_config().await));
        assert!(advertised.contains(&"createCeremony"));
        assert!(advertised.contains(&"escrow"));
        assert!(advertised.contains(&"spaces"));
    }

    #[tokio::test]
    async fn spaces_requires_the_config_switch_and_a_master_key() {
        // The shared test config has spaces enabled; a master key alone is not enough
        // with the switch off, and the switch alone is not enough without a master key
        // (asserted by the withheld/offered pair above).
        let mut config = with_master_key(base_config().await);
        assert!(config.spaces.enabled);
        config.spaces.enabled = false;
        assert!(!advertised(&config).contains(&"spaces"));
    }

    #[tokio::test]
    async fn agents_requires_at_least_one_registration_flow() {
        let mut config = base_config().await;
        config.agent_auth.service_auth_enabled = false;
        config.agent_auth.anonymous_enabled = false;
        config.agent_auth.trusted_issuers = Vec::new();
        assert!(!advertised(&config).contains(&"agents"));

        config.agent_auth.anonymous_enabled = true;
        assert!(advertised(&config).contains(&"agents"));
    }

    #[tokio::test]
    async fn waitlist_requires_the_config_switch() {
        let mut config = base_config().await;
        assert!(!config.waitlist.enabled);
        assert!(!advertised(&config).contains(&"waitlist"));

        config.waitlist.enabled = true;
        assert!(advertised(&config).contains(&"waitlist"));
    }

    #[tokio::test]
    async fn advertised_preserves_declaration_order() {
        let config = with_master_key(base_config().await);
        let advertised = advertised(&config);
        let declared: Vec<&str> = CAPABILITIES.iter().map(|c| c.name).collect();
        let mut previous = 0;
        for name in &advertised {
            let index = declared.iter().position(|d| d == name).unwrap();
            assert!(index >= previous, "advertised order diverged at {name}");
            previous = index;
        }
    }

    #[test]
    fn identifying_version_is_self_identifying() {
        assert!(IDENTIFYING_VERSION.starts_with("custos v"));
        assert_eq!(IDENTIFYING_VERSION, format!("custos v{VERSION}"));
    }
}
