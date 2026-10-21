// pattern: Functional Core

//! The `agents` entry of the `describeServer` capability table. `pds` lists it in its
//! advertisement order.

use custos_core::capability::Capability;

pub const CAPABILITY: Capability = Capability {
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
};
