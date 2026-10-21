//! The type every advertised Custos capability is declared with. The advertisement table itself
//! (`CAPABILITIES`, its order, and `advertised`) is `pds`'s; a feature crate exports its own entry
//! as a `CAPABILITY` constant that `pds` lists in its slot.

use common::Config;

/// One advertised capability: its wire name, the operator controls that decide whether
/// it is offered, a one-line summary, and the predicate that reads the live config.
///
/// `control` and `summary` are documentation surface rather than runtime inputs: the
/// generated operator reference page renders them, and `just capability-docs-check` holds
/// the hand-written operator page to them. They are deliberately declared here — beside
/// the predicate they describe — so a change to how a capability is gated cannot land
/// without the documentation moving in the same edit.
#[derive(Clone, Copy)]
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
