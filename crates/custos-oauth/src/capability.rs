// pattern: Functional Core

//! The `walletConsent` entry of the `describeServer` capability table. `pds` lists it in its
//! advertisement order.

use custos_core::capability::{Capability, CONTROL_ALWAYS};

pub const CAPABILITY: Capability = Capability {
    name: "walletConsent",
    control: CONTROL_ALWAYS,
    summary: "OAuth authorization can be approved in the identity wallet with a device-key-signed decision instead of a browser password.",
    enabled: |_| true,
};
