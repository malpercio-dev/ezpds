// pattern: Functional Core

//! The `spaces` entry of the `describeServer` capability table. `pds` lists it in its advertisement
//! order; the `enabled` predicate must stay the same condition [`crate::router`] and the sync
//! routes enforce.

use custos_core::capability::Capability;

pub const CAPABILITY: Capability = Capability {
        name: "spaces",
        control: "spaces.enabled signing_key_master_key",
        summary: "The Atproto Spaces alpha surface: permissioned space repos with signature-bound space credentials, oplog/CAR sync, and simplespace management.",
        // Two conditions, both required. `spaces.enabled` is the operator switch: off (the
        // default while the protocol is pre-launch alpha), the routes are not registered at
        // all. The master key is the gate on an enabled surface being *whole*: writes
        // succeed without one, but every sync serving (`getLatestCommit`/`listRepoOps`/
        // `getRepo`) mints a per-serving signed commit from the account's KEK-wrapped repo
        // signing key and answers 503 without it. A deployment no syncer can sync from does
        // not offer spaces.
        enabled: |config| config.spaces.enabled && config.signing_key_master_key.is_some(),
    };
