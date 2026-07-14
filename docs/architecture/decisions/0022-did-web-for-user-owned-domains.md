# ADR-0022: `did:web` for user-owned domains

- **Status:** Accepted
- **Date:** 2026-07-13
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0003](0003-did-plc-as-did-method.md) · [MM-278](https://linear.app/atbb/issue/MM-278) · [MM-279](https://linear.app/atbb/issue/MM-279) · [MM-285](https://linear.app/atbb/issue/MM-285)

## Context

ADR-0003 made `did:plc` the only account identity method because its ordered rotation keys and
72-hour recovery window support client-held custody. That remains the strongest default, but it
also excluded identities whose root of trust is intentionally a user-owned domain. Custos can
support those identities without claiming that domain control has PLC's recovery semantics.

Serving a DID for a domain the user does not control would create indefinite exit liability. A
new or migrated `did:web` therefore needs an external proof that the wallet-approved document is
already authoritative at the user's domain before Custos creates the account or takes over hosting.

## Decision

Custos may mint, migrate, or host a `did:web` identity only for a user-owned domain, after the
wallet proves control by publishing the exact reviewed DID document at its authoritative HTTPS
URL. `did:plc` remains the default identity method.

The document publishes the wallet device key alongside Custos's reserved `#atproto` key and
`#atproto_pds` service. The existing 2-of-3 escrow restores the device key, not domain ownership.
Custos-hosted updates require device-key approval; self-hosted identities use that key as a
monitoring anchor. DNS remains the immediate override and exit boundary.

Wallet recovery language and controls are method-specific. PLC monitoring, fork-point recovery,
and the 72-hour override apply only to `did:plc`; `did:web` recovery is domain control plus
escrowed keys.

## Consequences

- Users can create or migrate all four new/existing and self/Custos-hosted `did:web` shapes.
- Account promotion performs an SSRF-hardened external fetch and exact byte comparison; it never
  submits a PLC operation.
- Domain compromise remains identity compromise. Device-key escrow restores co-signing and
  monitoring continuity but cannot replace domain control.
- Custos accepts hosting liability only after independently observable proof of user control, and
  users can exit by repointing DNS.
- Method-specific UI and recovery paths must remain gated so `did:web` never inherits PLC claims.

## Alternatives considered

- **Keep `did:plc` as the only method.** Rejected because it prevents users from choosing domain
  control as their identity root and blocks migration of existing `did:web` accounts.
- **Mint `did:web` before publication.** Rejected because an authenticated wallet session does not
  prove control of the named domain.
- **Host domains Custos controls on a user's behalf.** Rejected because identity ownership and
  exit would remain dependent on Custos.
