# ADR-0003: `did:plc` as the DID method

- **Status:** Accepted (amended 2026-07-13 — see [Amendment](#amendment-2026-07-13-didplc-is-the-minted-method-didweb-is-hosted-for-user-owned-domains))
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0002](0002-wallet-authorized-account-migration.md) · [ADR-0012](0012-canonical-dag-cbor-for-plc-ops.md) · [`../identity-and-key-custody.md`](../identity-and-key-custody.md) · [`crates/crypto/src/plc.rs`](../../../crates/crypto/src/plc.rs) · [MM-278](https://linear.app/atbb/issue/MM-278) (migrate `did:web:malpercio.dev` onto Custos) · [MM-279](https://linear.app/atbb/issue/MM-279) (managed did:web hosting) · [MM-285](https://linear.app/atbb/issue/MM-285) (wallet did:web ceremony)

## Context

ATProto identities are DIDs, and the network supports two methods in practice:

- **`did:web`** — the DID document is a JSON file hosted at a domain
  (`https://example.com/.well-known/did.json`). Simple, no ledger — but whoever
  controls the domain/host controls the identity, there is no rotation-key
  hierarchy, and there is no recovery window if a key is compromised.
- **`did:plc`** — a self-certifying DID whose document is the head of a
  hash-linked log of **signed operations**, served by a directory
  (plc.directory). It carries an *ordered* `rotationKeys` array and a fixed
  (72-hour) window in which a higher-priority key can override a lower-priority
  key's operation.

ezpds's entire thesis — sovereign custody, credible exit, tamper detection and
recovery — depends on identity operations being independently signable and
overridable by a key the user holds. That requires rotation keys and a recovery
window.

## Decision

We will mint and manage all ezpds accounts as **`did:plc`** identities.
`did:web` is not offered as an account identity method.

## Consequences

- **Enables the custody model** (ADR-0001): ordered rotation keys let the
  wallet hold the top key and the PDS a lower one; the recovery window makes
  `plc_monitor` + `recovery.rs` and wallet-authorized migration (ADR-0002)
  possible. None of these are expressible under `did:web`.
- **Introduces a dependency on plc.directory** as the operation ledger. This is
  a semi-centralized service; ezpds mitigates trust in it by verifying every
  operation's signatures client-side (the audit-log verification in
  `plc_monitor`) rather than trusting the directory's word.
- **Requires canonical DAG-CBOR** for operations, since the DID is the hash of
  its own signed op — see ADR-0012.
- Identities are portable across PDSes by construction (the DID isn't bound to a
  host), which is what makes migration a repointing operation rather than a
  re-issuance.

## Alternatives considered

- **`did:web`.** Rejected: host/domain-controlled, no rotation-key hierarchy, no
  recovery window — it cannot express user-held identity custody, which is the
  product.
- **`did:key`.** Rejected as an *account* identity: immutable, carries no service
  endpoint and no rotation, so it can neither point at a PDS nor be recovered.
  (`did:key` is still used throughout for representing individual public keys.)

## Amendment (2026-07-13): `did:web` is offered only for user-owned domains

The original Decision said "`did:web` is not offered as an account identity
method." Taken literally that reads as "Custos rejects `did:web` accounts,"
which is too strong and was never the intent. The precise rule is:

> **Custos may mint or host a `did:web` identity only after the wallet proves control of the
> user-owned domain by publishing the exact reviewed DID document there.**

This is exactly the exit-liability boundary the superseded provisioning spec
already drew ([`docs/provisioning-api-spec.md:44-47`](../../provisioning-api-spec.md)):
`did:web` is offered only to users who bring their own domain, and Custos never
hosts a `did.json` for a domain the user does not control — because doing so
would obligate Custos to keep serving that document indefinitely after the user
leaves, the opposite of credible exit.

### Why this is consistent with the original decision

The Decision's *reasoning* was about **custody**, not about turning inbound
`did:web` accounts away. `did:plc` remains the default method Custos mints because only it
carries the ordered `rotationKeys` and 72-hour recovery window that ADR-0001's
client-held-custody model, `plc_monitor`, `recovery.rs`, and wallet-authorized
migration (ADR-0002) depend on. None of that is expressible under `did:web`.
That remains true and unchanged. A new `did:web` identity instead uses domain control as its root
of trust and publishes the wallet device key as an additional verification method; escrow restores
that co-signing/monitoring key, not ownership of the domain.

A `did:web` identity the user already owns is a different case. The user controls
the DID document at their own domain, so the "who can repoint this identity"
question is answered by domain control, not by a rotation-key hierarchy Custos
would have to hold. Accepting such an account as a PDS-hosting *destination* adds
no custody Custos must vouch for, and it is method-agnostic on the server:
migration-in (`createAccount` existing-DID path, `importRepo`, blob drain,
`checkAccountStatus`, `activateAccount`) never inspects the DID method, and every
store keys the DID as opaque TEXT.

### The two `did:web` shapes, and what each requires

1. **Self-hosted `did:web` (MM-278, shipped).** The user hosts and edits
   `did.json` at their own domain (e.g. `did:web:malpercio.dev`). Custos does
   **not** serve the document — it only resolves it (SSRF-guarded), caches it,
   and, on the operator's edit, re-resolves it via `refreshIdentity` (which
   rewrites the cache row and emits an `#identity` firehose frame so relays
   re-resolve). The migration choreography is *simpler* than `did:plc`: no email
   token and no PLC operation — the operator repoints the PDS by hand-editing
   `#atproto_pds` and the `#atproto` verification method in their own `did.json`
   (using the values from `getRecommendedDidCredentials`). The `did:plc`-only
   identity endpoints (`signPlcOperation`, `submitPlcOperation`,
   `requestPlcOperationSignature`) return an explicit "not a did:plc" error for
   these accounts rather than failing deep in a plc.directory audit-log fetch.

2. **Custos-served `did:web` for a user-owned domain (MM-279/MM-285, shipped).**
   The wallet first makes the reviewed document independently resolvable to prove domain control,
   then opts into Custos serving. DNS remains the instant override and exit boundary.

3. **New `did:web` (MM-285, shipped).** The wallet composes and exports the document with its
   device key, Custos's reserved repo-signing key, and Custos's PDS endpoint. `/v1/dids` resolves
   the authoritative domain and compares the exact bytes before atomically creating the account,
   genesis repo, session, and unchanged 2-of-3 Shamir shares. No PLC operation or plc.directory
   request occurs.

### Honesty in the wallet

Because `did:web` has **no rotation hierarchy, no audit log, and no recovery
window**, the Obsign wallet must not present its `did:plc`-only assurances
(PLC monitoring, recovery-window override, and PLC claim ceremonies) as if
they applied to a `did:web` identity. Those surfaces are gated for `did:web` and
replaced with an in-app explanation of what `did:web` does and does not provide —
"practice the assurance you preach" (DESIGN.md), stated honestly rather than by
silently showing an inapplicable "all secure" state.

### Net effect on the Decision

"`did:web` is not offered as an account identity method" is superseded by:
**`did:web` may be minted or hosted only for domains the user controls, after external publication
proves that control.** The custody rationale for keeping `did:plc` as the default is unchanged.
