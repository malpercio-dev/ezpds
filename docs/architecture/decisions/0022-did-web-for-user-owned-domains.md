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

## Amendment (2026-07-25): signing authority for passwordless auth

Both passwordless auth surfaces — `POST /v1/sessions/sovereign` and `POST /oauth/authorize/approve`
— were hard-gated to `did:plc`, so a `did:web` account carrying no password (which every
wallet-migrated account does, by design) could not authenticate at all. Extending them to `did:web`
requires deciding what counts as that identity's signing authority.

**The authority set is exactly `{did}#device`, and nothing else.** Not "any verificationMethod":
`#atproto`'s private key is Custos-held, so a broader set would let this server sign its own
sovereign-session envelope for an account it hosts. This keeps one rule across both `did:web` paths
— account promotion already enforces `#device` specifically. The predicate matches promotion's
(`type == "Multikey"`, `controller == did`, an id naming `#device`), differing only in shape: the
authority lookup *discovers* the key by extracting `publicKeyMultibase`, rendered as
`did:key:{multibase}` since a PLC rotation set stores `did:key:` URIs. Both paths match that id
through the shared `fragment_id_matches`, which accepts the bare `#device` the wallet composers
emit or the DID-qualified `{did}#device` form, and never a foreign DID's fragment. A document with more than one
`#device`-shaped entry is malformed (duplicate `id` values already violate DID Core) and fails
closed rather than picking one by array order. The document is resolved live; the `did_documents`
cache is never consulted, because `POST /v1/did-web/document` can write it.

**Passwordless auth is gated to self-hosted `did:web` only, enforced server-side.** That same route
lets an account rewrite its served document under mere session auth, so for a Custos-hosted
`did:web` a stolen session could install an attacker `#device` key and bootstrap sovereign sessions
— a privilege escalation with no key compromise. `did:plc` has no equivalent hole: rewriting the
rotation set requires an existing rotation key, and plc.directory is external to this server.

The gate is **exact rather than approximate**: `POST /v1/did-web/document` already refuses unless
hosting is enabled, so `did_web_hosting_enabled_at IS NULL` *is* the condition "no session-authed
rewrite is possible", with no gap in either direction. Enforcement lives in the shared authority
lookup, not the client — the route stays live for any other client and for accounts that already
opted in, so hiding the shapes in the wallet is a sensible default but never the boundary.

Consequently the two **Custos-hosted** `did:web` shapes are **deferred** and no longer offered by
the wallet; the two self-hosted shapes are unaffected, and the hosting routes and their plumbing
remain in place. Making `#device` immutable across a `/v1/did-web/document` edit would let the gate
be dropped and all four shapes supported, without redesigning anything.

## Consequences

- Users can create or migrate the two self-hosted `did:web` shapes. The two Custos-hosted shapes are
  deferred by the amendment above and are not offered.
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
