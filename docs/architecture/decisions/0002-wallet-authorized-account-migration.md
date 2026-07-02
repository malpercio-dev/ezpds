# ADR-0002: Account migration is wallet-authorized by default, with a PDS-signed interop fallback

- **Status:** Proposed
- **Date:** 2026-07-02
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [MM-207](https://linear.app/atbb/issue/MM-207) (migration epic) · [MM-211](https://linear.app/atbb/issue/MM-211) (outbound email) · [MM-222](https://linear.app/atbb/issue/MM-222) (identity PLC-signing surface) · [`../identity-and-key-custody.md`](../identity-and-key-custody.md)

## Context

ezpds currently implements **none** of the standard ATProto account-migration
XRPC surface — every migration-specific leg returns `501` — so an existing
account cannot migrate in, and an ezpds account cannot migrate out with off-the-
shelf tooling. This blocks the "credible exit / bring your existing identity"
story (MM-207).

The standard ATProto migration handshake signs the DID-repointing PLC operation
on the **old PDS**, authorized by an email token
(`requestPlcOperationSignature` + `signPlcOperation`). That is the correct model
when the PDS holds the rotation keys. But per [ADR-0001](0001-client-held-rotation-key-custody.md),
in ezpds the **wallet** holds `rotationKeys[0]` — so for any identity the wallet
already controls, routing the identity operation through the old PDS is
unnecessary, and making it *mandatory* would throw away the differentiator.

The crypto for wallet-side signing already exists (`build_did_plc_rotation_op`
with an external signer; the wallet already POSTs operations to plc.directory in
the claim and recovery flows). What is missing is the HTTP/XRPC handshake, the
data-transfer legs (`importRepo`, blobs), and — for the interop path — a working
outbound email path (MM-211), which is also currently stubbed.

## Decision

We will design migration as **two PLC-signing paths**, and make the wallet-
authorized path the default:

1. **Wallet-authorized (default).** When the wallet holds an authorized key in
   the DID's current `rotationKeys`, the migration's identity leg is built and
   signed **locally** with the device key and submitted directly to
   plc.directory. No email token, no dependency on the old PDS being alive or
   cooperative. This covers every wallet-native identity, wallet↔wallet moves,
   and any migration *off* ezpds.

2. **PDS-signed (interop fallback).** When the wallet does **not** yet hold a
   rotation key for the identity (first-time import of a foreign identity, e.g.
   from bsky.social), the identity leg uses the standard old-PDS
   `signPlcOperation` email-tokened flow *once*, and the operation it submits
   **inserts the wallet's device key as `rotationKeys[0]`**. After that single
   step the identity is wallet-controlled and path (1) applies thereafter.

The migration flow **detects which case it is in** (does the wallet hold an
authorized key?) and selects path (1) when possible.

We will still build the full server-side XRPC surface required by MM-207
(`createAccount` existing-DID path, `reserveSigningKey`, `importRepo`,
`listMissingBlobs`, `checkAccountStatus`, and the `identity.*` PLC endpoints).
Their role is **interop**: they let goat / the official client migrate *off*
ezpds the standard way and let ezpds be a migration *destination*. The wallet's
own first-class flow does not route its identity leg through them.

## Consequences

- **Credible exit becomes a cryptographic fact**, not a PDS policy promise: the
  flagship migration cannot be blocked by a hostile or dead old PDS.
- **Email (MM-211) is decoupled from the flagship path.** MM-211 remains a hard
  dependency for the *interop* path (ezpds-as-old-PDS signing a departure via
  standard tooling), for first-time foreign import, and for password reset — but
  the wallet-authorized migration needs no email for its identity leg. The Linear
  framing should reflect this scoping rather than treating email as the linchpin
  of all migration.
- **Server work is still required and substantial** — the data-transfer legs and
  the interop XRPCs are unchanged in scope; the differentiator changes *which
  path is primary*, not whether the endpoints exist.
- **Every migration surfaces a signed-operation review.** Because the user is the
  signer, the wallet shows the exact PLC diff (rotation keys, PDS endpoint,
  verification method) for biometric approval, reusing the claim flow's review
  UI and 4-point verification — consistent with the "practice the assurance you
  preach" design principle.
- **Ties into the existing safety net.** A hostile destination PDS cannot
  complete a takeover without the wallet's signature, and the standard-path key
  insertion is monitored by `plc_monitor` and reversible via `recovery.rs`.
- **Canonical end-to-end test:** with bsky.social accepting inbound migrations,
  the round trip is (a) import a bsky identity into ezpds (PDS-signed insertion),
  (b) migrate *out* of ezpds to a second PDS **self-signed by the wallet**, (c)
  migrate back — the self-signed middle leg is the proof of the differentiator.

## Alternatives considered

- **Only implement the standard PDS-signed handshake.** Rejected: it works, but
  it makes migration route through the old PDS even when the wallet already holds
  the top key — discarding the differentiator and keeping credible exit
  permissioned.
- **Only implement wallet self-signing; skip the interop XRPCs.** Rejected:
  breaks first-time import of foreign identities (the wallet holds no key yet) and
  prevents off-the-shelf tools from migrating off ezpds — failing the "full
  network participation" requirement of MM-207.
- **Block all migration on MM-211 email.** Rejected: correct for the interop
  path, but it would needlessly gate the wallet-authorized path, which requires
  no email. Email is a dependency of *a* path, not of migration as a whole.
