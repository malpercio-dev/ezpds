# ADR-0025: Wallet-driven per-account repo signing-key rotation

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** malpercio
- **Related:** ADR-0001 (client-held rotation-key custody), ADR-0004 (PDS-signed repo commits), ADR-0012 (canonical DAG-CBOR), `docs/architecture/identity-and-key-custody.md`

## Context

Each account's repo signing key — the P-256 key at `verificationMethods.atproto`
(and the PDS slot in `rotationKeys`) that signs every repo commit (ADR-0004) —
lives encrypted in the PDS's `signing_keys` table. Re-wrapping that ciphertext
under a new master key preserves the same key material; replacing the key with a
**fresh value** requires repointing the DID document, which is a PLC operation
that must be signed by a current rotation key.

The PDS cannot authorize that operation unilaterally: its own key is the exact
key being replaced, and the wallet's device key at `rotationKeys[0]` outranks it
(ADR-0001). Replacing the repo key is therefore inherently a wallet-driven,
per-account flow.

There is also an ordering constraint. The commit-signing lookup selects the
newest `signing_keys` row per DID, and relays verify commit signatures against
the DID document — so the new key must not sign a commit before the document
lists it, and the old key must not keep signing after the document stops listing
it. The DID document (on plc.directory) and the PDS's key store cannot be
flipped in one atomic step.

## Decision

We will rotate repo signing keys through a two-endpoint PDS surface driven by
the wallet, with the PDS — not the wallet — submitting the operation to
plc.directory:

1. `POST /v1/repo-keys/rotation` mints a **fresh** P-256 key (never reusing a
   previously staged one) and stores it as a `status = 'staged'` row in
   `signing_keys` (V048). Staged rows are invisible to every reader — commit
   signing, `getRecommendedDidCredentials`, service-auth minting — until
   cutover. The KEK re-wrap inventory sweeps them like any other row.
2. The wallet builds the rotation op — device key stays `rotationKeys[0]`, the
   staged key takes the PDS slot and `verificationMethods.atproto`, services and
   `alsoKnownAs` preserved byte-for-byte — behind a fourth strict pre-sign
   allowlist (`rotate_repo_key.rs`, sibling to the claim / migration /
   handle-change guards), signs it with the device key, and POSTs it to
   `POST /v1/repo-keys/rotation/complete`.
3. `complete` verifies the op (current-rotation-key signature, `prev` chains
   onto the head, installs exactly the staged key, `services` unchanged — a
   rotation must not double as a migration), then, **holding the account's
   `RepoWriteLocks` mutex**, submits it to plc.directory, refreshes the cached
   DID document, and atomically promotes the staged row while deleting the
   retired one. An `#identity` firehose frame tells relays to re-resolve.

Holding the per-account repo write lock across submit + promote is what closes
the ordering gap: no commit can be signed between plc.directory accepting the
new key and the local cutover, so a commit is never signed by a key absent from
the DID document.

`complete` is retry-safe: an op that is already the PLC head skips the
re-submit and only promotes; a repeat after full promotion returns success.

## Consequences

- A fresh repo key can now be issued end-to-end for a single account — the
  load-bearing mechanism for both the master-key-compromise and master-key-loss
  recovery stories (re-wrap alone cannot help in either).
- Retired key rows are **deleted**, not tombstoned: after a rotation the old
  private key is either compromised or undecryptable, and commit verification
  only ever needs the public keys recorded in the PLC operation log.
- The wallet must route this one op through the PDS instead of posting to
  plc.directory directly (unlike the recovery / migration / handle-change legs);
  the guard rails live on both sides, so a compromised PDS still cannot use the
  flow to move the account or smuggle keys — the wallet signs only an op it
  composed itself.
- Mass rotation (operator-initiated, compromise scenario) remains follow-on
  work: each account's wallet must still sign, so it becomes a prompt/queue
  surface, not a server-side batch.

## Alternatives considered

- **Insert the new key directly as the active row** — the newest-row lookup
  would flip the commit signer before the DID document repoints, leaving
  commits relays cannot verify. Rejected; staging exists precisely to prevent
  this.
- **Wallet submits to plc.directory itself, then notifies the PDS** — leaves a
  multi-second window (or forever, if the notify never arrives) where the
  document lists the new key while the PDS signs with the old one. Rejected.
- **Reuse `reserveSigningKey` / `reserved_signing_keys` for staging** — its
  reservations are idempotent per DID (`ON CONFLICT DO NOTHING`), so a key
  reserved before a compromise would be *reused* after it — exactly the wrong
  semantics for rotation. A begin call must always mint fresh.
- **PDS-signed rotation via `signPlcOperation`** — signs with the PDS-held key,
  which is undecryptable in the loss scenario and distrusted in the compromise
  scenario. Usable for neither.
