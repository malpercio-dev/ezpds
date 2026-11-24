# ADR-0043: Dedicated per-account KEM key, published through a wallet-signed op

- **Status:** Accepted
- **Date:** 2026-11-23
- **Deciders:** malpercio
- **Related:** ADR-0001 (client-held rotation-key custody), ADR-0004 (PDS-signed repo commits), ADR-0025 (wallet-driven repo-key rotation), ADR-0035 (per-space operator takedown); Linear MM-664 (the custody grilling), MM-675 (slicing, amended for atproto pull request 5974), MM-687 (this change); atproto `permissioned-data` @ `047d603`

## Context

Atproto Spaces lets a syncer check that a space record really came from the
writer's host, without that check becoming proof anyone else could use. It works
like this:

1. For each request, the syncer makes a throwaway P-256 keypair and sends the
   public half.
2. The host combines the private half of the writer's **KEM key** with the
   syncer's public key; the syncer combines its throwaway private key with the
   KEM key's public half, read from the writer's DID document as `#atproto_kem`.
   Both arrive at the same secret (Diffie-Hellman), from which HPKE secret export
   derives a 32-byte MAC key (`crypto::space_mac_secret`).
3. The host returns an HMAC over the response under that key; the syncer
   recomputes it.

Because the syncer could have computed the same MAC itself, the MAC convinces the
syncer and nobody else: a leaked record cannot be proven to a third party. ("KEM"
is HPKE's name for the key-agreement half; nothing here encrypts data.)

So every account needs a KEM key whose private half the host holds and whose
public half its DID document publishes. Until now Custos published none: it
recommended `#atproto_space` (the signing key reused for space credentials) and an
`#atproto_space_host` service, and no wallet flow ever published them. The
reference implementation, at the pin, generates a P-256 KEM key at account
creation, adds `com.atproto.server.reserveKemKey` beside `reserveSigningKey`,
recommends `atproto` + `atproto_kem` from `getRecommendedDidCredentials`, and
refuses to activate a did:plc account whose document does not publish the key it
holds.

Two Custos facts make this more than a copy of the reference. First, a Custos
account's DID document changes only through an op the wallet signs: the wallet's
device key outranks the PDS key in `rotationKeys` (ADR-0001), so the PDS cannot
add `#atproto_kem` to an existing did:plc document on its own. Second, the commit
signer picks the account's active row in `signing_keys`; a second key in that
table could end up signing commits.

## Decision

We will give every account a dedicated P-256 KEM key, separate from its signing
key, and publish it the same way every other key in a Custos DID document is
published.

- **Custody.** KEM keys live in their own `kem_keys` table (V079) with the
  `active`/`staged` lifecycle and the master-key AES-256-GCM wrapping of
  `signing_keys`. They never get a `purpose` column in `signing_keys`, so the
  commit-signer lookup cannot return one. Reservations (`reserved_kem_keys`) and
  the DID ceremony's pending key (`pending_accounts.kem_*`) mirror the signing
  key's. All three are `SecretFamily` entries, so `rewrap-master-key` covers them.
- **Genesis.** Every new account is created with the key as
  `verificationMethods.atproto_kem`, whether or not `[spaces] enabled` is set.
  `GET /v1/repo-signing-key` issues it with the repo key; `POST /v1/dids` requires
  the wallet's op (or new self-hosted `did.json`) to publish exactly it. Agent
  children reserve one with `reserveKemKey` and must publish it.
  `createAccount` with a client op follows the reference: a published key must be
  reserved, and an op without one gets a fresh key held unpublished.
- **Migration.** `getRecommendedDidCredentials` returns `atproto` and
  `atproto_kem` and no longer recommends the `atproto_space*` entries.
  Migration-mode `createAccount` takes the key reserved for the DID, or mints one;
  `activateAccount` refuses a document that does not publish it (a did:web with no
  `#atproto_kem` entry at all is let through, as in the reference). The old host
  deletes its KEM keys when the account is deactivated and its live document names
  another host.
- **Existing accounts and rotation.** `POST /v1/kem-key` stages a fresh key;
  `POST /v1/kem-key/complete` publishes and promotes it. For did:plc the wallet
  signs an op that sets `atproto_kem` and drops `atproto_space` /
  `atproto_space_host`, and the PDS refuses any other change, as it does for
  ADR-0025's rotation op. For a self-hosted did:web the user uploads the updated
  `did.json` and the PDS promotes only when the live copy publishes the staged key.
  A Custos-hosted did:web is rewritten by the PDS at stage time. Rotation is manual
  only; nothing is scheduled.
- **Write refusal.** While an account's cached DID document does not publish its
  active KEM key, space writes answer `KemKeyNotPublished`. Reads are still served,
  without a MAC. The check reads the cache, never plc.directory.

## Consequences

- Space records written on Custos can carry MACs any reference syncer can check,
  and the deniability property holds: only the syncer and the host can compute a
  MAC.
- The KEM key never signs and never enters `rotationKeys`. Rotating it changes no
  repo hash, `rev`, or rotation authority, so it needs no repo write lock: a syncer
  whose MAC fails against a stale document re-fetches it and retries.
- Accounts created before this change cannot write to spaces until they run the
  ceremony. The wallet's "Update identity for Spaces" entry point and its op guard
  are follow-on wallet work (MM-688); until then such accounts are read-only in
  spaces. A one-off scan found no staging or production DID document carrying
  `#atproto_space*`, so dropping those entries strands nobody.
- The wallet's migration guard currently accepts only `atproto` from a
  destination's recommended verification methods; inbound migration to Custos needs
  it to accept `atproto_kem` (MM-688). Custos already recommended `atproto_space`,
  so this is not a new break.
- A lost or compromised master key now also takes the KEM keys with it. The
  master-key disaster runbook gains a "re-stage KEM keys" step; it needs no
  rotation key, so it runs before the repo-key rotations.
- Old wallets that omit `atproto_kem` from the genesis op can no longer create an
  account. New wallets read the KEM key as optional, so they still work against a
  Custos that predates this change.

## Alternatives considered

- **Reuse the signing key as the KEM key.** One key fewer to publish, but the same
  scalar would sign commits and take part in Diffie-Hellman with arbitrary
  syncer-chosen points, and rotating either would rotate both. The reference uses
  separate keys; so do we.
- **A `purpose` column on `signing_keys`.** Reuses the table and its queries, but
  every reader of `signing_keys`, the commit signer first, would have to filter on
  it forever, and one that forgot would sign with a KEM key. A separate table makes
  that mistake impossible; the queries are shared through `repo_keys::KeyFamily`
  instead.
- **Let the PDS add `#atproto_kem` to did:plc documents with its own rotation
  key.** It holds one, but it ranks below the wallet's, and every other DID
  document change in Custos is wallet-signed (ADR-0001, ADR-0025). A PDS-signed op
  would also let a compromised PDS key change the document without the wallet.
- **Reserve the KEM key inside `reserveSigningKey`.** The first draft of the
  custody decision did this, before atproto pull request 5974 added
  `reserveKemKey`. Following the reference keeps `reserveSigningKey`'s response
  unchanged for every existing client.
- **Generate KEM keys only when spaces is enabled.** Then turning spaces on would
  require a ceremony for every account created while it was off. Generating at
  genesis costs one stored key per account.
