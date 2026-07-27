---
title: Capabilities
description: What your deployment advertises to clients, what each capability means, and how you control it.
---

Custos tells clients what it can do. `com.atproto.server.describeServer` — the
public, unauthenticated endpoint every AT Protocol client already calls — carries
an extra `custos` object alongside the standard fields:

```json
{
  "did": "did:web:pds.example.com",
  "availableUserDomains": ["example.com"],
  "inviteCodeRequired": true,
  "phoneVerificationRequired": false,
  "custos": {
    "version": "0.8.1",
    "capabilities": ["sovereignSessions", "walletConsent", "walletAccountDelete", "didWebHosting"]
  }
}
```

A client reads `capabilities` and enables the matching features. Obsign, for
example, only offers to create a brand-new identity on a server that advertises
`createCeremony`, and only offers escrow-assisted recovery where `escrow` is
advertised — instead of calling the endpoint and interpreting the failure.

Two properties follow from this being a **list of named capabilities rather than
an "is this Custos?" flag**. First, your deployment is described by what it
actually offers: a Custos server running without a master key advertises fewer
capabilities, and clients adapt rather than break. Second, a server that sends no
`custos` object at all — the reference PDS, rsky-pds, millipds — simply has none
of these, and a well-behaved client falls back to standard AT Protocol behaviour.
Nothing here is required of anyone; the extension is additive, and clients that
do not know the field ignore it.

The complete, generated list lives in the
[capability reference](/operator/reference/capabilities/). This page explains what
each capability means for you and how to switch it on.

## Identifying your server

`GET /xrpc/_health` reports a self-identifying version string rather than a bare
number:

```json
{ "version": "custos v0.8.1", "db": "ok" }
```

This is the shape third-party AT Protocol diagnostic tooling reads to fingerprint
an implementation (millipds reports `millipds v…` the same way; the reference PDS
returns a bare commit hash that names no software). It is also what Obsign pings
when you point it at a server. Nothing in it is sensitive: it names software and
version, which any protocol-level probe can already infer.

## The capabilities

Each heading below is the literal name that appears in `custos.capabilities`.

### `createCeremony`

Custos-native identity creation: mobile signup, per-account repo signing key
issuance, and the client-authored `did:plc` genesis ceremony in which the user's
device key is written into the DID's rotation keys from the very first operation.
This is the only way an identity is born already sovereign — the standard
`createAccount` lexicon never lets a client author its own genesis rotation keys.

Without it, a wallet steers users to *import* an existing identity instead, and
the claim ceremony takes sovereign custody of an identity hosted anywhere.

**Controlled by:** `signing_key_master_key`. The ceremony issues each account a
repo signing key and stores it encrypted under the master key, so a deployment
with no `EZPDS_SIGNING_KEY_MASTER_KEY` cannot perform it and does not advertise
it. There is no separate switch: configure a master key (as any real deployment
should — see [Configuration](/operator/configuration/)) and the capability
appears.

### `escrow`

Custos holds one share of the account's 2-of-3 Shamir recovery split — encrypted,
and useless on its own — and releases it through the recovery gate: an emailed
one-time code, then a cancellable delay window during which the account holder is
notified and can abort. This is what makes recovery possible for a user who has
lost their device but still holds one share.

Without it, the wallet's recovery story is entirely self-held: the user keeps
both remaining shares themselves, and no server is involved in recovery at all.

**Controlled by:** `signing_key_master_key`. The stored share envelope is
encrypted under the master key, so a deployment without one cannot accept a
deposit or perform a release, and does not advertise the capability. The delay
window itself is tuned separately with `recovery.release_delay_secs`
(`EZPDS_RECOVERY_RELEASE_DELAY_SECS`, default 24 hours) — that changes how a
release behaves, not whether escrow is offered.

### `sovereignSessions`

Passwordless full-access sessions. Instead of a password, the client signs a
fresh, timestamped, nonce-bound proof with a key that is already in the
identity's current PLC rotation keys, and Custos verifies it against
plc.directory — never against a cached document. The account holder's device key
*is* the credential, so an account can have no password at all.

Everything that needs a full-access session rides on this: app passwords,
changing a handle, removing an identity, restoring media from a backup.

**Controlled by:** always. This is inherent to running Custos and has no operator
switch. It grants Custos no additional power over an identity — any current
rotation key qualifies, and rotation keys are the account holder's to control.

### `agents`

The [auth.md](https://github.com/workos/auth.md) agent surface: an AI agent or
automation registers with the server, the account holder confirms the claim from
their wallet (reading the exact scopes first), and the agent then exchanges its
assertion for narrowly-scoped, revocable, audited access tokens. Agent tokens can
never manage agents — including themselves — and every registration is revocable
from the wallet or by the identity provider.

**Controlled by:** `agent_auth.service_auth_enabled`,
`agent_auth.anonymous_enabled`, `agent_auth.trusted_issuers`. These are the three
ways an agent can register, and **all three are off or empty by default** — an
untouched deployment does not offer agents at all. Enable whichever registration
flows you want (`EZPDS_AGENT_AUTH_SERVICE_AUTH_ENABLED`,
`EZPDS_AGENT_AUTH_ANONYMOUS_ENABLED`, or a configured `[[agent_auth.trusted_issuers]]`
entry) and the capability appears. What a claimed agent may then do is bounded
separately by `agent_auth.granted_scopes`; narrowing it narrows every assertion
minted afterwards.

### `walletConsent`

An OAuth authorization can be approved in the identity wallet with a
device-key-signed decision, rather than by typing a password into a browser
consent page. The signed envelope binds the request, the client, the decision,
and the exact scope set, so an approval cannot be replayed onto a different
request, flipped from a denial, or widened after the fact.

**Controlled by:** always. This is inherent to running Custos and has no operator
switch. Password-based browser consent continues to work for accounts that have a
password; the wallet path is an additional, stronger route to the same grant.

### `optionalPassword`

An account can be created on this server with no password at all. A client that
sees this capability may omit the password field entirely when creating an
account; the account is stored with no password hash and authenticates
afterwards through its device key — wallet-confirmed OAuth consent and sovereign
sessions — plus app passwords for standard AT Protocol clients like the Bluesky
app.

Passwordless accounts are not a new storage shape: accounts that migrate in from
another server have always been stored without a password. What this capability
changes is only whether a *new* account may be created that way.

An **empty** password is refused whether or not this is enabled, and that is
deliberate: an empty string is what an uninitialised form field sends, so
accepting one would let a client bug create an account with no credential that
nobody asked for. Omitting the field is the only way to ask.

**Controlled by:** `accounts.password_optional`. Off by default — a passwordless
account depends on device-key custody you cannot verify on the account holder's
behalf, so a deployment whose users are not all running the identity wallet
should keep the password required. Enable it with `[accounts] password_optional =
true` (`EZPDS_ACCOUNTS_PASSWORD_OPTIONAL`) and the capability appears. Turning it
back off stops new passwordless accounts being created; it does not affect
accounts that already have no password, which keep working exactly as before.

### `walletAccountDelete`

An account can be permanently deleted with a device-key-signed proof from one of
its current rotation keys, in place of the account password. The emailed
single-use confirmation code is still required — this swaps one of the two
factors, it does not remove one.

This capability is what makes `optionalPassword` safe to turn on. Deletion is the
one operation that had no route around the password: an account created without
one could be made, used, and migrated, but never removed, because every
credential path answered with the same refusal and left the holder no way
forward. The proof closes that.

The signed envelope binds this server, the account, the signing key, the moment,
and a single-use nonce, and it is verified against the identity's **authoritative**
current rotation set read live from plc.directory — never a cached document. It is
accepted for accounts that *do* have a password too: a current rotation key can
already migrate or retire the identity outright, so it is the stronger credential,
and honouring only the weaker one would make the endpoint answer differently
depending on whether a password exists. Unknown accounts, wrong passwords, and bad
proofs remain one indistinguishable response.

**Controlled by:** always. This is the same key-sovereign trust model as
`sovereignSessions` and has no operator switch; password-based deletion continues
to work unchanged for accounts that have a password.

### `didWebHosting`

Custos serves an opted-in account's `did:web` document at the account's own
domain (`/.well-known/did.json`) and emits an identity event so relays re-resolve
after an edit.

Hosting is opt-in **per account**, never automatic, and only ever for a domain
the user controls: moving the document onto Custos trades away some of the
independence a self-hosted document gives an identity, so it is the account
holder's decision. Exit is a DNS repoint away.

**Controlled by:** always. The server-side capability is inherent to running
Custos and has no operator switch; whether any given account uses it is that
account holder's choice.

### `waitlist`

A public interest-signup waitlist for a pre-launch deployment: an unauthenticated
`POST /waitlist` accepting an email address plus an optional atproto handle, meant
to be posted to directly from a marketing page on another origin (the endpoint is
CORS-open and carries no credentials). Signups are idempotent per email — a repeat
returns the same success and never discloses whether an address was already on the
list — and the handle is syntax-checked but deliberately never resolved, so the
endpoint has no outbound-request surface. The operator reads the list back with
`GET /v1/admin/waitlist` (newest first, with a total), which keeps working even
after the public endpoint is switched off again.

**Controlled by:** `waitlist.enabled`. Off by default — an instance that isn't
running a launch funnel should not carry a public write endpoint it never asked
for. Enable it with `[waitlist] enabled = true` (`EZPDS_WAITLIST_ENABLED`) and the
capability appears; the per-IP signup rate cap is `rate_limit.waitlist_per_5min`
(`EZPDS_RATE_LIMIT_WAITLIST_PER_5MIN`, default 30).

## Keeping this page honest

The capability table in the server source
(`crates/pds/src/capabilities.rs`) is the single source of truth: it holds each
capability's wire name, the configuration that gates it, and the predicate the
server actually evaluates. The
[capability reference](/operator/reference/capabilities/) is generated from it,
and a CI gate (`just capability-docs-check`) fails the build if a capability is
added, renamed, or re-gated without this page being updated in the same change.
If a "Controlled by" line above disagrees with your server's behaviour, that is a
bug, not a documentation lag — please report it.
