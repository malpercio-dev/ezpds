# Agent authentication for {{service_name}}

## About this service

`{{service_name}}` is an **[AT Protocol](https://atproto.com) Personal Data Server
(PDS)** running at `{{public_url}}`. A PDS is the home server for a user's ATProto
identity: it hosts their account, their cryptographic identity (a `did:plc` or
`did:web` DID), and their **repository** — the signed, content-addressed log of all
their records (posts, likes, follows, profile, and any other lexicon record type),
plus the blobs (images, media) those records reference. It also speaks the ATProto
network on the account's behalf: serving the repo to relays over the firehose,
resolving handles and identities, and proxying reads/writes to an AppView.

This document supports **agentic registration**: an autonomous agent can obtain its
own credential to act on behalf of a user here, without a browser-based login. Once
registered and holding an access token (§4), an agent calls this server's
[XRPC API](https://atproto.com/specs/xrpc) — the same `com.atproto.*` and `app.bsky.*`
endpoints a normal client uses. Depending on the scopes granted at registration, that
can include:

- **Reading** the user's records and repository — `com.atproto.repo.getRecord`,
  `listRecords`, `com.atproto.sync.getRepo`, and AppView reads like
  `app.bsky.feed.getTimeline` proxied through this PDS.
- **Writing** on the user's behalf — `com.atproto.repo.createRecord`, `putRecord`,
  `deleteRecord`, `applyWrites`, and `uploadBlob` (e.g. posting, liking, following).
- **Resolving identity** — `com.atproto.identity.resolveHandle` / `resolveDid`.

An agent credential is scoped and revocable (§7): it is not the user's password, and
account-level and identity-level operations (rotating keys, changing the handle,
deleting the account) are **not** granted to agents.

- **Resource server:** `{{public_url}}`
- **Authorization server:** `{{public_url}}`

This service is both the resource server and the authorization server — they share
one origin. This document follows the [auth.md](https://github.com/workos/auth.md)
convention: read it top to bottom and you will know how to register, obtain an
access token, and call the API.

> **Scope of this document.** It describes the surface **this deployment actually
> exposes today**. Where the [auth.md](https://github.com/workos/auth.md) spec
> defines a mechanism that is advertised but not yet enabled here (the
> machine-pollable claim grant, provider-driven revocation), the relevant section
> says so explicitly and gives the working alternative. Trust the live discovery
> documents below over any cached assumption.

## 1. Discover

Fetch the two discovery documents. Neither requires authentication.

**Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)):

```http
GET {{public_url}}/.well-known/oauth-protected-resource
```

It names the authorization server(s) and the scopes this resource understands.

**Authorization Server Metadata** ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)):

```http
GET {{public_url}}/.well-known/oauth-authorization-server
```

Alongside the standard OAuth fields, it carries an `agent_auth` block that points
at the agent-registration surface:

```json
{
  "issuer": "{{public_url}}",
  "token_endpoint": "{{public_url}}/oauth/token",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:workos:agent-auth:grant-type:claim"
  ],
  "agent_auth": {
    "skill": "{{public_url}}/auth.md",
    "identity_endpoint": "{{public_url}}/agent/identity",
    "claim_endpoint": "{{public_url}}/agent/identity/claim",
    "events_endpoint": "{{public_url}}/agent/event/notify",
    "identity_types_supported": ["anonymous", "identity_assertion", "service_auth"],
    "identity_assertion": {
      "assertion_types_supported": ["urn:ietf:params:oauth:token-type:id-jag"]
    }
  }
}
```

> **Not everything advertised is live yet.** This metadata declares the full
> auth.md surface for forward compatibility, but on this deployment the
> machine-pollable `urn:workos:agent-auth:grant-type:claim` grant (§3.4) and the
> `events_endpoint` revocation channel (§7) are **not yet implemented**. The
> `claim_endpoint` — the claim ceremony itself — *is* live. The sections
> cross-referenced here give the working alternative for each not-yet-live
> mechanism. The live path is: register (§3) → complete the claim ceremony if one
> is required (§3.4) → exchange the assertion with the JWT-bearer grant (§4) →
> call the API (§5).

## 2. Pick a method

Register at `POST {{public_url}}/agent/identity` with a JSON body whose `type`
field selects the flow. Each flow is **opt-in per operator** and may be disabled on
this deployment; a disabled flow answers with a `*_not_enabled` error.

| You have… | Use `type` | Notes |
|---|---|---|
| An **ID-JAG** from a trusted identity provider | `identity_assertion` | The strongest path. The issuer must be on this server's trust list. |
| Only the **user's email** | `service_auth` | Starts a claim ceremony the user completes. |
| **No user identity at all** | `anonymous` | Opt-in per operator. Returns a limited pre-claim assertion + a `claim_token` — see §3.3. |

## 3. Register

### 3.1 `identity_assertion`

Present an ID-JAG (a JWT issued by a trusted identity provider) as the `assertion`:

```http
POST {{public_url}}/agent/identity
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "urn:ietf:params:oauth:token-type:id-jag",
  "assertion": "<ID-JAG JWT>"
}
```

The server verifies the ID-JAG's signature, `iss` (must be on the trust list),
`aud`, `exp`, and `auth_time` freshness.

- **Already confirmed** `(iss, sub)` binding → **200** with a service-signed
  `identity_assertion` you can exchange in §4:

  ```json
  {
    "registration_id": "reg_…",
    "registration_type": "identity_assertion",
    "identity_assertion": "<service-signed JWT>",
    "assertion_expires": "2026-01-01T00:00:00.000Z",
    "scopes": ["atproto", "blob:*/*", "repo:*?action=create&action=update"]
  }
  ```

- **First-seen** binding (email matches a local account) → **401
  `interaction_required`** with a claim block. The user must confirm before a
  credential is minted (see §3.4):

  ```json
  {
    "error": "interaction_required",
    "error_description": "user confirmation is required to bind this agent to the account",
    "claim_token": "clm_…",
    "claim": {
      "user_code": "ABCD-1234",
      "verification_uri": "{{public_url}}/agent/claim",
      "expires_at": "2026-01-01T00:10:00.000Z"
    }
  }
  ```

### 3.2 `service_auth`

When you know only the user's email, pass it as `login_hint`. The server starts a
claim ceremony bound to the matching local account and returns the claim block:

```http
POST {{public_url}}/agent/identity
Content-Type: application/json

{
  "type": "service_auth",
  "login_hint": "user@example.com"
}
```

**200:**

```json
{
  "registration_id": "reg_…",
  "registration_type": "service_auth",
  "claim_token": "clm_…",
  "claim": {
    "user_code": "ABCD-1234",
    "verification_uri": "{{public_url}}/agent/claim",
    "expires_at": "2026-01-01T00:10:00.000Z"
  }
}
```

### 3.3 `anonymous`

When you have no user identity at all, register anonymously. The server records an
ownerless pre-claim identity and returns a **pre-claim `identity_assertion`** carrying
a limited scope set (the operator's `pre_claim_scopes`) plus a `claim_token` for an
optional later claim ceremony:

```http
POST {{public_url}}/agent/identity
Content-Type: application/json

{
  "type": "anonymous"
}
```

**200:**

```json
{
  "registration_id": "reg_…",
  "registration_type": "anonymous",
  "identity_assertion": "<service-signed pre-claim assertion>",
  "assertion_expires": "2026-01-01T01:00:00.000Z",
  "scopes": ["atproto", "repo:*?action=create&action=update", "blob:*/*"],
  "claim_token": "clm_…"
}
```

This flow is **opt-in per operator**; when disabled it answers `anonymous_not_enabled`.
The pre-claim identity stays unclaimed until a user completes a claim ceremony that
binds it to their account, so its assertion **cannot yet be exchanged** at the token
endpoint (the JWT-bearer grant requires a claimed identity — §4). Hold the
`claim_token` and start the claim ceremony at the `claim_endpoint` (§3.4).

### 3.4 The claim ceremony

A first-seen `identity_assertion` and `service_auth` return a **claim block** at
registration (a `user_code`, a human-facing `verification_uri`, and an `expires_at`);
`anonymous` returns only a `claim_token`. Either way the ceremony has two steps.

**Start the ceremony** at the `claim_endpoint`. This is required for `anonymous`
(which has no `user_code` yet) and idempotent for the others (it re-emits the pending
`user_code` they already hold):

```http
POST {{public_url}}/agent/identity/claim
Content-Type: application/json

{ "claim_token": "clm_…" }
```

**200:**

```json
{
  "registration_id": "reg_…",
  "claim_attempt_id": "cla_…",
  "status": "initiated",
  "expires_at": "2026-01-01T00:10:00.000Z",
  "claim_attempt": {
    "user_code": "AB3D9F",
    "expires_in": 600,
    "verification_uri": "{{public_url}}/agent/claim",
    "interval": 5
  }
}
```

**The user confirms.** Show the user the `user_code` and direct them to the
`verification_uri`. There they confirm — with their own account credentials — that
this agent may act for them. Confirmation binds the registration to their account and
mints the agent's `identity_assertion`.

**Poll for the confirmation** at the token endpoint with the claim grant
(`urn:workos:agent-auth:grant-type:claim`), waiting `interval` seconds between
attempts:

```http
POST {{public_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:workos:agent-auth:grant-type:claim
&claim_token=clm_…
```

While the user has not confirmed yet the endpoint answers `authorization_pending`;
polling faster than the `interval` answers `slow_down` (back off before retrying).
`expired_token` means the claim window lapsed unconfirmed (start over at §3), and
`access_denied` means the registration was revoked — stop. Once the user confirms:

**200:**

```json
{
  "access_token": "<Bearer token>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "atproto blob:*/* repo:*?action=create&action=update",
  "identity_assertion": "<service-signed identity_assertion>",
  "assertion_expires": "2026-01-01T01:00:00.000Z"
}
```

The response carries both a live access token (usable immediately — §5) and the
minted `identity_assertion`: store the assertion and re-exchange it per §4 when
the access token expires.

## 4. Exchange the assertion for an access token

A service-signed `identity_assertion` is not itself an API credential — exchange it
at the token endpoint using the JWT-bearer grant
([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)):

```http
POST {{public_url}}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<service-signed identity_assertion>
&resource={{public_url}}
```

**200:**

```json
{
  "access_token": "<Bearer token>",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "atproto blob:*/* repo:*?action=create&action=update"
}
```

The `scope` is a granular AT Protocol scope string — by default a conservative
least-privilege profile (write to your own repo plus blob uploads; no account or
identity management). Operators can widen or narrow it via configuration; the
token grants exactly what the registration was clamped to, never more.

The agent identity must be **claimed** and the assertion `sub` (a DID) must match
it; an unclaimed or unknown identity returns `invalid_grant`, a revoked identity
returns `access_denied`, and a `resource` other than this origin returns
`invalid_target`.

## 5. Use the access token

Send the token as a Bearer credential on API (XRPC) requests:

```http
GET {{public_url}}/xrpc/com.atproto.repo.listRecords?repo=<did>&collection=<nsid>
Authorization: Bearer <access_token>
```

This is a plain sender-unconstrained Bearer token: **no DPoP** and **no refresh
token**. When it expires, obtain a new one by re-running the §4 exchange with a
fresh `identity_assertion` (re-register per §3 if the stored assertion has also
expired).

## 6. Errors

Failures use the OAuth-style `{ "error", "error_description" }` body.

| `error` | Meaning | What to do |
|---|---|---|
| `invalid_request` | Missing or malformed field (e.g. absent `type`). | Fix the request body. |
| `service_auth_not_enabled` | The operator has not enabled `service_auth`. | Use another flow, or ask the operator. |
| `anonymous_not_enabled` | The operator has not enabled `anonymous` (see §3.3). | Use another flow, or ask the operator. |
| `issuer_not_enabled` | The ID-JAG `iss` is not on the trust list. | Present an assertion from a trusted issuer. |
| `invalid_grant` | Bad assertion/signature, or the identity is unclaimed. | Re-register and finish the claim ceremony. |
| `login_required` | The ID-JAG's `auth_time` is too old. | Re-authenticate the user, then retry. |
| `interaction_required` | User confirmation is pending (carries a claim block). | Complete the ceremony (§3.4), then retry. |
| `access_denied` | No local account matches, or the identity is revoked. | Verify the email/identity is hosted here. |
| `invalid_target` | The `resource` is not this origin. | Set `resource` to `{{public_url}}`. |

## 7. Revocation

- **Credential layer.** The agent access token is a short-lived Bearer with no
  refresh token (§5): stop using one and it lapses at `expires_in`. The standard
  OAuth 2.0 revocation endpoint (RFC 7009), advertised as `revocation_endpoint`
  (`POST {{public_url}}/oauth/revoke`), revokes the **refresh token** an interactive
  OAuth client holds — a DPoP-bound request, keyed to the token's own proof-of-
  possession key, that answers `200` whether or not the token existed. An agent's
  refresh-token-less Bearer has nothing to revoke there and simply expires.
- **Registration layer.** A revoked agent identity can no longer exchange
  assertions (§4 returns `access_denied`). Provider-driven revocation via a Security
  Event Token at the advertised `events_endpoint` is **not yet enabled on this
  deployment**; today an operator revokes a registration server-side.
