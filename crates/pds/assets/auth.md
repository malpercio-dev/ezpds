# Agent authentication for {{service_name}}

This service supports **agentic registration**: an autonomous agent can obtain its
own credential to act on behalf of a user, without a browser-based login.

- **Resource server:** `{{public_url}}`
- **Authorization server:** `{{public_url}}`

This service is both the resource server and the authorization server — they share
one origin. This document follows the [auth.md](https://github.com/workos/auth.md)
convention: read it top to bottom and you will know how to register, obtain an
access token, and call the API.

> **Scope of this document.** It describes the surface **this deployment actually
> exposes today**. Where the [auth.md](https://github.com/workos/auth.md) spec
> defines a mechanism that is advertised but not yet enabled here (the anonymous
> registration type, the machine-pollable claim grant, provider-driven revocation),
> the relevant section says so explicitly and gives the working alternative. Trust
> the live discovery documents below over any cached assumption.

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

## 2. Pick a method

Register at `POST {{public_url}}/agent/identity` with a JSON body whose `type`
field selects the flow. Each flow is **opt-in per operator** and may be disabled on
this deployment; a disabled flow answers with a `*_not_enabled` error.

| You have… | Use `type` | Notes |
|---|---|---|
| An **ID-JAG** from a trusted identity provider | `identity_assertion` | The strongest path. The issuer must be on this server's trust list. |
| Only the **user's email** | `service_auth` | Starts a claim ceremony the user completes. |
| **No user identity at all** | `anonymous` | Advertised, **not yet enabled on this deployment** — see §3.3. |

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
    "scopes": ["com.atproto.access"]
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

### 3.3 `anonymous` — not yet enabled

The `anonymous` type is advertised in `identity_types_supported` for spec
completeness, but this deployment cannot yet issue a credential to an agent with no
user identity: every agent identity is bound to an existing account. A request with
`type: "anonymous"` returns `anonymous_not_enabled` (or `temporarily_unavailable`
where the operator has toggled it on ahead of implementation). Use
`identity_assertion` or `service_auth` instead.

### 3.4 The claim ceremony

Both first-seen `identity_assertion` and `service_auth` return a **claim block**:
a `user_code`, a human-facing `verification_uri`, and an `expires_at`. Show the user
the `user_code` and direct them to the `verification_uri`; there they confirm that
this agent may act for them. Confirmation binds the registration to the account.

> **Polling — read this.** The auth.md spec defines a machine-pollable claim grant
> (`urn:workos:agent-auth:grant-type:claim`) and a `claim_endpoint`, both advertised
> in the discovery metadata. **They are not yet implemented on this deployment.**
> Until they are, complete the ceremony out of band: after the user confirms, an
> `identity_assertion` agent obtains its credential by simply **re-issuing the same
> `POST /agent/identity` request** — once the binding is confirmed the server returns
> the minted `identity_assertion` (the 200 shape in §3.1) instead of
> `interaction_required`. Back off between attempts and give up at the claim's
> `expires_at`.

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
  "expires_in": 900,
  "scope": "com.atproto.access"
}
```

The agent identity must be **claimed** and the assertion `sub` (a DID) must match
it; an unclaimed, revoked, or unknown identity returns `invalid_grant`, and a
`resource` other than this origin returns `invalid_target`.

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
| `anonymous_not_enabled` | `anonymous` is unavailable here (see §3.3). | Use `identity_assertion` or `service_auth`. |
| `issuer_not_enabled` | The ID-JAG `iss` is not on the trust list. | Present an assertion from a trusted issuer. |
| `invalid_grant` | Bad assertion/signature, or the identity is unclaimed/revoked. | Re-register and finish the claim ceremony. |
| `login_required` | The ID-JAG's `auth_time` is too old. | Re-authenticate the user, then retry. |
| `interaction_required` | User confirmation is pending (carries a claim block). | Complete the ceremony (§3.4), then retry. |
| `access_denied` | No local account matches, or the identity is revoked. | Verify the email/identity is hosted here. |
| `invalid_target` | The `resource` is not this origin. | Set `resource` to `{{public_url}}`. |

## 7. Revocation

- **Credential layer.** Access tokens are short-lived (§5); stop using one and it
  lapses at `expires_in`.
- **Registration layer.** A revoked agent identity can no longer exchange
  assertions (§4 returns `invalid_grant`). Provider-driven revocation via a Security
  Event Token at the advertised `events_endpoint` is **not yet enabled on this
  deployment**; today an operator revokes a registration server-side.
