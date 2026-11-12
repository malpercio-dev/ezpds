# ADR-0042: Unbound Bearer tokens for MCP connectors

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** malpercio
- **Related:** MM-652 (the decision), MM-647 (wayfinder map) and its research MM-648, MM-649, MM-650, MM-651; MM-636 (implementation); ADR-0024 (hosted agent credential forwarding); ADR-0019 (auth.md agent authentication); `crates/custos-oauth/src/routes/oauth_authorize.rs`, `crates/custos-oauth/src/routes/oauth_token/`, `crates/custos-core/src/auth/jwt.rs`, `tools/mcp-sidecar/`

## Context

A **connector** is a third-party MCP client that reaches Custos through the hosted
MCP sidecar using the MCP-spec OAuth handshake. That handshake has no pushed
authorization request and no DPoP. Custos requires both: `/oauth/authorize`
refuses a request without a PAR `request_uri`, and the authorization-code and
refresh grants refuse a request without a DPoP proof. The sidecar forwards
`Authorization: Bearer` (ADR-0024), and the PDS refuses a DPoP-bound token
presented that way. A connector therefore cannot get a token, and could not use
one if it did.

The research settled the facts. No target connector sends DPoP or has a published
plan to (MM-648). Connectors register through client metadata documents, which
Custos already accepts (MM-649). A connector acts as the user's own DID, a
client-held refresh token is acceptable, and nothing Custos hosts may hold a
credential that acts for the user, which rules out a front that exchanges for a
Custos token (MM-650).

Two things already exist. An OAuth grant whose `resource` is one of the
operator's `[oauth] connector_resources` is recorded as a `connector` agent
record: the owner sees and revokes it in My agents, and its tokens carry the
record's `registration_id`, so owner-only routes refuse them. And auth.md agent
tokens are already unbound Bearer tokens with a five-minute lifetime (ADR-0019).

What is new is an unbound token that acts as the user's own DID and is renewed by
a refresh token the client holds.

## Decision

We will issue unbound Bearer tokens to connectors, on narrower terms than a
DPoP-bound session.

**The trigger is the resource.** A request whose RFC 8707 `resource` matches an
entry in `[oauth] connector_resources` is a connector request. Matching compares
scheme, host, port and path, ignoring a trailing slash. There is no connector
client class: client metadata is self-asserted, so it cannot carry a privilege.
Any client may ask for connector terms, which is acceptable because the terms are
strictly weaker. An empty `connector_resources` (the default) leaves every
endpoint behaving as before.

**PAR and DPoP become optional for a connector request, and only for one.**

- `/oauth/authorize` admits a plain request when it names a connector resource.
  PKCE S256, a resolvable client metadata document and a registered redirect URI
  are still required. The plain request joins the same consent path a pushed one
  takes. Server metadata keeps `require_pushed_authorization_requests: true`.
- The token endpoint issues a token without a DPoP proof when the code or refresh
  family was issued for a connector resource. A connector that does send a proof
  gets a bound token as before.
- A loopback redirect URI matches its registered form on any port (RFC 8252
  §7.3) for a connector request. Every other request keeps exact matching.

**The terms.**

- *Scope ceiling.* A connector grant never carries `identity:*`, `account:*` or
  any `transition:*` scope. Scopes above the ceiling are dropped before the
  consent page renders and again when the token is issued.
- *Lifetime.* A connector access token lasts five minutes, the agent lifetime.
  Refresh tokens rotate on every use with the existing reuse detection, and the
  session keeps its 14 days.
- *Audience.* The token's `aud` is the configured connector resource. The PDS
  accepts a token whose `aud` is its own URL or a configured connector resource.
- *Target check.* A `resource` that is neither this server nor a configured
  connector resource is `invalid_target` at PAR, at `/oauth/authorize` and on the
  authorization-code and refresh grants. A token request that names a resource
  must name the one the grant was issued for.
- *Reach.* A connector token is accepted wherever a user OAuth token is, except
  the owner-only routes that already refuse agent-derived tokens.

**Recording an unbound family.** A refresh token stores the connector resource it
was issued for. A refresh row with no DPoP thumbprint is honoured only when it
carries a resource that is still configured. A row with neither stays refused as
a pre-binding legacy row, and removing a resource from the configuration ends its
families at their next refresh.

**Consent.** The consent page tells the user, on a connector request, that the
access is not tied to a device key and what it cannot do.

## Consequences

- Claude and other MCP clients can sign in through the sidecar and call tools as
  the user.
- A leaked connector access token is usable by anyone until it expires. The
  five-minute lifetime, the scope ceiling and the audience are what bound that. A
  leaked refresh token is bounded by rotation: the next legitimate refresh
  detects the reuse and ends the family.
- The audience does not confine a token to the sidecar. The sidecar only
  forwards, so whoever holds a connector token can call the PDS directly. The
  audience identifies what the token was issued for and lets the PDS refuse
  tokens minted for anything else.
- The owner revokes a connector in My agents. `/oauth/revoke` still requires a
  DPoP proof, so an unbound connector cannot revoke its own refresh token there.
- A user cannot grant a connector identity or account scopes at all. A connector
  that needs them is out of scope.
- The OAuth conformance suite keeps every assertion that PAR and DPoP are
  mandatory for other requests, and gains the connector handshake and its
  refusals.
- The wallet's own consent screen does not yet show the unbound-access notice.
  The browser consent page does. That is follow-up work.
- The sidecar must advertise the resource Custos is configured with, answer an
  unauthenticated request with a `401` naming its protected-resource metadata,
  and list the scopes a connector should request.

## Alternatives considered

- **Wait for MCP clients to support DPoP.** No target connector has a plan, and
  the spec proposal is an unmerged draft. This means no connector support for an
  unknown time.
- **A bearer-issuing front.** A Custos-hosted component would hold a DPoP-bound
  session and hand the connector its own token. It would hold a credential that
  acts for the user, which MM-650 and ADR-0024 rule out.
- **A connector client class.** Waive PAR and DPoP for clients on an allowlist
  or with a marker in their metadata. An allowlist does not scale to
  self-registered clients, and a marker is self-asserted.
- **A path allowlist for connector tokens.** Accept them only on the routes the
  sidecar forwards. It stops nothing the scope ceiling does not, and adds a
  second list to keep in step with the tool surface.
- **A shorter refresh session.** Rotation already covers a stolen refresh token;
  a shorter session mostly forces re-consent.
- **A new single `mcp_resource` setting.** `connector_resources` already exists
  and already classifies grants, so a second setting would be a duplicate.
