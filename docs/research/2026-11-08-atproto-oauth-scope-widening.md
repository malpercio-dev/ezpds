# How atproto OAuth handles widening an already-authorized client's scopes

Research for MM-643, gathered 2026-11-08.

**Question.** When an atproto OAuth client that already holds a grant needs wider scopes, what do the protocol and the reference PDS expect?

**Answer.** Neither the protocol nor the reference PDS has an upgrade path. The client starts a new authorization request (PAR) with the wider scope. The new request produces a new token family. The old session is not widened. The reference client revokes the old session itself, and the server would otherwise leave both sessions live. The reference PDS keeps one record per (account, client) pair: the union of every scope the user has approved for that client. It uses the record only to decide whether consent can be skipped. Consent is skipped only when every requested scope is already in the record, and in practice only for confidential or trusted clients. When consent is shown, it shows the full requested set, not the newly added scopes. The specs add nothing beyond this. A session is fixed to its initial grant, and a permission set can grow under an existing grant without new consent.

Sources: the atproto specs at atproto.com, and `bluesky-social/atproto` at commit `7f619af` on `main`. File paths are relative to `packages/`.

## 1. Re-run PAR: a new grant, not an upgrade

- **The client re-authorizes with a new scope.** `@atproto/oauth-client` takes a per-call `scope` option that overrides the scope in the client metadata (`oauth/oauth-client/src/oauth-client.ts:257`). No endpoint or parameter widens an existing session.
- **Requested scopes must be declared in advance.** Every scope the client requests must already appear in its client metadata `scope`. The server rejects any undeclared scope with `invalid_scope` (`oauth/oauth-provider/src/client/client.ts:335-356`). The spec says the same: client metadata declares "all scope values which might be requested by this client", and the request scope "must be a subset" of them ([OAuth spec](https://atproto.com/specs/oauth), "Clients" and "Request Fields"). To widen beyond the declared set, the client must first publish new metadata.
- **Each code exchange creates a new token family.** `createToken` generates a fresh `tokenId` and refresh token. It stores the scope from that authorization request and does not look at existing tokens (`oauth/oauth-provider/src/token/token-manager.ts:113-180`).
- **A refresh cannot change scope.** The refresh-grant schema has only `grant_type` and `refresh_token`, with no `scope` field (`oauth/oauth-types/src/oauth-refresh-token-grant-token-request.ts`). `rotateToken` rebuilds the scope from the stored request parameters (`token-manager.ts:236-260`). RFC 6749 §6 allows a refresh request to narrow scope. The atproto profile leaves that out entirely.
- **What happens to the old session.** The server does not touch it, and the spec allows "multiple concurrent auth sessions" (OAuth spec, "Authorization Interface"). The reference client revokes the old session before it stores the new one: "We revoke any existing session first to avoid leaving orphaned sessions" (`oauth-client.ts:412-417`). Its session store is keyed by DID, so the new session replaces the old one rather than coexisting with it.

## 2. Remembered grants and consent in the reference PDS

- **Storage.** `AuthorizedClientData = { authorizedScopes: readonly string[] }`, held in a map keyed by client ID for each account (`oauth/oauth-provider/src/account/account-store.ts:102-103`). The PDS stores it in the `authorized_client` table, with primary key `(did, clientId)` and a JSON `data` column (`pds/src/account-manager/db/schema/authorized-client.ts`), and writes it with an upsert (`pds/src/account-manager/helpers/authorized-client.ts:10-35`).
- **Approval only adds scopes.** After the user consents, the server writes `old ∪ approved` back. It writes only when the client is new or the union has grown (`oauth/oauth-provider/src/router/create-api-middleware.ts:706-726`). The record never shrinks. The only delete helper removes every row for a DID (`authorized-client.ts:44`), and its only caller is `deactivateAccount` with `deleteCredentials` set (`pds/src/account-manager/account-manager.ts:456-467`). Revoking a session leaves the remembered grant in place.
- **When consent is required.** `checkConsentRequired` (`oauth/oauth-provider/src/oauth-provider.ts:389-406`) requires consent when any of these is true:
  - the client has no record;
  - the request has `prompt=consent`;
  - a requested scope is missing from `authorizedScopes`.

  If the request has no `scope`, a known client needs no consent. The comparison works on raw scope strings. An `include:` scope counts as one token and is not expanded first.
- **Skipping consent needs more than a covered scope.** The check feeds two paths: `prompt=none`, and automatic SSO when `login_hint` matches exactly one session (`oauth-provider.ts:654-657, 690-728`). Both also require that no new login is needed. The request manager then forces `prompt=consent` on every public client that is not trusted (`oauth/oauth-provider/src/request/request-manager.ts:259-276`). A third-party public client therefore sees the consent screen every time, even if nothing new is requested. This matches the spec: silent approval applies when "the user has already approved the same scopes for the same client in the past", it applies to confidential clients, and servers "can set their own policies" (OAuth spec, "Authorization Interface").
- **The consent screen shows the full set, not the new scopes.** The server removes `consentRequired` before it renders the page (`oauth-provider.ts:736-740`). It sends `permissionSets` for the whole requested `scope`. The UI receives no field for previously authorized scopes (`oauth/oauth-provider-ui/src/authorization-page.tsx:200-206`), so nothing marks which scopes are new.
- **The user can narrow a request but not widen it.** When the user approves, `narrowAuthorizedScope` keeps only the requested scopes the user ticked and refuses any that were not requested. It always requires `atproto` (`request-manager.ts:437-441`; tests in `request-manager.test.ts:14-43`). The spec says the granted scope "may reflect partial authorization by the user", and the token response must carry `scope` (OAuth spec, "Authorization Scopes").

## 3. Permission sets and `include:` scopes

- The permission spec says "OAuth session are strictly limited to the auth scopes in the initial grant" and "The permissions associated with an Access Token should remain fixed". It also says "Permission sets can be updated over time as new schemas are added to a namespace". All three are in the "Permission Sets" section of the [permission spec](https://atproto.com/specs/permission).
- Permission sets are the protocol's answer to scopes growing over time. A client requests `include:<nsid>` once. When the namespace owner adds resources to the set, the grant covers them without new consent. The spec does not describe incremental authorization or a delta-only consent screen.
- In the code, the set is re-expanded on every refresh: `rotateToken` calls `buildTokenScope` again (`token-manager.ts:260`), and cached lexicons go stale after five minutes (`oauth-provider/src/oauth-constants.ts:84`, used in `lexicon/lexicon-getter.ts:48-51`). An access token keeps its scope. The next refresh picks up the expanded set. The remembered-grant check stores the literal `include:` string, so an expanded set never triggers consent.

## 4. RFCs and incremental authorization

- **RFC 6749 §3.3.** The authorization server may grant less than was requested and must then return the granted `scope`. atproto adopts this and makes the `scope` field mandatory.
- **RFC 6749 §6.** A refresh may request a narrower scope. atproto drops this: the refresh grant has no `scope` field.
- **RFC 9126 (PAR).** PAR moves the request parameters to a back-channel push and defines nothing about scope changes. In atproto, widening is an ordinary new PAR request.
- **OIDC `prompt`.** atproto supports `none`, `login`, `consent`, `select_account` and `create` (`oauth-provider.ts:648-745`; `oauth/oauth-types/src/oauth-authorization-request-parameters.ts:86-87`). The provider code cites OIDC Core for `prompt`, but the spec rejects `openid` as a scope (`request-manager.ts:241-248`).
- **Google's `include_granted_scopes`.** This is a vendor extension and not part of any RFC. atproto does not adopt it: it does not appear anywhere in `packages/`. Each new token holds exactly the scope of its own request. To keep the old scopes, the client must request them again together with the new ones. That is cheap, because the full set must already be declared in client metadata.

## Implications for Custos

- No atproto mechanism widens a live grant in place. Widening is a new authorization that issues new tokens, and the old session is revoked or left to expire. If Custos widens an agent's stored grant in place, it does something atproto OAuth does not do. If Custos re-runs the grant ceremony instead, it follows atproto's pattern.
- The reference PDS's remembered grant is an only-growing union of approved scopes per (account, client). It controls whether consent can be skipped, not what a token holds. That matches Custos's stored grant only in part: Custos's grant also bounds the identity assertion. A union-only store would also never record that an owner narrowed or revoked a grant.
- Delta-only consent ("show only what's new") has no precedent in the reference PDS, which always shows the full requested set. If Custos shows only the delta, that is new UX of its own, not mirrored behaviour.
- Raising a ceiling has an atproto precedent. Client metadata `scope` caps what may ever be requested, and a client widens beyond it only by republishing metadata. The operator's scope profile plays the same role for agents. A permission set expanding under an existing grant is the one case where atproto widens permissions without new consent.
- `narrowAuthorizedScope` lets the user approve a subset of the request. A Custos widening ceremony could let the owner approve part of the requested widening in the same way.
