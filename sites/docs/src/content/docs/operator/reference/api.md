---
title: HTTP & XRPC API
description: Generated route reference for the Custos server.
---

> Generated from source for ezpds **v0.5.2**. Do not edit this page by hand.

Every path registered by the server is listed here. For `/xrpc/` endpoints, use the namespace after `/xrpc/` to find the request, response, and authentication schema in the [AT Protocol Lexicon reference](https://docs.bsky.app/docs/api/at-protocol-xrpc-api). Custos-specific endpoints are explained in the operator workflows elsewhere in this documentation; this generated inventory is the complete route-coverage index.

| Registered path | Family |
| --- | --- |
| `/` | Custos HTTP |
| `/.well-known/atproto-did` | Custos HTTP |
| `/.well-known/did.json` | Custos HTTP |
| `/.well-known/oauth-authorization-server` | Custos HTTP |
| `/.well-known/oauth-protected-resource` | Custos HTTP |
| `/agent/child` | Custos HTTP |
| `/agent/child/delete` | Custos HTTP |
| `/agent/child/revoke` | Custos HTTP |
| `/agent/event/notify` | Custos HTTP |
| `/agent/identity` | Custos HTTP |
| `/agent/identity/claim` | Custos HTTP |
| `/agent/identity/claim/confirm` | Custos HTTP |
| `/auth.md` | Custos HTTP |
| `/metrics` | Custos HTTP |
| `/oauth/authorize` | Custos HTTP |
| `/oauth/client-metadata.json` | Custos HTTP |
| `/oauth/jwks` | Custos HTTP |
| `/oauth/par` | Custos HTTP |
| `/oauth/revoke` | Custos HTTP |
| `/oauth/token` | Custos HTTP |
| `/static/{*path}` | Custos HTTP |
| `/v1/accounts` | Custos HTTP |
| `/v1/accounts/claim-codes` | Custos HTTP |
| `/v1/accounts/claim-codes/revoke` | Custos HTTP |
| `/v1/accounts/mobile` | Custos HTTP |
| `/v1/accounts/sessions` | Custos HTTP |
| `/v1/accounts/{id}/storage` | Custos HTTP |
| `/v1/accounts/{id}/usage` | Custos HTTP |
| `/v1/admin/accounts` | Custos HTTP |
| `/v1/admin/accounts/{id}/email` | Custos HTTP |
| `/v1/admin/accounts/{id}/reset-token` | Custos HTTP |
| `/v1/admin/accounts/{id}/revoke-credentials` | Custos HTTP |
| `/v1/admin/audit` | Custos HTTP |
| `/v1/admin/devices` | Custos HTTP |
| `/v1/admin/devices/{id}/revoke` | Custos HTTP |
| `/v1/admin/health` | Custos HTTP |
| `/v1/admin/pairing-codes` | Custos HTTP |
| `/v1/admin/recovery-releases` | Custos HTTP |
| `/v1/admin/relay-status` | Custos HTTP |
| `/v1/admin/request-crawl` | Custos HTTP |
| `/v1/admin/transfers` | Custos HTTP |
| `/v1/admin/transfers/{id}/cancel` | Custos HTTP |
| `/v1/agents` | Custos HTTP |
| `/v1/agents/claim-preview` | Custos HTTP |
| `/v1/agents/{registration_id}/audit` | Custos HTTP |
| `/v1/agents/{registration_id}/revoke` | Custos HTTP |
| `/v1/devices` | Custos HTTP |
| `/v1/devices/{id}/pds` | Custos HTTP |
| `/v1/did-web/document` | Custos HTTP |
| `/v1/did-web/hosting` | Custos HTTP |
| `/v1/dids` | Custos HTTP |
| `/v1/dids/{did}` | Custos HTTP |
| `/v1/handles` | Custos HTTP |
| `/v1/handles/{handle}` | Custos HTTP |
| `/v1/pds/keys` | Custos HTTP |
| `/v1/recovery/escrow-share` | Custos HTTP |
| `/v1/recovery/initiate` | Custos HTTP |
| `/v1/recovery/release` | Custos HTTP |
| `/v1/recovery/release/cancel` | Custos HTTP |
| `/v1/repo-keys/rotation` | Custos HTTP |
| `/v1/repo-keys/rotation/complete` | Custos HTTP |
| `/v1/repo-signing-key` | Custos HTTP |
| `/v1/sessions/sovereign` | Custos HTTP |
| `/v1/transfer/accept` | Custos HTTP |
| `/v1/transfer/complete` | Custos HTTP |
| `/v1/transfer/initiate` | Custos HTTP |
| `/xrpc/_health` | AT Protocol XRPC |
| `/xrpc/app.bsky.actor.getPreferences` | AT Protocol XRPC |
| `/xrpc/app.bsky.actor.putPreferences` | AT Protocol XRPC |
| `/xrpc/com.atproto.admin.getSubjectStatus` | AT Protocol XRPC |
| `/xrpc/com.atproto.admin.updateSubjectStatus` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.getRecommendedDidCredentials` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.refreshIdentity` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.requestPlcOperationSignature` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.resolveDid` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.resolveHandle` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.resolveIdentity` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.signPlcOperation` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.submitPlcOperation` | AT Protocol XRPC |
| `/xrpc/com.atproto.identity.updateHandle` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.applyWrites` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.createRecord` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.deleteRecord` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.describeRepo` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.getRecord` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.importRepo` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.listMissingBlobs` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.listRecords` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.putRecord` | AT Protocol XRPC |
| `/xrpc/com.atproto.repo.uploadBlob` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.activateAccount` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.checkAccountStatus` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.confirmEmail` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.createAccount` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.createAppPassword` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.createInviteCode` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.createInviteCodes` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.createSession` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.deactivateAccount` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.deleteAccount` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.deleteSession` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.describeServer` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.getAccountInviteCodes` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.getServiceAuth` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.getSession` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.listAppPasswords` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.refreshSession` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.requestAccountDelete` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.requestEmailConfirmation` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.requestEmailUpdate` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.requestPasswordReset` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.reserveSigningKey` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.resetPassword` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.revokeAppPassword` | AT Protocol XRPC |
| `/xrpc/com.atproto.server.updateEmail` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getBlob` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getBlocks` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getLatestCommit` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getRecord` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getRepo` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.getRepoStatus` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.listBlobs` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.listRepos` | AT Protocol XRPC |
| `/xrpc/com.atproto.sync.subscribeRepos` | AT Protocol XRPC |
| `/xrpc/com.atproto.temp.checkHandleAvailability` | AT Protocol XRPC |
| `/xrpc/com.atproto.temp.checkSignupQueue` | AT Protocol XRPC |
| `/xrpc/{method}` | AT Protocol XRPC |
