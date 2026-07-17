# Changelog

All notable user-visible changes to ezpds are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes are collected in `changelog.d/` during development and inserted here when
`just set-version` prepares a release. There is intentionally no `Unreleased` section.

## [0.5.2] - 2026-07-16

### Fixed

- The V047 database migration no longer fails on servers with recorded agent activity: the `agent_identities` rebuild now carries `agent_audit_events` through the table swap (preserving audit pagination order) instead of tripping its foreign key.


## [0.5.1] - 2026-07-16

### Added

- Generate API, operator configuration, and mobile IPC reference pages from their source registries, with CI parity checks that reject drift.

- Account owners can mint sovereign child agent identities: the server provisions a reserved repo-signing key while recovery authority stays in the wallet-signed PLC genesis operation.

- Credential-forwarding Streamable-HTTP MCP sidecar (`tools/mcp-sidecar/`, deployable as `mcp.obsign.org`): serves the existing Custos MCP tool surface over HTTP to many callers, authenticates each via OAuth against Custos, and forwards the caller's token per request while holding nothing durable — no on-disk credential cache, nothing that survives a restart (ADR-0024).

- The parent of a sovereign child agent can now read the child's audit trail and revoke it through the `/v1/agents/{registration_id}` management API — previously a child's audit trail was readable by no one (the child's own tokens are agent-derived and refused by the owner guard). Validated end to end by the new hosted-sidecar `create_post` acceptance suite (`just mcp-sidecar-test`).

- Operators can rotate the master encryption key (`EZPDS_SIGNING_KEY_MASTER_KEY`) with the new offline `pds rewrap-master-key` subcommand: every stored secret is re-encrypted from the old key to the new one in a single atomic transaction, and a wrong old key aborts with no writes.


### Changed

- DIDs are now rejected up front unless they are syntactically valid (lowercase method, valid identifier characters, size-bounded), matching the reference PDS on record writes and identity resolution.

- XRPC request bodies are now validated against the vendored `com.atproto.*` lexicon schemas before handling, so malformed input gets the reference PDS's exact 400 `InvalidRequest` responses (previously some malformed bodies got a non-standard 422 or 415, and schema violations the reference rejects were silently accepted).

- Handle, collection, and record-key validation is now checked against upstream AT Protocol conformance vectors.


### Fixed

- A PDS-custodied handle change now submits its PLC directory operation before opening the local handle-swap transaction, so the single-connection database is no longer held across the network call — one custodied handle change can no longer stall other in-flight requests.

- A permanent identity removal that was interrupted after the account was deleted but before the identity was retired on the network (for example, iOS killing the wallet mid-flow) now resumes automatically on the next launch instead of stranding a non-removable identity.


### Security

- Account-owner surfaces (agent claim confirm, agent list/revoke/audit, child-agent minting, did:web hosting) now enforce DPoP token binding: a DPoP-bound OAuth access token presented as plain Bearer without its proof is rejected instead of accepted.

- The caller-influenced well-known handle-resolution fallback now uses the SSRF-hardened HTTP client, closing a reflected-SSRF sink reachable through unauthenticated `resolveHandle` requests.


## [0.5.0] - 2026-07-15

### Added

- Permanently remove an identity from the wallet — deletes the account on the PDS, tombstones the DID in the PLC directory, and wipes local key material.

- did:web identities on Custos: migrate an existing did:web account onto Custos, optionally let Custos host its `did.json`, and create a new did:web identity through a guided ceremony in the wallet.

- Change your handle from the wallet: for sovereign identities, a device-key-signed `alsoKnownAs` update is submitted directly to the PLC directory.

- Operators can repair account state through new maintenance operations.

- Per-DID sovereign sessions: the wallet now holds a device-key-controlled session for each identity and restores, refreshes, and renews it without re-entering a password. The PDS issues these sessions and guards them with a nonce replay store.

- Documentation sites for Obsign (users) and Custos (operators) now build with Astro Starlight — navigable, searchable, and deployed as an independent static service, each in its own design register.


### Changed

- Enum-valued server environment variables are now parsed case-insensitively.

- Account emails are normalized to lowercase on every read and write, so sign-in and account lookups are case-insensitive.

- Onboarding now leads with a single "Create identity" action (did:plc on Custos); the did:web own-domain path is tucked behind a lower-priority "Advanced" link for experienced users, and the entry screen shows a Back action when opened from a wallet that already holds identities.

- XRPC procedures that accept no input now reject a non-empty request body instead of silently ignoring it.

- The create-account flow prefills the chosen handle and accepts the login handle case-insensitively.


### Fixed

- Fixed the wallet blanking on resume and several viewport and scroll layout glitches on mobile.

- PDS-custodied handle changes now update the authoritative PLC document, while wallet-sovereign identities remain device-key controlled.

- Fixed the source-PDS login prefill in the wallet migration flow.

- The PDS no longer fails to start on IPv4-only hosts when binding its iroh socket.

- The wallet reconciles an ambiguous or lost PLC submission before retrying, avoiding duplicate directory operations.


### Security

- Repo-write authentication paths now enforce DPoP token binding.

- Identity resolution and atproto-proxy fetches share a single SSRF-hardened HTTP client.


## [0.4.7] - 2026-07-12

Release history before changelog fragments were introduced is preserved in Git tags.

[0.5.0]: https://github.com/malpercio-dev/ezpds/releases/tag/v0.5.0
[0.4.7]: https://github.com/malpercio-dev/ezpds/releases/tag/v0.4.7
