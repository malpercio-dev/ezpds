# Changelog

All notable user-visible changes to ezpds are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes are collected in `changelog.d/` during development and inserted here when
`just set-version` prepares a release. There is intentionally no `Unreleased` section.

## [0.7.2] - 2026-07-22

### Added

- A periodic blob-integrity scrub sweep now re-hashes every stored blob against its recorded CID and size, and walks the blob directory for both orphan directions — a row whose file has gone missing and a file no row owns — surfacing bitrot, truncation, or a bad restore as an operator alarm (`blob_scrub_*` metrics, `GET /v1/admin/health`) months before a migration would trip over it. When a blob-mirror bucket is configured, a bad or missing file can be auto-healed from its verified-good copy (`[blob_scrub] auto_heal`, on by default).

- The migration blob-drain now degrades per-blob instead of parking the whole migration on a single dead blob: each blob is retried individually, and any that still can't be transferred are collected into a loss manifest the wallet shows you — which media, which post references it, and whether your previous server couldn't serve it or the new one refused it — so you can make an informed choice to continue without them rather than abandoning the run. Verification tolerates the accepted skips, and the progress screen surfaces the specific per-blob failure detail (fetch-from-source vs upload-to-destination) instead of a generic "couldn't transfer one or more blobs."

- Obsign can now keep a user-held backup of an account's media in the wallet's iCloud Drive folder ("Back up media" on the identity screen): an opt-in, incremental mirror of the account's blobs — every fetched file is verified against its content address before it is stored, the mirror size is always shown, and the copy is visible in the Files app. If the hosting server ever loses the originals, "Restore to server" uploads the mirrored files back byte-for-byte, so posts keep pointing at the same media — the one backup layer that survives the server itself failing.

- Brass Console operators can export a redacted, per-relay network-error log from Settings for troubleshooting.

- The user-held media backup now tops itself up in the background: on iOS, an opted-in identity's iCloud mirror is refreshed by a scheduled background task (BGProcessingTask), so media posted days ago no longer stays unprotected until the next time the app is opened. Each run is the same incremental, content-address-verified pass as "Back up now" and degrades per-identity, so one account's failure never stops the others. Settings gains a "Media backup" section to tune it: turn background backups off entirely, restrict them to while charging, or skip them on cellular data.

- If you've backed up your media to iCloud, migrating away from a server that has lost some of your blobs is no longer a loss: when your old server can't serve a piece of media during a migration, the wallet now falls back to your local backup copy, verifies it still matches its content hash, and uploads that copy to your new server. Because media is content-addressed the substitution is exact — nothing in your posts is rewritten — so a backed-up blob your old server dropped shrinks (ideally empties) the migration's loss manifest instead of forcing you to skip it.


### Changed

- The marketing site's copy now matches the shipped custody model: the three-rotation-key ordering (device, recovery, server), backup described as a device-created recovery secret split 2-of-3, the blob bucket mirror alongside Litestream, and identity-method jargon (did:plc) moved off the marketing pages into the docs site's new did:web coverage.

- Marketing FAQ now states the backup cadence precisely: the database streams off-box continuously, while photos replicate on a regular sweep.

- Restoring your iCloud media backup no longer stops at files iOS has offloaded to save space. When a backed-up file isn't on the device, the wallet now asks iCloud to download it, waits for it to arrive (with a time limit), verifies it still matches its content hash, and uploads it — so a restore on a device where most of the mirror has been evicted just works instead of handing you a long list of files to download by hand in the Files app. The restore summary shows how many files it pulled from iCloud first, so a slower restore explains itself. Files that are genuinely gone (no iCloud copy to download) are still reported per-file, and the run continues past them.


### Fixed

- Blob uploads are now crash-durable: bytes are written to a temp file, fsynced, atomically renamed onto the final content-addressed path, and the directory fsynced, before the blob is recorded — closing a gap where a crash or power loss could leave truncated bytes at a valid path even though the database row was already durable.

- `getBlob` now re-hashes each blob's bytes against its CID before serving and returns a 404 (flagging the scrub-sweep alarm counter) on a mismatch, so a corrupted file is never handed to downstream caches; verified responses now carry the `Cache-Control: public, max-age=31536000, immutable` header the blob-handling spec recommends.

- Wallet diagnostics exports now include redacted connection and timeout failures from account creation, OAuth refresh, and authenticated requests.


## [0.7.1] - 2026-07-19

### Added

- Blob files are now replicated off the deployment volume: configuring an S3-compatible bucket (`EZPDS_BLOB_MIRROR_*`, the same shape as the Litestream variables) enables a periodic mirror sweep that uploads every stored blob after verifying its bytes against its CID, and a restore-on-boot pass that heals any blob file missing from the volume out of the bucket before the server takes traffic — so blobs lost with the volume can be recovered from the mirrored copy instead of being gone for good.

- Custos can now validate records against arbitrary resolved ATProto lexicons, including required and nullable fields, string formats, collection key rules, refs and unions, and array, byte, and blob constraints, with conformance pinned to the upstream record-data interop vectors.


### Changed

- The instance landing page and the OAuth consent and error pages now follow the viewer's system light/dark appearance, matching the identity wallet and the marketing and docs sites.

- Corrected the repo-engine lexicon module's own documentation to reflect that it now validates record data against a resolved lexicon, not only lexicon documents themselves.


### Fixed

- `com.atproto.server.getServiceAuth` now accepts app-password sessions for non-protected methods (and privileged app passwords for the `chat.bsky.*` surface), matching the reference PDS. Previously it required a full-access token and rejected every app-password session, which broke video upload from the Bluesky app (the app authenticates to a self-hosted PDS with an app password). Protected account-management methods remain blocked for all credentials.

- Migrating an account into this PDS now announces the identity change so the network re-resolves it: `activateAccount` force-refreshes the account's cached DID document from the authoritative PLC source and emits an `#identity` firehose frame, and `submitPlcOperation` emits `#identity` after a successful operation. Previously a migrated-in account could keep serving its pre-migration DID document (old PDS endpoint and signing key) in `getSession`/`describeRepo`, causing clients to route to the old PDS and fail service-auth verification ("Token could not be verified") on feeds and video upload.

- OAuth token responses now include the account DID in the `sub` field, as the AT Protocol OAuth profile requires. Third-party atproto clients (such as tangled.org) previously failed to complete sign-in because the token response omitted `sub`.


## [0.7.0] - 2026-07-18

### Added

- Obsign Settings now has an **Export diagnostics** action that shares a redacted log of the session's network errors — operation, server host, HTTP status, and short error code only, never tokens, request/response bodies, or account data — so a network problem can be handed to support without a device or simulator.

- The marketing site (about.obsign.org) now follows the visitor's system light or dark appearance, in the same warm "archive at night" palette as the wallet.

- Shared links to the marketing site now unfurl with branded Open Graph preview cards for both the Obsign and Custos pages.

- Added ATProto lexicon meta-schema and data-model validators (`repo-engine`), gated against the vendored `bluesky-social/atproto-interop-tests` `lexicon/` and `data-model/` acceptance/rejection vectors, so a malformed lexicon document or a non-conformant data-model value is caught against the same fixtures the reference implementation uses.

- Wallet-confirmed OAuth consent (Phase A): a sovereign or migrated account with no password can now sign in to third-party OAuth apps using only its wallet. The consent page shows a typed code and an "Open in Obsign" handoff link; the wallet previews the app, origin, and requested scopes, lets you reduce the granted scope, and approves with a biometric-gated device-key signature verified against your identity's authoritative PLC rotation keys. Approvals are single-use, expire in about five minutes, cannot be replayed onto a different request or a widened scope set, and both approvals and denials are audited.

- Signing in to an OAuth app across devices no longer needs typing: the sign-in page now shows a QR code beside the short code, and the Obsign wallet can scan it with the phone camera to approve the login with your device key. The wallet always re-fetches the app, origin, and requested permissions from your server by the request's id — never from the QR — before the biometric confirmation, and the typed code stays as the fallback when there's no camera.


### Changed

- The documentation sites' screen tours now cover the v0.6.0 screens — share recovery (including the escrow waiting period), app passwords, the "Add a recovery key" upgrade prompt, and the operator console's audit log — and the wallet's browser-harness fake now models the current three-key recovery rotation ([device, recovery, PDS]) so the pictured DID document shows the recovery key.

- Retired the legacy server-side recovery-share path from account creation: `POST /v1/dids` now requires the wallet-generated recovery key and escrow share for a did:plc identity (the server never generates or splits a recovery secret), and did:web identities are created without recovery escrow. The now-dead pending-share columns were dropped from the database.


### Fixed

- Permanent account deletion no longer fails on accounts with email-verification history or sovereign child agents: all account-keyed references are purged or safely unlinked (a schema tripwire test now enforces this), and deleting a parent schedules its children for deletion instead of stranding them.

- The wallet's "Add a recovery key" flow no longer reports every failure as a connection problem: a directory throttle now says to wait a moment, a directory or server problem is named as such, and only real transport failures say "check your connection".

- Exportable network diagnostics now capture connection failures (timeouts, DNS, refused connections, TLS), not only server-error responses — so a "Couldn't reach the server" error (such as when adding a recovery key) no longer produces an empty diagnostics log.

- "My agents" no longer fails with a misleading "check your connection" error when your session has expired. The agent-management surface is now per-identity (opened from an identity's detail screen) and runs through the same refreshable per-identity session as app passwords and change-handle: an expired session self-heals, or prompts a quick biometric unlock, instead of dead-ending on a never-refreshed login token.

- The sovereign-child mint tests no longer race wiremock's shared mock-server pool: the mock plc.directory guard is now held for each test's lifetime, fixing a CI-only flake where a parallel test could reset the pooled server mid-mint and surface as a spurious 502. No runtime behavior changed.

- Adding or recovering a recovery key no longer fails instantly with "Couldn't reach the server": the wallet's authenticated HTTP client sent PUT requests (used to deposit your recovery share) but its internal sender only handled GET and POST, so every deposit failed before any network call and was mislabelled as a connection problem. PUT requests are now sent correctly, and connection failures on the escrow and session-refresh paths are recorded in the exportable diagnostics log.

- The wallet's signing-key rotation, change-handle, and app-password flows no longer report every failure as a connection problem (matching the earlier re-key fix): a directory or server throttle now says to wait a moment, a directory or server problem is named as such, and only real transport failures say "check your connection".


## [0.6.0] - 2026-07-17

### Added

- Custos now watches labelers: configure `[labeler] watched` with any labeler DIDs (with optional per-labeler label watchlists) and a background pass polls each labeler's `com.atproto.label.queryLabels` for the hosted accounts, persisting the labels currently in force (honoring negations and expiry). Flagged accounts sort first on the operator account listing (`GET /v1/admin/accounts`, each row carrying its `flags` and the page a `flaggedTotal`), the health readout reports a `flagged` account count plus the watcher's last pass, and the Brass Console renders the triage view — a flagged-accounts notice on Home and per-row `⚑` flag lines (label value · labeler · date) on the Accounts screen.

- Operators can now see whether the upstream relay is actually crawling and indexing their server: a new admin readout (`GET /v1/admin/relay-status`) compares the PDS's exact sequencer head against what the relay reports for the host via `com.atproto.sync.getHostStatus`, surfacing the relay's lifecycle status, its cursor, the exact gap, and when it last consumed an event — plus a "Request crawl" action (`POST /v1/admin/request-crawl`) that re-invites the relay on demand. The admin-companion (Brass Console) Home screen renders it as a live federation-health block, polling every 15 seconds, with reachable / crawling / behind-by-N / not-seen states shown as text + icon (never color alone).

- Custos now keeps a server-wide admin audit log: every privileged operator action (takedowns, credential sweeps, code mints and revokes, device pairings and revocations, transfer cancels, account repairs, crawl requests) is durably recorded with the credential that signed it — master token or specific paired device — and served at `GET /v1/admin/audit` with filters and pagination. The Brass Console gains an Audit screen to browse it: reverse-chronological, filterable by action, with per-event drill-in by actor or subject.

- A wallet-custodied account can now rotate its repo signing key to a freshly generated one end-to-end: the wallet's new "Rotate signing key" flow stages a fresh key on the PDS (`POST /v1/repo-keys/rotation`), device-key-signs the DID-document key swap, and hands it back for submission (`POST /v1/repo-keys/rotation/complete`) — the PDS submits to plc.directory and cuts its commit signer over atomically under the account's repo write lock, so no commit is ever signed by a key absent from the DID document, and the retired key material is deleted after cutover (ADR-0025).

- Every natively-handled GET endpoint (`com.atproto.sync.*`, `com.atproto.repo.{getRecord,listRecords,describeRepo,listMissingBlobs}`, `com.atproto.identity.resolve*`, `com.atproto.server.getServiceAuth`) now validates its query parameters against the same vendored `com.atproto.*` lexicon schemas request bodies already use: a missing required parameter, a malformed value (DID, handle, NSID, CID, TID, …), or an out-of-range `limit` gets the reference PDS's 400 `InvalidRequest` envelope with byte-identical messages (e.g. `Params must have the property "repo"`, `Params/limit can not be greater than 100`), replacing axum's bare `Query`/`RawQuery` extractors and their plain-text rejections.

- Record writes (`createRecord`, `putRecord`, `applyWrites`) now run full lexicon-schema validation against a vendored set of `app.bsky.*` record types (posts, likes, reposts, follows, blocks, lists, profiles): an invalid record of a known type is rejected by default, the `validate` flag makes validation required (`true`) or skipped (`false`), the record's `$type` must match the write's collection, the record key must satisfy the lexicon's key rule (e.g. a TID for posts), and each write reports `validationStatus` (`valid` / `unknown`) — matching the reference PDS's `assertValidRecord` behavior. Records in collections Custos doesn't recognize stay writable and are reported as `unknown`.

- A parent account can now permanently delete a sovereign child agent it provisioned (`POST /agent/child/delete`): the call revokes the child's capability, deactivates it immediately so relays stop serving its repo, and schedules a permanent purge after a configurable grace window (`accounts.child_deletion_grace_secs`, default 24 hours) — after which the scheduled-deletion reaper removes the child's account, repo, handle, and blobs and emits an `#account status="deleted"` firehose frame, exactly like `deleteAccount`. Ownership is enforced like revoke (an unknown or foreign child DID returns a uniform 404 and agent-derived credentials are refused), the deletion is recorded in a durable tombstone that outlives the purged child, and the wallet-held recovery key and did:plc identity are left untouched for the wallet to retire.

- The Obsign wallet can now mint, list, and revoke Bluesky app passwords for a key-sovereign account. Sovereign accounts are deliberately passwordless, so the official Bluesky app — which signs into a third-party PDS with a password `createSession`, not OAuth — previously had no way to log in; the wallet's new App passwords screen (full-access, biometric-gated) creates a named scoped password to paste into the Bluesky app once, shows it exactly once at mint time, and revokes it per-name at any time.

- The PDS now stores its escrowed recovery share (Share 2 of the 2-of-3 split) in a dedicated `recovery_escrow` table, AES-256-GCM-wrapped under the master key from day one and covered by `pds rewrap-master-key`, with new account-owner endpoints to deposit/replace (`PUT /v1/recovery/escrow-share`) or opt out of (`DELETE /v1/recovery/escrow-share`) escrow, an append-only `recovery_audit_events` trail recording every escrow lifecycle action, and full cleanup on account deletion.

- Custos can now release a wallet's escrowed recovery share (Shamir Share 2) behind an email-OTP gate with a cancellable delay window — the server half of the escrow-assisted recovery ceremony. `POST /v1/recovery/initiate` (public, always-200, no enumeration) emails a single-use 1-hour OTP to the account address; `POST /v1/recovery/release` consumes the OTP to open a release that stays `pending` for a configurable delay (`[recovery] release_delay_secs` / `EZPDS_RECOVERY_RELEASE_DELAY_SECS`, default 24h) before the share becomes collectable by re-polling, with every step audited (`release_requested`/`released`) and notified to the account email; `POST /v1/recovery/release/cancel` (account-owner authed) kills a pending release, composing with `revoke-credentials` for a compromised-mailbox response. A wrong/expired/replayed OTP, an unknown handle, and an escrow-deleted account all fail identically (uniform 401, no oracle); initiate + release share one per-IP rate-limiter instance so alternating them can't double the OTP-guess budget. Operators see in-flight releases at `GET /v1/admin/recovery-releases`.

- The Obsign wallet gained the "Recover from backup shares" onboarding path: any two of the three Shamir shares recover an identity onto a new device. The escrow-assisted path auto-loads Share 1 from iCloud Keychain and releases Share 2 via the server's emailed-code escrow flow (honest pending-delay wait state, cancelled-release handling); the fully sovereign path takes Share 1 plus the Share 3 word phrase and touches only plc.directory until re-escrow. Reconstruction is verified against the DID's authoritative rotation keys before anything signs, corrupted shares and cross-generation shares fail with distinct human-legible errors, and a mandatory — and restart-resumable — rotation epilogue voids the lost device's entire share world (fresh share set, new recovery key, re-escrowed Share 2, rewritten iCloud share, new Share 3 walkthrough).

- Existing accounts created under the old server-generated recovery model can now migrate to the client-generated one: a calm "Add a recovery key" prompt on the wallet home surface (shown only for old-model did:plc identities) runs a per-DID re-key that generates a fresh recovery seed on-device, inserts the derived recovery key into the DID document's `rotationKeys` via a device-key-signed PLC operation, re-escrows the Share 2 envelope with the server — which voids the dead legacy server-held share in the same transaction — rewrites the iCloud-Keychain Share 1, and walks through the new Share 3 word phrase. Every step is additive and resumable: the device key never leaves `rotationKeys[0]`, so an interrupted migration never drops recovery below its pre-migration baseline.


### Changed

- Record writes (`createRecord`, `putRecord`, `applyWrites`) now reject a malformed top-level `createdAt` datetime or any malformed `at://` AT-URI in the record, matching the reference PDS's format checks for records it recognizes.


### Fixed

- Sovereign-session replay nonces are now pruned after their safe retention window instead of accumulating indefinitely.


### Security

- The DID ceremony now generates its recovery material client-side (the ceremony inversion): the wallet mints the recovery seed, derives a recovery rotation key placed in the genesis `rotationKeys` as `[device, recovery, PDS]` (ADR-0027), splits the seed 2-of-3 into versioned share envelopes, and deposits exactly one share — the Share 2 envelope — with the server, which stores it KEK-wrapped in `recovery_escrow` atomically with promotion. The server never sees the seed or the other shares, so no database backup can ever hold reconstruction material. Share 3 is now presented as a 42-word phrase (with a QR machine form), and the wallet stages the share set in a local Keychain slot until backup is confirmed so a mid-ceremony retry reuses the same set. Legacy-shaped requests from pre-inversion wallet builds (and all did:web ceremonies) keep working via the old server-side path for a transition window, flagged in logs for adoption tracking.


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
