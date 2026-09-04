# Changelog

All notable user-visible changes to ezpds are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes are collected in `changelog.d/` during development and inserted here when
`just set-version` prepares a release. There is intentionally no `Unreleased` section.

## [0.16.1] - 2026-09-03

### Added

- DPoP proof verification is now pinned against the RFC 9449 normative vectors (Figure 8 JWK thumbprint, Figure 2 token-request proof, Figure 13 resource proof with `ath`), so a canonicalization or hashing regression in the ES256 `cnf.jkt` path fails a known-answer test instead of only a length check.

- The Custos MCP `upload_blob` tool now takes the blob inline as base64 (`data` argument, either a `data:` URL or bare base64 alongside `mime_type`), so a remote client over the hosted sidecar can upload an avatar, banner, or thumbnail without a shared filesystem — previously the tool read only from the sidecar's own `CUSTOS_MCP_IMAGE_DIR` volume, which a remote agent cannot write to. Reading by `path` remains for stdio callers that do share the server's filesystem; passing both is refused, and inline uploads are capped at 5 MiB decoded (the sidecar's request-body ceiling rises to match).


### Fixed

- The wallet now defaults to `https://pds.obsign.org` instead of the retired `obsign.org` apex, which has answered 404 for every PDS call since the 2026-07-24 hostname migration. A fresh install no longer pre-fills a server it cannot reach, and an install that saved the apex before that date is rewritten to the serving host on launch rather than staying wedged.

- The wallet now writes did:web documents with bare `#device`, `#atproto`, and `#atproto_pds` ids instead of DID-qualified ones. Some third-party resolvers only match the bare form, so a wallet-composed identity could resolve on Custos yet fail to load elsewhere. Custos accepts both forms.


## [0.16.0] - 2026-09-03

### Added

- Groundwork for agent child accounts: the crypto layer can now derive an account's delegation seed and per-child account seeds from its recovery seed, so a child's rotation key needs no new stored secret. Nothing uses these yet — no change to existing accounts or keys.

- An account owner can now renew a sovereign child agent's expired credential without re-provisioning it: `POST /agent/child/assertion` issues a fresh identity assertion for an active child, re-clamped to the operator's current agent scopes and recorded on the child's audit trail. Revoked children, agent-derived callers, and other accounts' children are refused.

- An agent that registers anonymously can now be given an account of its own instead of a credential to act as you. It proposes a handle (`handle_hint`), the claim-approval screen shows that proposal, and confirming with a signed genesis op mints the agent its own DID, repo, and handle under your cryptographic ownership — the agent's existing claim poll simply returns a credential subject to the new account, with no change on its side. Servers advertise the capability as `agent_auth.child_provisioning`, and the served `auth.md` documents the flow.

- The wallet can now hold the delegation seed that lets an identity give an agent an account of its own: new identities get it during the recovery-share ceremony, and any identity created earlier can enable it from My Agents by entering two of its recovery shares. Nothing is rotated or published — the shares are checked against the public record, and only the device changes.

- When an agent registers on its own, the approval screen now offers a second answer: instead of letting it act as you, you can give it an account of its own — its own handle and its own record, with a recovery key derived from your seed so the account stays yours. The agent can propose a handle; you decide it. If your server turns the handle down, nothing is spent and you can simply pick another.

- The wallet's My Agents screen now lists the agent accounts you have minted alongside the agents acting on your behalf, and opens each one on a detail screen showing its handle, DID, permissions, and full activity record. From there you can renew a dormant agent's credential, revoke it while keeping its account and history, or delete the account outright — which takes it offline immediately and shows the date its data is permanently removed.

- Restoring your wallet on a new device now brings your agents' accounts back with it. My Agents re-derives each account's recovery key from your recovery seed and checks it against the public directory, so the wallet can tell you plainly which agent accounts it can still recover — and names any it cannot, rather than leaving you to find out during an emergency. An account it simply could not reach is reported as unchecked, never as lost.

- `create_post` on the Custos MCP server takes an `embed`, so an agent can publish quote posts and external link cards. Previously the only embed it could produce was an image attachment from `image_path`, which left quoting another post — and posting a link with a preview card — out of reach entirely. The value is written to the record as given (`app.bsky.embed.record` for a quote, `app.bsky.embed.external` for a card), so anything the lexicon accepts is reachable; `upload_blob` supplies a ref for a card's thumbnail. Passing both `embed` and `image_path` is refused rather than silently dropping one.

- The Custos MCP server exposes an `upload_blob` tool: upload a file and get its blob ref back, for setting an avatar or banner or filling any other record field that takes a blob. Until now blob upload only happened inside `create_post`'s image attachment, so anything else meant calling `com.atproto.repo.uploadBlob` on the PDS by hand. Files are read from the same confined `CUSTOS_MCP_IMAGE_DIR` directory `create_post` uses — with it unset, uploads stay disabled.

- Agents connected over MCP can now update the account's Bluesky profile — display name, description, avatar, and banner — with a single `update_bluesky_profile` call, instead of needing the operator to unlock the raw record-write tools. It reads the current profile first and changes only the fields named, so nothing you did not mention is lost, and a profile edited somewhere else mid-call makes the write fail rather than quietly overwrite it. An avatar or banner can be given as a file to upload or as a ref from an upload you already did.

- Agent identities can now read the AppView through the PDS proxy: the default `[agent_auth] granted_scopes` profile gains `rpc:*?aud=did:web:api.bsky.app`, so an agent can see the likes, reposts, and replies its own posts earned and read its own notifications instead of getting `InsufficientScope`. The grant is bound to the AppView audience rather than `aud=*` — the proxy signs service auth with the account holder's own repo key — and existing registrations pick it up when they re-register or re-claim. The wallet now names the service an `rpc:` grant reaches ("Call the Bluesky app service on your behalf") instead of describing every one of them as "other services".


### Changed

- Agents can now delete records in the account they were claimed against: the default `[agent_auth] granted_scopes` profile adds `repo:*?action=delete`, so an agent that publishes a mistaken post can retract it instead of escalating to the operator. This does not widen what an agent can destroy — the profile already granted `action=update`, which overwrites a record just as irreversibly. Agent registrations created before this release keep their existing scopes and pick delete up when they re-register or are re-claimed.

- Agent identity assertions for confirmed bindings no longer strand sporadic agents behind a fresh claim ceremony: every successful jwt-bearer exchange now returns a renewed `identity_assertion` (a sliding window the Custos MCP client persists automatically), and assertions minted for claimed bindings — claim confirmations, re-mints, and sovereign-child capabilities — live `[agent_auth] claimed_assertion_ttl_secs` (default 30 days) instead of the 1-hour pre-claim TTL. Revocation remains the kill switch: a revoked identity is refused at its next exchange regardless of the assertion's remaining lifetime.


### Fixed

- The served `auth.md` skill's discovery example now shows the `agent_auth.events_supported` and `agent_auth.child_provisioning` fields the server already advertises at `/.well-known/oauth-authorization-server`, so an agent reading the skill top to bottom sees the same metadata shape it will fetch.

- Connecting an MCP client to the hosted Custos server no longer dead-ends during sign-in. The server told clients to authorize against an address that had stopped serving Custos, so the standard OAuth discovery walk stopped with nothing to go on. It now reports the authorization server the PDS itself publishes, so the two can no longer disagree — and if it cannot read that, it says so and asks the client to retry rather than sending it somewhere wrong.

- The Custos MCP `whoami` tool no longer reports the PDS base URL. On the hosted sidecar that field carried the deployment's internal hostname (`http://ezpds.railway.internal:8080`) straight back to the client; a stdio caller configures the URL itself, so the field told nobody anything they did not already know.

- The Custos MCP tools now check text against the limits atproto actually enforces, before writing. `create_post` advertised a 3000-character ceiling while `app.bsky.feed.post` caps text at 300 graphemes (and 3000 UTF-8 bytes), so a long post was accepted by the tool and then refused by the PDS with a raw `InvalidRequest`; the same mismatch applied to `update_bluesky_profile`'s display name and description. Over-long text is now rejected with a message naming the limit and how far past it you are, counting grapheme clusters and UTF-8 bytes rather than JavaScript characters.

- Posts published through the Custos MCP `create_post` tool now carry rich-text facets: URLs, `#hashtags`, and `@mentions` in the post text render as links instead of dead plain text, and linked URLs get their social card. Detection covers fully-qualified `http(s)://` URLs (bare domains are left alone so filenames and prose are not turned into links); a `facets` argument overrides it when the link text differs from the URL.

- Failed agent token exchanges now say why: an expired identity assertion, an unclaimed or unknown registration, and a subject/DID mismatch each get their own `error_description` on the jwt-bearer grant (revocation stays the distinct `access_denied`), and the Custos MCP client routes on them — a lapsed assertion still triggers the re-onboarding path, but a rejected-as-invalid assertion now fails loudly instead of looking like a session expiry, so a sporadic agent can tell "re-register" from "revoked, stop" without operator archaeology.


## [0.15.0] - 2026-08-29

### Added

- The Atproto Spaces surface is now operator-gated behind `[spaces] enabled` / `EZPDS_SPACES_ENABLED` (off by default while the protocol is pre-launch alpha; deployments already using spaces must set it). When enabled alongside a signing-key master key, `describeServer` advertises a new `spaces` capability so clients and syncers can discover the surface — without a master key, space writes succeed but the sync routes 503, so the capability is withheld. `GET /v1/admin/health` now also reports the space jti-replay and oplog-compaction sweeps' last completed pass.

- Operators can now take down a single Atproto Space instead of the whole account that owns it — including a space governed by another server, where this host stores members' repos and has no other lever. A taken-down space answers `SpaceNotFound` to every read, write, credential renewal and listing while nothing stored is destroyed, so clearing the takedown restores it exactly. `GET /v1/admin/spaces` lists what the server stores (owned and foreign, with repo and record counts) and `POST /v1/admin/spaces/takedown` applies or clears the refusal; both are recorded in the admin audit log.


### Changed

- Documentation: corrected two Atproto Spaces source-doc annotations — the `auth/space.rs` seam doc now notes that `createSpace` authenticates as the caller (there is no prior owner to check), rather than implying every simplespace management method runs the owner check, and the `db/spaces.rs` header now attributes the `app_access`/`app_allowed` allowList columns to their V069 migration. No behavior change.

- Update marketing site

- Custos's outbound Atproto Spaces write notifications are now verified against a mock foreign space host: the exact `notifyWrite` / `notifySpaceDeleted` request bodies, the method-scoped service auth each carries, the retry-and-give-up ladder, and the `#atproto_space_host` → `#atproto_pds` endpoint fallback that every alpha-era host is actually reached through.

- The vendored Atproto Spaces lexicons are now pinned to an exact upstream commit rather than the moving `permissioned-data` branch, so their byte-identity with `bluesky-social/atproto` is reproducibly auditable.


### Fixed

- Confidential OAuth clients whose `private_key_jwt` assertion carries `iat` but no `exp` — the shape the reference provider and real-world clients such as attie.ai mint — can now complete the token exchange; an `exp`-less assertion is bounded by a 60-second `iat` max age instead of being rejected.


## [0.14.0] - 2026-08-27

### Added

- Repo writes now verify the new commit's record count against a maintained per-repo count and abort loudly if a commit drops records it did not explicitly delete, so MST corruption like the 2026-08-27 data-loss incident can no longer persist silently.

- Atproto Spaces space-host role: `com.atproto.space.listRepos` (the writer set, with each repo's last-reported rev and commit hash), `registerNotify`/`unregisterNotify` for syncer subscriptions with a seven-day renewable expiry, and inbound `notifyWrite` from foreign repo hosts. Every space write now fans out best-effort notifications — a repo host auto-registers the authority's `#atproto_space_host` and reports to it, a space host forwards to its registered syncers — and `simplespace.deleteSpace` sends `notifySpaceDeleted` before dropping the subscriptions.

- Atproto Spaces: a space can now gate credentials on *which app* is asking, and on a per-user decision made elsewhere. `getSpaceCredential` verifies an optional client attestation — resolving the app's `client_id` to its published client-metadata document and JWKS over the SSRF-hardened client, and spending its `jti` single-use — so `appAccess: #allowList` is an enforced perimeter rather than an unverified claim; a space with `policy: managing-app` asks the app it names, over service auth, whether to authorize each user, and denies whenever that app answers no or cannot be reached. Both config members are consequently accepted by `createSpace`/`updateSpace` instead of refused, and `getSpace` reports the allow list back.

- Atproto Spaces now follow their account's lifecycle, and can follow it to a new host. A suspension or takedown closes the whole permissioned-space surface — reads, writes, and delegation tokens alike — while self-service deactivation closes only ordinary writes, keeping the migration window open; a space host stops answering a syncer's credential the moment the space's authority stops being an active account, reporting `SpaceNotFound` rather than the durable `SpaceDeleted` signal. Migration gains its inbound leg: `POST /v1/space/import-repo` ingests the two-root CAR that `com.atproto.space.getRepo` exports, into a deactivated account, making the destination repo exactly the CAR's record set — so it hashes to the digest the source published and every syncer can converge on it. Enumerate what to move with `listSpaces` + `listBlobs`; blobs still travel by `uploadBlob`, and the new host's oplog starts fresh.

- Atproto Spaces tooling and hardening: credential-authed space requests are now rate-limited per credential holder (keyed by the credential's bound DPoP key thumbprint, `rate_limit.space_credential_per_5min`, rejections visible as `rate_limit_rejections_total{limiter="space_credential"}`); the Custos MCP server grows an agent tool surface for spaces (`list_spaces`, `space_get_record`, `space_list_records`, `space_create_record`, plus destructive-gated put/delete) that the hosted sidecar re-exports; the wallet's consent screens describe `space:` grants in plain language instead of showing the raw token; and the interop CLI gains a `spaces-test` round-trip scenario. Operators can now also set the agent scope profile via `EZPDS_AGENT_AUTH_GRANTED_SCOPES` (comma-separated), as the docs already promised.

- A token whose signature fails against a cached DID document now force-refreshes that document at most once per minute per DID, and the new `did_signature_refresh_total` metric reports how often that healing refresh runs, fails, or is held back — so a caller replaying a badly-signed token can no longer drive one plc.directory or did:web fetch per request.


## [0.13.0] - 2026-08-27

### Added

- Notification registrations can opt into a metadata-minimizing ping mode (`ping: true` on the register routes): the relay then sends a content-free `content-available` background push — no sealed payload reaches the relay or Apple at all — and the app fetches events from its Custos on wake. Sealed alert pushes remain the default.

- Groundwork for Spaces (permissioned data): the LtHash multiset hash and deniable commit sign/verify primitives land in the crypto crate, pinned to the reference golden vectors from the atproto `permissioned-data` branch. No server or app surface changes yet.

- OAuth grants can now carry Atproto Spaces permissions: the `space:<spaceType>` scope grammar (with `authority`, `skey`, `collection`, `action`, and `manage` parameters) parses, normalizes, and enforces alongside the existing resource types, and permission sets may bundle `"resource": "space"` entries. Read access is all-or-nothing per space, record writes stay collection-constrained, and space management is a separate, default-empty capability. The space XRPC routes that consume these grants ship separately.

- Groundwork for Spaces (permissioned data): the DB-backed permissioned repo store lands — schema for spaces, per-space repos (incremental LtHash state), records, the sync oplog, members, notify registrations, and jti replay protection, plus the single write choke point and blob GC that unions public and space references. No routes yet; the record CRUD and management surfaces follow.

- Spaces (permissioned data): the PDS record surface goes live — `com.atproto.space.createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `listSpaces`, `getRecord`, `listRecords`, and `getLatestCommit`, all OAuth-authed against the caller's own permissioned repos and gated by their `space:` grant. Writing into a space this server has not seen records it, so joining another authority's space needs no prior setup, and `getLatestCommit` mints a fresh deniable commit per request rather than serving a stored one.

- Atproto Spaces (permissioned data) auth: `com.atproto.space.getDelegationToken` mints single-use delegation tokens, and `com.atproto.space.getSpaceCredential` — Custos as a space authority — exchanges one plus a DPoP proof for a DPoP-bound space credential (`cnf.jkt`), honoring the `public` and `member-list` policies. Repo-host verification of those credentials, with full RFC 9449 per-request proof validation and per-host replay protection, lives behind the one new read-side auth seam the upcoming space read/sync routes use.

- Atproto Spaces: the PDS-required `com.atproto.simplespace` management surface — `createSpace`, `updateSpace`, `deleteSpace`, `getSpace`, `addMember`, `removeMember`, `listMembers`. Spaces are anchored on the caller's own DID and managed under `space:…?manage=` grants; `getSpace` also accepts a DPoP-bound space credential, so a member hosted anywhere can read the space's configuration. `public` and `member-list` policies with `open` app access are implemented; `managing-app` and `allowList` are refused at create/update time (`UnsupportedPolicy` / `UnsupportedAppAccess`) rather than stored unenforced. Deleting a space tombstones it (so credential renewals answer `SpaceDeleted`), removes the authority's own repo, and leaves members' records in place, unreadable.

- The OAuth consent screen now describes Atproto Spaces requests in plain language instead of raw scope strings: each `space:` grant is shown under the space type's declared name (localized to the browser's language when the declaration offers a translation), a named authority appears as its bidirectionally-verified handle, and the collections the app could write are spelled out. A request for every kind of space under any authority is called out with a prominent warning. The raw scope token stays visible on each row, and a declaration that can't be reached falls back to it rather than blocking the sign-in.

- Atproto Spaces sync surface: `com.atproto.space.listRepoOps` (incremental oplog sync with head commits and an hourly compaction sweep bounding retention to seven days), `com.atproto.space.getRepo` (streaming two-root CAR export — signed commit plus canonical DRISL index), and space-authed `com.atproto.space.getBlob`/`listBlobs` for permissioned blob fetch and enumeration. All behind the space read seam (covering OAuth grant or DPoP-bound space credential).

- DID documents now carry every verification method and service a PLC operation publishes — including the Atproto Spaces `#atproto_space` key and `#atproto_space_host` service — and `getRecommendedDidCredentials` recommends both; resolution falls back to `#atproto` / `#atproto_pds` when they are absent.


### Fixed

- Proxied Bluesky requests no longer depend on a live DID-document fetch. An `atproto-proxy` header naming the operator's own configured AppView or chat service (which the official Bluesky app sends on every request) is now recognised as the default rather than a caller-chosen retarget, so a slow or failing `did:web:api.bsky.app` no longer breaks feed loads — and those requests regain read-after-write merging, so your own new posts appear in your timeline immediately. Every other DID document resolved from plc.directory or a `did:web` endpoint is now cached for an hour and refreshed in the background for up to a day, matching the reference PDS.

- Repo writes can no longer silently destroy records: a local patch to the atrium-repo
  MST fixes an upstream bug (atrium-rs/atrium#343) where inserting a record whose key
  hashes to a higher tree layer could discard every record sorting on one side of the
  insertion point — whole collections vanished with no error and no firehose delete.


## [0.12.0] - 2026-08-19

### Added

- Settings → Notifications now shows, per identity, whether this launch's push registration succeeded — and when it didn't, why and what fixes it. An identity that can't receive notifications (for example, one whose session is locked) no longer reads as perfectly healthy.

- App passwords can now be minted with an opt-in personal-details grant (an "Allow personal details" checkbox in Obsign, beside the existing direct-messages one), letting that password's sessions read and set the personal-details preferences — today the birth date the official Bluesky app's age verification requires, which a passwordless sovereign account previously could not get past at all. A deliberate, per-credential divergence from the reference PDS (ADR-0033); unchecked, behavior is unchanged, and the server advertises support as the `appPasswordPersonalDetails` capability.

- The wallet's Change handle screen now supports domains you own, including the bare domain itself (an apex handle like `obsign.org`): choose "Use a domain you own", and Obsign shows the exact `_atproto` DNS TXT record to publish, verifies it from both your DNS and your hosting server's vantage — distinguishing a missing record, one still propagating, and one pointing at a different identity — and only enables the change once the record verifies.


### Changed

- The handle step of onboarding now says which failure it hit when it can't load the server's handle domains, instead of one generic message: an unreachable server points at your connection, a server that answers with a failure asks you to try again shortly, and an address that answers but not like a server tells you to check the address you entered.


### Fixed

- OAuth token-endpoint DPoP nonces now follow the reference provider's rotating-window scheme (valid one to three minutes, reusable, consistent across restarts) instead of being single-use — fixing clients that cache a nonce or make concurrent token calls, which logged in fine and then failed every subsequent call.

- Push notifications now decrypt and render on device: the release lane previously shipped the wallet's Notification Service Extension without its shared-keychain entitlement, so every push showed "Couldn't verify a notification from your Custos instance" while Settings reported no problems. The signed IPA gate now also fails loudly if an extension's keychain access groups ever go missing again.

- Unlocking an identity now re-registers it for push notifications on the spot, so an identity that was locked when Obsign opened starts receiving sign-in requests and other notifications right after the unlock instead of waiting for a future launch. The server also logs when a sign-in push could not be sent because the account has no registered device.

- Consent QR codes scanned with the iPhone Camera app now open the consent approval screen in Obsign (when the app is running or backgrounded), instead of landing on the overview. When several identities are managed, Obsign works out which one the sign-in request is for before navigating.

- The "Open in …" chip shown when scanning a sign-in QR with the iPhone Camera app now reads "Open in obsign" instead of the technical "org.obsign.identitywallet" scheme name. QR codes from servers that haven't updated yet still open the app.

- Creating an identity on a server whose handle domains are configured with a leading dot (`.example.com`, the form the wider network uses) no longer builds a broken handle. The handle step composed `alice..example.com`, which the server rejects as malformed, so account creation failed at the last step with nothing on screen explaining why. Handle composition now accepts either form, matching what changing a handle already did.


## [0.11.2] - 2026-08-17

### Changed

- The operator configuration reference now describes every top-level configuration section — nine (including `crawlers`, `appview`, `chat`, `iroh`, and `telemetry`) previously rendered no description.


### Fixed

- A notification that timed out before Obsign could verify it now leaves a breadcrumb behind, just like every other unverified notification. Previously a timeout rendered the same "Couldn't verify" banner but left Settings → Notifications reporting no recent failures, so the one surface built to explain the banner silently contradicted it.


### Security

- The OAuth authorization endpoint now enforces the PAR-only flow its metadata has always advertised: a direct `/oauth/authorize` request with inline parameters, or one carrying an unsupported JAR `request` object, is refused at flow start instead of being processed (or silently stripped).


## [0.11.1] - 2026-08-12

### Fixed

- OAuth server metadata now states the `request_uri` capability fields explicitly (`request_uri_parameter_supported`, `require_request_uri_registration`, `request_parameter_supported`) instead of leaning on their OpenID Connect Discovery absent-field defaults — a real client read their absence as "no PAR support", silently downgraded to a legacy non-PAR flow, and its login died after consent without ever reaching the token endpoint.


## [0.11.0] - 2026-08-08

### Added

- OAuth loopback client identifiers (`http://localhost?redirect_uri=…&scope=…`) are now supported, so a developer building an app against a locally running Custos can use the standard atproto development client instead of publishing a metadata document.

- Operators can now tune the OAuth access-token lifetime with `EZPDS_OAUTH_ACCESS_TOKEN_TTL_SECS` (default 900 seconds, accepted range 1–1800). The conformance suite uses it to test what a client sees when its token expires.

- The OAuth conformance suite now covers confidential clients (`private_key_jwt`), and a client publishing its keys at a loopback `jwks_uri` is no longer refused for using plain http — the same development exception `client_id` resolution already made.

- The OAuth conformance suite now covers refresh-token rotation, including the concurrent-refresh case that used to log clients out silently.


### Changed

- User documentation is rewritten in plainer language for a security-minded audience, and the signing-in guide now documents push-to-approve with number matching.

- Obsign developer documentation moved from the app overview into module docs beside the code it describes; no runtime behavior changed.

- Server developer documentation moved from the crate overview into module docs beside the code it describes; no runtime behavior changed.

- Marketing site copy now speaks to the launch audience: security outcomes lead (ownership reads as the consequence, not the pitch), protocol vocabulary like rotation-key indexes and PLC moved off the Obsign page to the Custos and docs tiers, the recovery-share wording matches where shares actually live, and the privacy page accurately scopes what analytics records.

- The pages Custos renders in the browser now follow the writing-style guide's user register: OAuth error pages say what happened, what it means, and what to do next (with mechanical detail moved to the server log), the consent page's wallet path drops protocol vocabulary, and the landing page describes key custody in plain words.

- The wallet's everyday and onboarding copy now follows the writing-style guide's user register: protocol vocabulary ("rotation key", "PLC directory", "PDS", "tombstone", "did:web") is replaced with the established plain words ("deciding key", "the public record", "server", "retire", "domain identity") on every surface outside the advanced tier, and error messages state what happened and what to do next.

- The Brass Console drops the descriptive lede paragraph that opened every screen — the elements speak for themselves, with the load-bearing facts kept as one-liners (the accounts sort order and meter legend, the status screen's facts-not-verdict contract) — and the remaining prose loses its machine-flavored tells while keeping the operator register's protocol vocabulary untouched.

- Obsign's error surface now has a declared seam (ADR-0031): screens own every error sentence keyed on the typed `code`, diagnostic detail stays in the log (or a visibly subordinate detail slot), and server attribution is only ever true — a local Keychain failure can no longer render as "Your PDS reported: …". The recovery-override, identity-removal, and claim screens drop their raw error-chain interpolations for calm, styled sentences, and `get_available_user_domains` rejects with a typed error instead of a bare string. In the operator console, a relay's own rejection reason is now attributed to the relay and length-bounded instead of being spoken in the console's voice at whatever length the relay sent — so a server the operator doesn't run can't put words in their tools' mouth.

- A confidential OAuth client's published key set (`jwks_uri`) is now cached instead of fetched on every token request. Previously each token refresh added a round trip to the client's key host, and an outage there made the client unable to authenticate at all; the key is now reused for up to an hour (configurable via `[oauth] client_jwks_cache_ttl_secs`).


### Fixed

- Pushed authorization requests now record the client's DPoP key, and the token endpoint refuses a code bound to a different one. The binding currently reaches codes issued through the wallet consent path; the password consent form cannot carry it (its pushed request is already consumed by the time the form is submitted). The PAR endpoint also no longer requires a `state` parameter, and an authorization response no longer echoes an empty `state` back to a client that sent none.

- A device holding more than one identity on the same Custos instance now receives notifications for every one of them. Previously each identity's registration replaced the last one's route to the device, so only the most recently opened identity got pushes and the rest went silent with nothing to explain it.

- OAuth sessions now match the reference PDS's lifetimes and refresh semantics: access tokens live 15 minutes (was 5), refresh sessions 14 days (was 24 hours), and a concurrent duplicate refresh (multi-tab, background+foreground) no longer silently logs the client out — while replaying an old refresh token later revokes the whole session as a theft signal.

- The token endpoint now actually verifies `private_key_jwt` client authentication (RFC 7523, ES256, 30-second clock tolerance) instead of silently ignoring a confidential client's `client_assertion` and treating it as public. The client's registered `token_endpoint_auth_method` decides what is required, with keys taken from its metadata `jwks` or a policy-checked `jwks_uri` fetch.

- Granular `rpc:` OAuth scopes now match their `aud` on the service DID regardless of `#serviceId` fragments, so a grant written in either convention (bare DID or fragment-qualified) authorizes both PDS proxying and `getServiceAuth` consistently.

- XRPC endpoints now answer errors in the flat AT Protocol shape (`{"error": "ExpiredToken", "message": ...}`) with the canonical atproto error names, so third-party app sessions refresh instead of dying when an access token expires. The provisioning API's nested envelope is unchanged.


## [0.10.2] - 2026-07-29

### Fixed

- A relay operator can now see why Apple refused a notification. The relay logged connection failures but swallowed refusals — a push Apple answered with an error produced no log at all, leaving a misconfigured key, a sandbox/production mismatch, and a dead device token indistinguishable. Every refusal now logs the HTTP status and Apple's own reason string. What the instance is told is unchanged: it still receives only the coarse outcome, so a relay misconfiguration still cannot fan out registration-destroying instructions.


## [0.10.1] - 2026-07-29

### Fixed

- The notification relay can now actually reach Apple. Its HTTP client was built without HTTP/2 support — a default feature lost when the workspace opted out of defaults — and Apple's push service speaks nothing else, so every real delivery failed in transport with a connection error while the relay's own tests (whose stand-in APNs speaks HTTP/1.1) stayed green. Pushes sealed for your device now arrive.


## [0.10.0] - 2026-07-29

### Added

- Obsign can now receive the encrypted notifications your Custos instance sends. On first launch it asks permission, generates a notification key that never leaves the device, and tells each of your identities' servers where to reach it — so a notification can be sealed to your phone specifically, and read nowhere else. What that protects is the notification's *content*: neither the relay in the middle nor Apple can see what one says. It does not hide that a notification happened — your own server is told which device to reach, and Apple necessarily handles delivery — so what is kept from everyone in between is the message, not the fact of it. The key is used for nothing else: it never signs anything, and losing it costs you banners rather than an identity. Obsign also re-checks which signing keys your instance publishes every time it contacts it. That is what keeps the window short if one of those keys is ever compromised — a key your operator revokes stops being trusted by your phone the next time the two talk, without you doing anything. Registration is quiet by design: on a simulator, or for an identity hosted somewhere that runs no relay, Obsign simply carries on with notifications switched off rather than reporting an error you cannot act on. Both Obsign and Admin Companion now require iOS 17, which is where Apple's encrypted-notification support begins.

- Obsign now reads the encrypted notifications your Custos instance sends. Until now your phone could receive one but not open it, so every notification arrived as a placeholder; a small extension bundled with the app now unseals each one the moment it arrives — on the lock screen, without waking the app, and without the relay in the middle or Apple ever seeing the text. What you read is what your server wrote.
  
  When a notification *cannot* be opened, Obsign says so plainly rather than showing you something that looks genuine. iOS does not let an app silently discard a notification, so anything that fails to unseal — a relay sending noise, a message signed with a key your phone has not seen, or one arriving before you have unlocked your phone since restarting it — appears as an explicit "Couldn't verify a notification from your Custos instance". It is never dressed up as real content, which is what stops whoever carries your notifications from being able to put words in your server's mouth.
  
  Because that notice on its own cannot tell you *which* of those happened, Settings gains a Notifications section that can. It counts the recent failures and names the likely cause in plain language — and, where there is something to do, says what: a key mismatch is usually fixed by opening one of your identities, since Obsign refreshes the keys on every contact with your server, while a run of unrecognisable notifications points at the relay rather than at anything of yours being at risk. Once you have dealt with it, you can clear the record so the next real report is not lost in an old one.

- The notification relay can now be deployed: it ships its own container image and Railway config, so you can run one yourself instead of pointing your instance at ours. A relay serves no web address at all — it is reached over an encrypted peer connection by its node id — so there is nothing to expose to the internet and nothing to put behind a domain. Its database is disposable, since everything in it is rebuilt when instances re-enroll, but its node key is the relay's address and can be supplied as a deployment secret so it survives the machine being rebuilt. A new operator runbook walks the whole path: getting an Apple push key, starting the relay, handing out single-use enrollment codes to the instances you serve (or turning that ceremony off when you are the only tenant), checking a notification arrives end to end, and reading the outcome the relay reports when one does not. It is also honest about the boundary: your own relay can only push to apps belonging to your own Apple developer team, so the official Obsign apps still need the official relay — which is precisely why that relay is built to see nothing.

- Signing in to an app can now come to you. When a sign-in page knows which account it is for, your Custos instance sends a sealed push to Obsign; tapping it opens the approval screen directly on that request — nothing to look up, no sign-in code to copy over, no QR to scan. The push travels the same encrypted path as every Obsign notification: what the relay and Apple carry is a sealed payload and an opaque delivery handle, so who the login is for, which app asked, and where it came from stay hidden from everyone between your server and your phone. (Like any courier, the relay can see that *something* was delivered — it just can't read what.) And Obsign only acts on a tapped notification it could cryptographically verify came from your instance.
  
  Because a prompt that finds *you* is exactly where tap-fatigue attacks live, approval on this channel demands one extra proof: the sign-in page shows a two-digit number, and Obsign requires you to type it before Face ID. If someone else started that login, you are not looking at their screen, so there is nothing you can type — a blind "Approve" is impossible, and your server enforces the number, not just the app. A wrong number never kills the request; denying it (which needs no number) does, and is exactly the right answer to a prompt you did not start.
  
  If the push never arrives — notifications off, relay down, a new phone — nothing is lost: the same sign-in page still shows the typed code and the QR, and either one opens the same request in Obsign, where the number is still asked for and still on the page in front of you.

- OAuth endpoints now emit structured operator logs for every token/revocation rejection (error code + description), every authorization error redirect, and each completed authorization-code exchange (client + account) — no token material — so failed third-party logins can be diagnosed from server logs instead of request counters.


## [0.9.2] - 2026-07-27

### Fixed

- OAuth `include:` permission-set expansion now skips individual entries that cannot be converted to a valid scope (matching the reference implementation) instead of rejecting the whole set — fixes logins from apps requesting Bluesky's `app.bsky.authCreatePosts` set, whose `inheritAud` video-upload entry is unrenderable without an `?aud=` parameter.


## [0.9.1] - 2026-07-27

### Fixed

- OAuth logins from browser-based atproto apps (which request `response_mode=fragment`, the official client library's default) now complete: the authorization response is delivered in the URL fragment when requested instead of always in the query string, and the server metadata advertises `response_modes_supported`.

- Third-party atproto apps that send a direct (non-PAR) authorization request no longer fail with "client_id is not registered": the authorize endpoint now resolves an unknown URL-shaped client's metadata document live, exactly as the PAR endpoint already did, and enforces the same private-use-scheme redirect rule.


## [0.9.0] - 2026-07-27

### Added

- Groundwork for encrypted push notifications: Custos gained the sealing layer that will let a self-hosted instance send notifications through a relay it does not have to trust. Payloads are sealed to a per-device key with HPKE (RFC 9180, DHKEM-P256 + AES-256-GCM, authenticated mode), so a relay operator and Apple both see only opaque bytes and neither can forge a notification your device will accept. Payloads are also padded up to one of three fixed sizes: that does not hide length outright, but it reduces what length can reveal from a per-notification fingerprint to which of three buckets a notification fell into. Nothing is enabled by this change on its own; the relay, the registration flow, and the on-device decryption arrive in the phases that follow.

- New `notify-relay` service: a blind courier that self-hosted Custos instances enroll with over iroh (`ezpds/notify/0`) to obtain opaque push handles for their devices. Enrollment is closed by default and gated on operator-minted single-use codes (`notify-relay mint-code --ttl 60m`); `open_enrollment = true` admits any instance on a self-run relay. Handles are resolvable only by the instance that registered them, and per-instance rate limits apply. Sending pushes to Apple arrives in a following change.

- The notification relay can now actually deliver. It signs in to Apple with the operator's own push key, wraps each instance's sealed payload in the envelope Apple requires, and forwards it — carrying a fixed, content-free "Encrypted notification" placeholder that the real notification replaces once your device decrypts it. Everything that identifies the notification stays sealed: the relay copies the ciphertext through without reading it, and the only secret it holds is its own Apple credential. Two things travel back. When Apple reports that a device token is dead, the instance is told so it can drop that registration instead of pushing into the void forever. And every notification is checked against Apple's 4 KB limit before it is sent, so a payload that would have been rejected on the relay's credentials is reported to the sender as too large instead. Pushes are budgeted twice over — per instance, and per device at 60 an hour — so a bug in one instance cannot flood a phone, and one device's traffic cannot starve another's. A relay with no Apple key configured still enrolls instances and hands out push handles; it just says plainly that it cannot deliver yet. Nothing sends notifications through this yet — the Custos side that triggers them arrives next.

- Custos can now send push notifications, and the first one is live: when an agent asks to act on your behalf, your phone tells you instead of the request waiting silently until you next open the app. Point your instance at a relay with `[notifications] relay` and the feature switches on; leave it unset and none of it exists — no keys are generated, no registration endpoints answer, nothing is sent. Notifications are sealed on your instance to one specific device and opened only on that device, so neither the relay nor Apple ever sees what a notification says. They also prove where they came from: your instance signs each one with a key your devices have pinned, so a relay that turned hostile could drop or repeat notifications but could never write one that looks genuine. Length is padded to fixed sizes, because how long a notification is would otherwise reveal what kind it is; anything too large to pad is dropped rather than sent in a way that leaks. Devices register over the app's normal authenticated channel and can unregister at any time, and when Apple reports a device is gone, its registration is removed at once. Deleting an account or revoking an operator device also tells the relay to forget the devices involved. Operators rotate the signing keys with `pds notification-keys` — publish a new key alongside the old, retire the old once devices have re-pinned, or revoke it outright if it is compromised.

- A recovery key for identities hosted anywhere. Until now, the wallet's Shamir recovery seed came bundled with Custos escrow, so an identity you imported from bsky.social or any other spec-compliant PDS got a Secure-Enclave root key, monitoring, and backups — but no way back in if you lost the device. The new "Add a recovery key" flow on the identity screen is the same ceremony minus the escrow: the wallet generates the seed, splits it 2-of-3, and publishes a device-key-signed operation that inserts the derived recovery key straight after your device key. Nothing is removed, and no share — nor any part of the recovery key — is ever sent to your PDS; the only thing the wallet asks it is the public question of whether it offers recovery escrow at all. Share 1 goes to your Keychain to sync across your Apple devices; Shares 2 and 3 are both yours to save, and any two of the three restore the identity through the existing recovery ceremony. The flow is offered only where it is the right answer: on a server that advertises recovery escrow, the escrow-backed upgrade is offered instead, and on a server that could not be reached nothing is offered at all rather than guessing. If you later move to a host that does hold shares, the wallet offers escrow once — as an option, not a reminder.

- App passwords, handle changes, identity removal, and media restore now work on any server. Four features that are pure standard AT Protocol have been dark for identities hosted anywhere but Custos, for a single reason: each needs a full sign-in, and the only sign-in the wallet knew how to perform was the passwordless one that a Custos server offers. On bsky.social or the reference PDS there was no such option, so the buttons were there and the session behind them was not. The wallet now asks the identity's server which sign-in it supports and offers the right one: a Face ID unlock where the server accepts a device-key signature, and a prompt for your account password where it does not — with emailed two-factor codes handled, and the password sent once, to your own server, and never stored. From then on the session behaves identically either way: it refreshes on its own, and it is discarded if your identity moves to a different host. A server the wallet could not reach is never assumed to lack passwordless sign-in — it keeps offering the unlock it already used, because a network hiccup is not a fact about your server.

- Rescue and migration can now finish on any spec-compliant PDS, not just a Custos one. The final cutover step used to mint a passwordless sovereign session unconditionally, which only Custos serves — so a move to the reference PDS or bsky.social would fail at the last step, after the identity operation had already landed. Obsign now asks the destination what it supports and, where passwordless sessions are not on offer, durably keeps the session that destination already issued, in the same strict order (activate, store the credential, then stand the old server down). The destination picker also states plainly how you will sign in after the move.

- The wallet's background identity monitor now has a face you can look at. The home screen's status strip says when the public record was last checked and opens a new **Protection** surface: every identity's status in one list — reordered so anything under attack leads — plus the monitor's own history, showing when each check ran, what it covered, and when each identity was last verified. The check runs every 15 minutes as before; you can now see that it is happening, and run one yourself.

- The operator console now renders the blob-integrity readouts the server already reports: the Status screen's Storage panel names unowned blobs — stored bytes no account claims, an alarm that fires while blob collection is still running on schedule — account detail shows an account's uploaded blob figures beside its owned ones, and did:web accounts state in the accounts list whether this server serves their DID document. A server too old to report any of these reads as "not reported" rather than as zero.

- An account with no password can now be permanently removed: `com.atproto.server.deleteAccount` accepts a device-key-signed proof from one of the identity's current rotation keys in place of the password, alongside the emailed confirmation code as before. Custos advertises this as the `walletAccountDelete` capability, and Obsign drops the password field from the removal screen on a server that offers it.

- Operators can now let accounts be created without a password at all. With `[accounts] password_optional = true` (`EZPDS_ACCOUNTS_PASSWORD_OPTIONAL`) the server advertises a new `optionalPassword` capability, and a client may omit the password field when creating an account; the account then authenticates through its device key — wallet-confirmed OAuth consent and sovereign sessions — plus app passwords for standard AT Protocol clients. Obsign reads that capability and skips its password screen entirely against such a host, while continuing to ask for one everywhere else, so an older deployment is unaffected. Off by default: a passwordless account depends on device-key custody an operator cannot verify for the account holder. An empty password is rejected either way — an empty string is what an uninitialised form field sends, so omitting the field is the only way to ask for a passwordless account.

- Operators can now see how much push-notification work is waiting. The notification queue holds jobs in memory and never blocks a request, which is the right trade when a relay is slow — but it also meant that a relay being down for a maintenance window, or pointed at the wrong node id, showed up only as a rising count of warnings in the log. There is now a `notify_queue_depth` metric alongside the others at `/metrics`, and a `notifyQueueDepth` figure in the operator health readout that the console can show. It counts the jobs still outstanding, including the one currently being attempted, so a single push stuck against an unreachable relay is visible rather than reading as an empty queue. Expect zero; a number that climbs and stays there is a relay outage becoming a memory cost. Instances with no relay configured report nothing at all rather than a misleading zero.


### Changed

- Each identity in the wallet now opens as an instrument panel rather than a list of ten equal buttons: a status panel states whether the identity is secure, needs attention, or is under attack — with a security checkup you can expand — and the actions sit beneath it, sorted by how often you need them. Signing in to apps, Bluesky, and your agents are one tap away; "Move or rebuild" is its own visible door; and handle, backups, and the DID document live behind "Manage identity", with the protocol-level tools one further step down behind a screen that explains what they do. Every operation keeps the confirmations it already had.

- Obsign now opens straight onto the alarm when one of your identities is being changed without your authorization. Previously the alarm waited behind the home screen's protection strip, so the most time-critical thing the app can tell you was also the one thing it made you navigate to. Now, on launch or when you return to the app, a single affected identity opens on its own alarm surface and several open the Protection list, most urgent first. It is always an offer, never a lock-in: "Not now" returns you to a home screen that still shows the alarm as a banner and flags the affected identities, and once you have dismissed an alarm the app will not keep pulling you back to it. Interrupted key handling still comes first — a half-finished recovery, removal, or move resumes ahead of re-showing an alarm you have already been told about.

- Adding an identity now starts with one plain question — "Add an identity — what's your situation?" — instead of a row of doors named after the machinery behind them ("create", "import", "recover"). Pick the sentence that describes you: starting fresh, you already have an account somewhere, you lost access to your wallet, or your server is gone. Obsign works out which ceremony that means and takes you into it; the ceremonies themselves are unchanged. "My server is gone" is answered honestly rather than made into a fifth journey of its own: if the identity is already in this wallet, Obsign points you at that identity's "Move or rebuild" door, and if the wallet was lost too, it says so and takes you through recovering the wallet first — because rebuilding an account elsewhere is signed by the identity's own key, which the wallet has to hold before it can rebuild anything.

- The canonical base64url check that keeps a signed device-key proof from being re-spelled into a fresh nonce now lives in one shared module instead of being copied into each of the three routes that verify such proofs (passwordless session issuance, wallet-confirmed OAuth consent, and passwordless account deletion), so the three can no longer drift apart. Behaviour is unchanged.

- The iOS pull-request gate now runs clippy for both mobile apps, so lint findings in crates the Linux gate cannot compile no longer accumulate unchecked.


### Fixed

- A newly created identity could finish onboarding, show "You're all set", and then not appear on the home screen. The last step of the create flow records the identity in the wallet's own list — the home screen reads from that list alone — and if that one write failed, the flow reported success anyway, nothing retried it, and the state survived force-quitting the app. The identity, its master key, and its recovery shares were never at risk, but the only way to make it visible again was to run the recovery ceremony on an identity that had not actually been lost. That step now retries, and if it still fails the app says so plainly and offers to try again instead of claiming success. Obsign also re-checks this on every launch and re-registers an identity whose create flow left it out — so an install already stuck in this state repairs itself on the next open. Identities you removed from a device on purpose are remembered as removed and are never brought back.

- The wallet no longer claims custody of a rotation key it cannot sign with. Your identity's key lives in this device's Secure Enclave, and an encrypted device backup can restore the two small records that *name* that key but never the key itself — so a restored or replaced iPhone used to show a confident "Root key" badge while every action that needed a signature (changing your handle, migrating, repairing the hosting endpoint, removing the identity) failed with an error naming the symptom instead of the cause. The wallet now asks the enclave whether the key is really there before reporting it, and when it is not, says so plainly: the identity card reads "Can't sign", and both the card and the identity screen explain that the identity itself is intact — only this device's control of it is gone — and offer the recovery ceremony, which issues a fresh key on this device and installs it as the identity's top rotation key. The check is a lookup rather than a signature, so it adds no Face ID prompt. It deliberately does not quietly issue a replacement key instead: a new key is not in the identity's rotation list, so doing that would have replaced one false claim with another.

- The identity screen's "Sign in to an app" entry (wallet-confirmed OAuth consent — QR scan or typed code) now appears for did:web identities too. The server-side authority lookup became method-agnostic when did:web sovereign sessions shipped, but the wallet still offered the entry only for did:plc, leaving a passwordless did:web account with no way to reach the consent approval it was newly entitled to.

- Creating an identity in Obsign no longer ends by opening a sign-in page over the app. Account creation used to finish by handing off to the server's web sign-in, which a passwordless account could not get through: the page offers a password the account does not have, and its alternative is to "open Obsign and approve" — but Obsign was already the app hosting that page, and closing it cancelled the sign-in. Signing up therefore could not complete at all on a passwordless account. The hand-off is gone: creation now goes straight from "You're all set" to your identities. Nothing is lost by removing it — your account is already active when its identity is minted, and Obsign signs in to it with the device key it just created, asking for Face ID the first time something actually needs the account. Accounts created with a password are unaffected, and signing in to other apps — on this device or another — is unchanged.

- Approving a third-party app's sign-in from Obsign failed with "your server rejected the approval — the signature could not be verified against your identity's current keys" whenever the app passed along the handle you had typed. Custos compared that hint to your DID as plain text, so `alice.example.com` never matched `did:plc:…`, and the approval was refused two steps before your signature was ever examined — the message blamed your keys for something they had not done. Nothing was ever wrong with Obsign's signature or with any account's keys. Custos now binds a handle-shaped hint to the account it actually names, requiring both that the account claims the handle in its DID document and that the handle resolves back to that DID, so neither half alone lets one account approve a request named for another. Handles are matched without regard to case, as the AT Protocol intends. Typing your DID instead of your handle was the workaround and still works — and remains the way through if handle resolution for your domain is down.

- The wallet no longer asks the public did:plc directory about identities that were never in it. An identity held at your own domain (a did:web) is anchored by control of that domain, not by a record in the directory — but the background watch was checking every identity the same way, so for a did:web it made a request that could only fail, every fifteen minutes and again each time you opened the app or the identity. The failure was then reported as "we could not reach the public record", which was not true: there was no record to reach. The watch now covers only the identities that have one, which removes the repeated request on mobile data and leaves the did:web identity screen saying what is actually the case — that it is held at your domain and nothing is out of place.

- Text on buttons throughout the wallet — identity cards, navigation rows, status strips — was rendering in Arial instead of the app's own typeface, because browsers force their default font onto controls unless told otherwise. Every button now uses the same type as the rest of the app.


### Security

- Obsign's Keychain items now live in a stable access group that does not track the iOS bundle
  identifier, with the previous group still declared so anything written before this release stays
  readable. Until now the bundle identifier silently doubled as both the Keychain access group and
  the iCloud container id, so renaming it would have made every device key, recovery share, session,
  and backup unreachable with no error shown. The iCloud container id is now frozen permanently, and
  a CI gate refuses a bundle-identifier change that arrives without the migration (ADR-0030).

- A deletion proof is single-use (its nonce is spent before the confirmation code is checked, so a captured envelope cannot be replayed against a token obtained later), is bound to the account it names, and is verified against the identity's authoritative current rotation set read live from plc.directory rather than any cached document. Unknown accounts, wrong passwords, and bad proofs remain one indistinguishable response, and no credential failure consumes the emailed code.


## [0.8.5] - 2026-07-25

### Added

- The operator console's Status screen now surfaces sweep failures alongside staleness. Each background-sweep row reports the relay's `errors` count as a named `failed <n>` segment, so a sweep that ran but skipped part of its work — for blob GC, an account whose reconcile failed and whose blobs go uncollected until fixed — no longer reads as all-clear just because its timestamp is fresh. The two faults are named independently (`failed <n>` versus `stale`), since one means a single subject is broken and the other means the sweep is not completing at all. A relay predating the field reports no failures rather than failing the readout.

- Blob storage readouts can now tell lost ownership rows from reclaimed blobs. Every operator-reachable blob figure resolved through the per-account ownership table, so an account whose ownership rows vanished reported exactly the same zeroes as one whose blobs were collected — diagnosing the difference meant opening a SQLite shell on the running server. `GET /v1/accounts/:id/storage` now reports `uploadedBlobCount`/`uploadedBlobBytes` beside the ownership figures, counting the physical blob rows that record the account as uploader, and `GET /v1/admin/health` reports `blobUnownedCount`/`blobUnownedBytes` — stored blob rows that no account claims at all. Because garbage collection removes a physical row together with the file it points at, a surviving row means the blob was never reclaimed, which is the distinction the ownership figures alone cannot draw; confirming the files themselves are present and intact remains the blob-integrity scrub's job, reported separately on the health endpoint. Content-addressed blobs are shared between accounts, so a small per-account gap in either direction is normal. `GET /v1/admin/accounts` also now reports `didWebHosting` per account, stating whether Custos serves that account's did:web document — a flag that gates a serve path returning a plain 404 when off, indistinguishable from an unknown host, so an operator previously had no way to tell "not hosted" from "broken" without a database shell.

- Self-hosted `did:web` accounts can now use both passwordless auth paths. `POST /v1/sessions/sovereign` and `POST /oauth/authorize/approve` were hard-gated to `did:plc`, so a `did:web` account carrying no password — which every wallet-migrated account does, since the migration `createAccount` request has no password field and the server stores none by design — had no way to authenticate at all. That was more than a sign-in inconvenience: the wallet's own iCloud media restore runs through the same full-access session seam, so once the refresh chain from migration lapsed, the recovery path lapsed with it. Both routes now resolve the account's signing authority from its DID method's authoritative source: the current PLC rotation set for `did:plc`, and the published `#device` verification method for `did:web`, fetched live over HTTPS rather than from the local document cache. Signature verification was already method-agnostic, so P-256 and secp256k1 device keys work exactly as before, and every failure still collapses to the same opaque rejection.


### Security

- Passwordless authentication for a `did:web` account is restricted to identities Custos does not host the DID document for, enforced on the server. `POST /v1/did-web/document` lets an account rewrite its served document under ordinary session authentication, so for a Custos-hosted `did:web` a stolen session could install an attacker's `#device` key and mint sovereign sessions from it — a privilege escalation requiring no key compromise. Because that route already refuses unless managed hosting is enabled, "hosting is off" is exactly the condition "no session-authenticated rewrite is possible", with no gap in either direction. `did:plc` has no equivalent exposure: rewriting a rotation set requires an existing rotation key, and plc.directory is external to this server. The authority set for a `did:web` is exactly the `{did}#device` key and nothing else — notably not `#atproto`, whose private key Custos holds — and a document publishing more than one `#device` entry is treated as malformed and refused rather than resolved by document order. Obsign accordingly no longer offers the two Custos-hosted `did:web` options; the managed-hosting routes remain available for accounts that already opted in and for other clients.


## [0.8.4] - 2026-07-25

### Added

- A blob GC pass that skipped accounts now reports it: the new `blob_gc_errors_total` metric and an `errors` field on each sweep in `GET /v1/admin/health` distinguish a pass that ran but left work undone from one that is not completing at all (which still shows as a stale timestamp).


### Fixed

- Blob garbage collection no longer deletes the blobs of an account whose repo walk failed. Previously, when reconciling an account errored, that account's blobs were never pinned permanent and the sweep collected them once their upload grace expired — destroying the ownership row, the stored blob, and the file, and then propagating those deletions to the mirror bucket. The sweep now excludes any account that failed to reconcile in the same pass, so blobs whose references could not be computed are never collected; such an account retains its blobs until the underlying fault is fixed.

- Listing the records of a collection no longer fails, or risks returning another collection's records, when the repository holds record keys shorter than the requested collection name. The underlying repository library's prefix scan yields such keys even though they fall outside the requested range; every key is now re-checked against the collection prefix and the scan stops as soon as it passes the end of that range, which also makes listing a small collection cheaper. Because the leak previously surfaced as an error, listing a collection could fail permanently for an affected account and, in turn, block blob reconciliation for it.


## [0.8.3] - 2026-07-25

### Fixed

- Labels are visible again on posts and accounts for Custos-hosted identities. When a client asked the AppView for content, Custos dropped the `atproto-accept-labelers` header naming the labelers that account subscribes to — and the AppView applies only the labelers it is told about, falling back to its own default moderation service alone. Every label from every subscribed labeler was therefore stripped before it reached the client, with no way to tell the difference between "this content carries no labels" and "the labelers were never asked". Custos now forwards that header (along with `accept-language` and `x-bsky-topics`) upstream, and passes the AppView's `atproto-content-labelers`, `atproto-repo-rev`, and `retry-after` back to the client — on the streaming proxy path and on every fallback rung of the read-after-write path alike, matching the reference PDS.

- Backup Share 1 can now sync to your other Apple devices. Every wallet Keychain write omitted the iCloud sync attribute, so the share the "lost phone, iCloud intact" recovery path depends on never left the device that created it — recovery on a new device silently needed the escrowed Share 2 *plus* the Share 3 word phrase. Share 1 is now written to the iCloud-synchronizable Keychain, read from there first, and an existing share is copied across on the next app launch. Obsign can only confirm it wrote the share with the sync attribute set; whether iCloud delivers it is Apple's to do, and with iCloud Keychain switched off it stays put. The repair runs on-device, so it cannot help an identity whose only device is already lost — the backup and recovery screens now say which shares are actually in hand rather than assuming Share 1 will be waiting.

- `just set-version` now regenerates the version-stamped operator reference pages, so a release PR no longer fails `just docs-check` on its first CI run.


## [0.8.2] - 2026-07-24

### Added

- An existing did:web identity can now be brought into the wallet: the "bring an existing did:web" path resolves the domain's live DID document, registers the identity, and opens the migration flow — previously it failed with "DID is not managed by this wallet."

- The wallet's background backup task now refreshes your repo (posts) snapshot as well as your media mirror, so an opted-in identity's posts stay backed up to iCloud without opening the app — no longer only on the next launch. The two backups opt in independently: you can enable one mirror and not the other, and each pass runs off-foreground in the same scheduled wake-up.

- Custos now tells clients what it can do: `com.atproto.server.describeServer` carries a `custos` object with the running version and the capabilities that deployment actually offers (identity creation, recovery escrow, passwordless sessions, agents, wallet-confirmed consent, did:web hosting), derived from the live configuration rather than assumed. Obsign reads and caches it per host, so features are offered based on what a server supports instead of being attempted and failing — and a server that sends nothing, like the reference PDS or bsky.social, is handled as having no Custos capabilities rather than as an error. `GET /xrpc/_health` now identifies itself as `custos vX.Y.Z` instead of a bare version number, matching what third-party AT Protocol diagnostic tooling reads. Operators: see the new [Capabilities](https://docs.obsign.org/operator/capabilities/) page for what each capability means and how it is controlled.

- Custos can now run a public interest-signup waitlist (the `waitlist` capability, `[waitlist] enabled` / `EZPDS_WAITLIST_ENABLED`, off by default): an unauthenticated, CORS-open, rate-limited `POST /waitlist` accepts an email plus an optional atproto handle for a marketing page's signup form — idempotent per email, handle never resolved — and `GET /v1/admin/waitlist` reads the list back for the operator; the Obsign marketing site now carries the TestFlight signup form posting to it.


### Changed

- The wallet's welcome screen now says what its buttons actually do: "Create an identity" and "Import an identity". The second is a correction rather than a rewording — that button has always started the flow that puts your device's key in charge of an identity hosted somewhere else, which is the front door for anyone arriving from bsky.social or a self-hosted PDS; it was labelled "Move an identity to another PDS", which is a different feature and lives on the identity's own screen. Creating an identity also now checks up front whether the server you configured can actually do it: creation requires your device to author the identity's first record and hold its master key from that moment, which a standard ATProtocol server cannot accept, so a server that does not advertise the Custos create ceremony gets an honest explanation on the server screen — before you fill in a claim code, an email and a handle — with import one tap away on the server you already chose. A server the wallet simply could not reach is treated as a question it failed to ask, not as an answer: that shows a retryable error rather than telling you your server cannot create identities.


### Fixed

- Creating or migrating a did:web identity no longer fails verification of the published did.json: the wallet composed the document's `#device` key in a bare encoding the server could never match against the submitted device key (the server compares the multicodec-prefixed did:key form), so every live did:web ceremony was rejected with a generic "document does not match" error. Both the creation ceremony and the migration identity leg now publish the same did:key encoding the server verifies.

- Migrating a did:web identity no longer dead-ends at the start screen with "couldn't verify this identity's keys": the migration path detector asked plc.directory for the identity's PLC audit log, which a did:web identity does not have, so detection always failed. A did:web identity now takes the wallet-driven path directly — its identity leg is the domain's did.json edit, which the wallet composes and verifies.

- Migrating a did:web identity to another PDS no longer fails — the wallet now resolves the source DID from the domain's own did.json instead of plc.directory, and the final cutover persists the destination session directly since a did:web account has no PLC rotation keys.

- Resolving a did:web identity's hosting PDS no longer fails with a generic network error — the wallet now recognizes the absolute-form service ids ("did:web:host#atproto_pds") that did:web documents carry, alongside plc.directory's bare "#atproto_pds" form.

- Bluesky direct messages now work for Custos-hosted accounts — the service-auth tokens the server mints for chat-service proxying carry the jti nonce Bluesky's chat service requires for replay protection.

- The wallet now alternates which iCloud backup mirror runs first in each background wake-up, preventing posts or media from being repeatedly delayed when iOS limits background processing time.

- A did:web identity can now be removed from the wallet. The permanent-removal flow was did:plc-only: the entry point was hidden for a did:web, because behind it the removal always tried to publish a PLC tombstone — an operation a did:web has no directory log for, which would have deleted the account and then stranded the identity in a "retry" state that could never succeed. Removal is now method-aware: a did:web is deleted on its PDS and erased from the device with no PLC step, and the wallet says plainly that the last step — taking the DID's `did.json` off the domain — is yours, since it never had control of that domain.


## [0.8.1] - 2026-07-24

### Added

- The wallet can now repair a did:plc identity's hosting endpoint ("Repair hosting endpoint" on the identity screen): when the hosting server changes hostname underneath the account, the DID document still points at the dead host and every app misroutes. The wallet signs the `atproto_pds` repoint with the device key and submits it directly to plc.directory — no session and no contact with the old endpoint, and the new endpoint is probed to prove it actually hosts the account before anything is signed. A sixth strict pre-sign allowlist guarantees nothing but the endpoint string changes.


### Changed

- The Obsign marketing site now lives at the apex (`obsign.org`), completing the `pds.obsign.org` hostname migration: the PDS landing page, marketing Open Graph metadata and rendered cards, analytics domain gate, Bruno production environment, and deploy docs all reference the apex instead of the retired `about.obsign.org` subdomain. The `about` handle name stays reserved so the retired subdomain can never be claimed as a user handle.


## [0.8.0] - 2026-07-23

### Added

- A wallet-authorized migration whose source PDS can no longer serve the repository now falls back to the user's iCloud repo snapshot: `transfer_repo` imports the locally backed-up CAR instead of failing, provided the mirror holds a snapshot that re-validates against the account's DID. When no valid snapshot exists the original source failure is surfaced unchanged, so a source repo-read fault becomes a non-event for backed-up users — the repo twin of the existing blob-drain mirror fallback.

- The wallet can now rebuild an account on a new PDS entirely from its iCloud backups when the old PDS is gone or uncooperative ("Rebuild from backup" on the identity screen): it enrolls a self-controlled signing key via a device-key-signed PLC operation submitted directly to plc.directory, mints the migration `createAccount` service-auth token offline, imports the backed-up repo snapshot, restores media from the blob mirror, and re-points the DID — with strict guards preserving the wallet's rotation key at every step, and the new account staying inert until final activation.


### Changed

- The Custos mark on the PDS landing page and the Custos marketing page is now the "operator's prompt" glyph (a brass chevron and a filament cursor), matching the Brass Console app icon, replacing the earlier gold disc.


### Fixed

- The wallet's sign-in QR scanner is now visible: the camera preview (a native layer the barcode scanner renders behind the WebView) was staying hidden behind the app's opaque root background, so the scan screen appeared blank. The root and body grounds are now both dropped to transparent while scanning, letting the camera show through.

- Custos now serves its own `did:web` server identity at `/.well-known/did.json`, synthesized from the configured public URL and server DID. Previously the route only served opted-in account documents, so the server's own DID never resolved; it now survives a public-URL migration with no database row involved.


## [0.7.2] - 2026-07-22

### Added

- A periodic blob-integrity scrub sweep now re-hashes every stored blob against its recorded CID and size, and walks the blob directory for both orphan directions — a row whose file has gone missing and a file no row owns — surfacing bitrot, truncation, or a bad restore as an operator alarm (`blob_scrub_*` metrics, `GET /v1/admin/health`) months before a migration would trip over it. When a blob-mirror bucket is configured, a bad or missing file can be auto-healed from its verified-good copy (`[blob_scrub] auto_heal`, on by default).

- The migration blob-drain now degrades per-blob instead of parking the whole migration on a single dead blob: each blob is retried individually, and any that still can't be transferred are collected into a loss manifest the wallet shows you — which media, which post references it, and whether your previous server couldn't serve it or the new one refused it — so you can make an informed choice to continue without them rather than abandoning the run. Verification tolerates the accepted skips, and the progress screen surfaces the specific per-blob failure detail (fetch-from-source vs upload-to-destination) instead of a generic "couldn't transfer one or more blobs."

- Obsign can now keep a user-held backup of an account's media in the wallet's iCloud Drive folder ("Back up media" on the identity screen): an opt-in, incremental mirror of the account's blobs — every fetched file is verified against its content address before it is stored, the mirror size is always shown, and the copy is visible in the Files app. If the hosting server ever loses the originals, "Restore to server" uploads the mirrored files back byte-for-byte, so posts keep pointing at the same media — the one backup layer that survives the server itself failing.

- Brass Console operators can export a redacted, per-relay network-error log from Settings for troubleshooting.

- The user-held media backup now tops itself up in the background: on iOS, an opted-in identity's iCloud mirror is refreshed by a scheduled background task (BGProcessingTask), so media posted days ago no longer stays unprotected until the next time the app is opened. Each run is the same incremental, content-address-verified pass as "Back up now" and degrades per-identity, so one account's failure never stops the others. Settings gains a "Media backup" section to tune it: turn background backups off entirely, restrict them to while charging, or skip them on cellular data.

- If you've backed up your media to iCloud, migrating away from a server that has lost some of your blobs is no longer a loss: when your old server can't serve a piece of media during a migration, the wallet now falls back to your local backup copy, verifies it still matches its content hash, and uploads that copy to your new server. Because media is content-addressed the substitution is exact — nothing in your posts is rewritten — so a backed-up blob your old server dropped shrinks (ideally empties) the migration's loss manifest instead of forcing you to skip it.

- The identity wallet can now back up your posts. Alongside media backup, the Media Backup screen has a "Back up your posts" section that mirrors a full snapshot of your repository — every post, like, follow, and profile edit — into your iCloud Drive. Each snapshot is integrity-checked before it is saved (and the previous good copy is kept if a fetched one fails the check), so you hold a self-custodied, portable copy of the one part of your account that otherwise lives only on your server.

- The marketing site now runs self-hosted, cookieless, IP-anonymized page-view analytics (Umami), disclosed on a new privacy page linked from every footer. No cookies are set, no data leaves the self-hosted instance, and analytics stay scoped to the marketing site — the mobile apps, PDS backend, and any auth surface remain untouched.


### Changed

- The marketing site's copy now matches the shipped custody model: the three-rotation-key ordering (device, recovery, server), backup described as a device-created recovery secret split 2-of-3, the blob bucket mirror alongside Litestream, and identity-method jargon (did:plc) moved off the marketing pages into the docs site's new did:web coverage.

- Marketing FAQ now states the backup cadence precisely: the database streams off-box continuously, while photos replicate on a regular sweep.

- Restoring your iCloud media backup no longer stops at files iOS has offloaded to save space. When a backed-up file isn't on the device, the wallet now asks iCloud to download it, waits for it to arrive (with a time limit), verifies it still matches its content hash, and uploads it — so a restore on a device where most of the mirror has been evicted just works instead of handing you a long list of files to download by hand in the Files app. The restore summary shows how many files it pulled from iCloud first, so a slower restore explains itself. Files that are genuinely gone (no iCloud copy to download) are still reported per-file, and the run continues past them.

- The PDS instance landing page now carries a favicon and shows the Custos brand mark (a gold disc on a cool-slate square) in place of the Obsign seal, matching the marketing site.


### Fixed

- Blob uploads are now crash-durable: bytes are written to a temp file, fsynced, atomically renamed onto the final content-addressed path, and the directory fsynced, before the blob is recorded — closing a gap where a crash or power loss could leave truncated bytes at a valid path even though the database row was already durable.

- `getBlob` now re-hashes each blob's bytes against its CID before serving and returns a 404 (flagging the scrub-sweep alarm counter) on a mismatch, so a corrupted file is never handed to downstream caches; verified responses now carry the `Cache-Control: public, max-age=31536000, immutable` header the blob-handling spec recommends.

- Wallet diagnostics exports now include redacted connection and timeout failures from account creation, OAuth refresh, and authenticated requests.

- The marketing site's analytics embed now restricts itself to the production domain (`about.obsign.org`), so non-production deployments (Railway staging, local previews) no longer report page views into the production analytics dashboard.


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
