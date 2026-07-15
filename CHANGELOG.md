# Changelog

All notable user-visible changes to ezpds are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes are collected in `changelog.d/` during development and inserted here when
`just set-version` prepares a release. There is intentionally no `Unreleased` section.

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
