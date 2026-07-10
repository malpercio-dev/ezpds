# Architecture Decision Records

An **Architecture Decision Record (ADR)** captures a single significant
architectural decision: the context that forced it, the decision itself, and the
consequences we accepted. ADRs are the *historical record* — read them to
understand why the architecture is the way it is.

## Rules

- **ADRs are immutable once `Accepted`.** Don't rewrite history. If a decision
  changes, write a *new* ADR and mark the old one `Superseded by ADR-NNNN`.
- **One decision per record.** If you're tempted to use "and", it's probably two
  ADRs.
- **Numbered sequentially**, zero-padded: `0001-...`, `0002-...`. The number is
  permanent; the slug describes the decision.
- **Status** is one of: `Proposed`, `Accepted`, `Deferred`, `Deprecated`,
  `Superseded by ADR-NNNN`. (`Deferred` = decided in principle but intentionally
  not scheduled; it waits on a named trigger.)
- Record decisions that are *already embodied in the code* too — a decision
  doesn't have to be new to be worth recording. Backfilling the load-bearing
  ones gives future readers the "why".

## Writing a new ADR

1. Copy [`adr-template.md`](adr-template.md) to
   `NNNN-short-slug.md` (next number).
2. Fill it in. Keep it tight — an ADR is a page, not a spec. Link to
   design plans / specs for detail.
3. Add it to the log below.
4. If it changes a documented fact, update the relevant doc under
   [`../`](../) in the same change.

## Log

| ADR | Status | Decision |
| --- | --- | --- |
| [0000](0000-record-architecture-decisions.md) | Accepted | Record architecture decisions as ADRs |
| [0001](0001-client-held-rotation-key-custody.md) | Accepted | The user's wallet holds `rotationKeys[0]`; the PDS holds `rotationKeys[1]` |
| [0002](0002-wallet-authorized-account-migration.md) | Proposed | Account migration is wallet-authorized by default, with a PDS-signed interop fallback |
| [0003](0003-did-plc-as-did-method.md) | Accepted | `did:plc` as the DID method (not `did:web`/`did:key`) |
| [0004](0004-pds-signed-repo-commits.md) | Accepted | The PDS holds the repo signing key and signs commits |
| [0005](0005-functional-core-imperative-shell.md) | Accepted | Functional Core / Imperative Shell workspace architecture |
| [0006](0006-oauth-callback-via-aswebauthenticationsession.md) | Accepted | OAuth callback via ASWebAuthenticationSession (vendored plugin), not deep links |
| [0007](0007-mobile-only-pds-is-full-pds.md) | Accepted | Mobile-only phase — the PDS is a full PDS (four-phase device model) |
| [0008](0008-pds-as-oci-image-not-nix-built.md) | Accepted | Ship the PDS as an OCI image built by the Dockerfile; keep the flake minimal |
| [0009](0009-deploy-via-railway-github-integration.md) | Accepted | Deploy via Railway's native GitHub integration; CI gates, it doesn't deploy |
| [0010](0010-toolchains-managed-outside-nix.md) | Accepted | Manage the compiler toolchains outside Nix (rustup + dynamic Apple toolchain) |
| [0011](0011-sqlite-via-sqlx.md) | Accepted | SQLite (via sqlx) as the datastore |
| [0012](0012-canonical-dag-cbor-for-plc-ops.md) | Accepted | Canonical DAG-CBOR encoding for did:plc operations |
| [0013](0013-native-swiftui-shell-over-rust-core.md) | Deferred | Native SwiftUI shell over the Rust core (if/when we leave Tauri) |
| [0014](0014-atrium-repo-for-repo-engine.md) | Accepted | Adopt `atrium-repo` for the repo engine's MST and block store |
| [0015](0015-ci-on-github-actions.md) | Accepted | Host CI on GitHub Actions (leaving the tangled spindle) |
| [0016](0016-dynamic-lexicon-permission-set-resolution.md) | Accepted | Dynamic Lexicon-based permission-set resolution, not a static scope table |
| [0017](0017-multi-relay-admin-pairings.md) | Accepted | One global admin device key across N relays; pairings in a single versioned keychain document with a Rust-owned active pointer |
| [0018](0018-admin-signed-request-envelope.md) | Accepted | Admin auth via per-device P-256 signed-request envelopes; master token stays as break-glass |
| [0019](0019-authmd-agent-authentication.md) | Accepted | Adopt the auth.md convention (self-registration, human claim ceremony, jwt-bearer exchange) as the agent-auth surface |
| [0020](0020-set-revocation-trusted-issuers.md) | Accepted | Provider-driven agent revocation via Security Event Tokens, gated on the existing `trusted_issuers` list |
