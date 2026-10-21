# Frozen contracts

What a change may not alter without a deliberate, announced migration: the surfaces other software, stored data, and phones already in users' hands depend on. Wave 11 ([design plan](../design-plans/2026-09-06-v2-in-place.md)) rebuilds Custos and Obsign in place, so every Wave 11 issue is accepted against this list.

How to use it:

- **Citing.** A change names the row it touches by heading, e.g. "frozen contract: Device / Keychain account names". The heading is the stable handle; do not rename one without updating the issues that cite it.
- **Proof.** Each row names the suite that fails if the contract moves. A row marked **no oracle today** is held by convention only; the issue named there adds the oracle, and until it lands, a change touching that row needs a manual check recorded in the PR.
- **Changing a row.** Needs an ADR (or an amendment to the one that froze it) and, for wire and data rows, a compatibility story for clients and databases already deployed. Additive changes (a new route, a new migration, a new capability) are not breaking; renames, removals, and semantic changes are.

## Wire

### XRPC paths and lexicons

Every registered XRPC path, method, request and response shape, and error name, including the vendored Spaces-alpha lexicons at their pinned commit.

- **Oracle:** `just bruno-check` (path coverage between registered routes and `bruno/`), `crates/pds/tests/http_suite.rs`.
- **Gap:** `bruno-check` checks paths only; method, body, and auth changes rely on `http_suite.rs` and review.

### OAuth and DPoP

The OAuth server profile the atproto clients depend on: PAR, consent, token exchange, client-assertion rules, token `sub`, and RFC 9449 DPoP binding (scheme to `cnf.jkt`, nonce rotation per ADR-0032).

- **Oracle:** `tools/oauth-conformance` (`just oauth-conformance-test`; runs in CI's PDS gate). Access-token verification outside `auth::extractors::authenticate_access` does not compile (`verify_access_token` is `pub(super)`), nor does space-credential verification outside `auth::space` (`verify_space_credential` is private).

### Firehose sequence and cursor

`com.atproto.sync.subscribeRepos` frame shapes, monotonic `seq`, cursor and replay semantics, and the durable log retention that replay relies on.

- **Oracle:** `crates/pds/tests/http_suite.rs`; live relay read in the S4 gate (design plan §6).

### DID documents and well-known routes

`/.well-known/atproto-did`, `did:web` documents, and the served `didDoc` shape, including the `#atproto_pds` service id form.

- **Oracle:** `crates/pds/tests/http_suite.rs`; `tools/oauth-conformance` for the metadata documents clients fetch.

### `describeServer` `custos` extension

The capability table advertised under `custos`, and the config gate for each entry.

- **Oracle:** `just capability-docs-check` (table in `crates/pds/src/capabilities.rs` versus the operator capabilities page), `just docs-check` (generated reference).

### auth.md agent flow

The agent-consent and child-lifecycle endpoints and the agent assertion lifecycle (sliding renewal per ADR-0036).

- **Oracle:** `tools/mcp` conformance suite (`just mcp-test`; runs in CI's PDS gate), which self-onboards through the flow against a hermetic PDS.

### MCP tool surface

The tool names, input schemas, and destructive/file-access annotations exposed by `tools/mcp` and single-sourced by `tools/mcp-sidecar` (ADR-0024).

- **Oracle:** `tools/mcp` conformance suite; `tools/mcp-sidecar` hermetic suite (`mcp-check.yml`).

### Notification relay protocol `ezpds/notify/0`

The iroh ALPN, enrollment messages, and opaque push-handle contract between a Custos instance and `crates/notify-relay`.

- **Oracle:** `crates/notify-relay` and `crates/pds` notification tests; golden HPKE vectors in `crates/crypto` cross-checked by the wallet's NSE logic-test bundle.

## Data

### SQLite file and migration log

One SQLite database, one linear log of V-numbered migrations applied by the custom runner. Migrations are append-only; none is edited or reordered once released.

- **Oracle:** the migration runner tests in `crates/pds`, and `http_suite.rs` booting against the full log.

### Blob layout

`{data_dir}/blobs/{cid[0:2]}/{cid}`, content-addressed, with the GC and scrub behaviour that protects pinned blobs.

- **Oracle:** the blob store and GC tests in `crates/pds`.

### KEK-wrapped key columns

Signing and rotation keys at rest wrapped by the master key, and the `pds rewrap-master-key` procedure.

- **Oracle:** `just runbook-parity-check` (canonical runbook versus the published operator page), plus the key-wrapping tests in `crates/pds` and `crates/crypto`.

### Litestream replication

The replicated SQLite file and the restore procedure in [deploy.md](../deploy.md).

- **Oracle:** **no oracle today** beyond the production backup itself; any change to journal mode, page size, or file location needs a manual restore drill recorded in the PR.

## Device

### Bundle ids, Keychain access group, iCloud container

Both apps' bundle identifiers, each app's stable Keychain access group declared first with its legacy group retained, and the frozen iCloud container id ([ADR-0030](decisions/0030-stable-keychain-group-and-frozen-icloud-container.md)).

- **Oracle:** `just bundle-identity-check`; `just ios-template-check` for the template and extension wiring.

### Keychain account names

Every Keychain account-name constant the wallet and console use to store device keys, tokens, ceremony records, and settings (for example `device-rotation-key-priv`, `oauth-access-token`, `relay-base-url`, and the per-DID `{did}:device-key` family in `apps/identity-wallet/src-tauri/src/keychain.rs`; `admin-device-key-priv` and `notification-key-priv` in the console). A renamed account is an unreachable key on an already-installed phone, with no error.

- **Oracle:** **no oracle today.** The wallet's `deny_list_accounts_never_sync` test lists accounts but asserts sync policy, not name stability. The Keychain account-name pin test (MM-561) adds a golden list.

### Synchronizable share-1 slot

Recovery share 1 lives in the iCloud-synchronizable Keychain; nothing outside the Share 1 family is stored synchronizable.

- **Oracle:** the wallet's `deny_list_accounts_never_sync` test (negative side). The positive side, that the share-1 slot name and attributes are stable, is covered by the same pin test (MM-561).

### Non-exportable Secure Enclave keys

Device keys on a real device are generated in and never leave the Secure Enclave; software keys exist only on simulator and macOS host builds.

- **Oracle:** the iOS cross-compile and the `ios-device-key` tests; the device behaviour itself is only provable on hardware, via a TestFlight install-over (design plan §6, M1 and M4 gates).

## Operations

### Deploy artifact and Railway wiring

The root `Dockerfile` as the only PDS build, Railway's native GitHub integration with "Wait for CI", staging on `main`, production on the `production` branch ([ADR-0008](decisions/0008-pds-as-oci-image-not-nix-built.md), [ADR-0009](decisions/0009-deploy-via-railway-github-integration.md)).

- **Oracle:** the CI PDS gate (`just ci-pds`); `verify-release` on the `production` branch. A local `docker build` is the repro for Railway build failures.

### `EZPDS_*` configuration

Every environment variable and config-file key an operator sets, with its default.

- **Oracle:** `just docs-check` (generated config reference), `just capability-docs-check`.

### Admin token

The bearer admin token and the admin route authentication it gates.

- **Oracle:** `crates/pds/tests/http_suite.rs`; the Brass Console's signed-envelope scheme ([ADR-0018](decisions/0018-admin-signed-request-envelope.md)) is separate and frozen with the wire rows above.

## Whole-system oracles

These are not rows; they are the suites a Wave 11 change is expected to leave green and unchanged: `crates/pds/tests/http_suite.rs`, `tools/oauth-conformance`, the `tools/mcp` conformance suite, the browser-harness scenarios in both apps, the docs screenshots (`just docs-screenshots-check`, advisory), and `just bruno-check`.
