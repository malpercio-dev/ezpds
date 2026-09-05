# Threat model

Last verified: 2026-09-05

Custos is a self-hostable ATProto PDS. This is the operator-tier map of what it
protects, who can reach it, and where each mitigation actually lives. Every row
below cites the ADR, code path, or CI gate that implements it — an unverified
claim doesn't belong here, it belongs in [Open items](#open-items).

## Scope and assets

| Asset | Where it lives |
| --- | --- |
| Genesis/rotation keys (device, recovery, PDS) | Wallet Secure Enclave / Keychain (device), re-derived only during recovery from Shamir shares (recovery), PDS key store (PDS) — [`docs/architecture/identity-and-key-custody.md`](../architecture/identity-and-key-custody.md), genesis ops in `crates/crypto/src/plc.rs` |
| Repo signing key | PDS-side, wrapped by the master KEK; signs every repo commit — [ADR-0004](../architecture/decisions/0004-pds-signed-repo-commits.md), rotation in `crates/pds/src/auth/signing_key.rs` |
| Master key (KEK) | `EZPDS_SIGNING_KEY_MASTER_KEY`, env-only, wraps every at-rest secret — [`docs/operations/master-key-disaster-runbook.md`](../operations/master-key-disaster-runbook.md) |
| Device keys | `crates/ios-device-key/src/device_key.rs` — Secure Enclave on a real device, software P-256 elsewhere, over a Keychain the calling app supplies |
| Recovery shares (Shamir) | `crates/crypto/src/shamir.rs` (3-share split, 2-of-3 reconstruction), rendered to words by `crates/crypto/src/mnemonic.rs` |
| Account data and blobs | SQLite (`{data_dir}/*.db`) + `{data_dir}/blobs/`, Litestream-replicated DB and mirror-replicated blobs — [`docs/deploy.md`](../deploy.md) |
| Sessions/tokens | Access/refresh JWTs and OAuth DPoP-bound tokens — `crates/pds/src/auth/jwt.rs`, `crates/pds/src/auth/dpop.rs` |
| DID documents / handles | `crates/pds/src/identity/` (`did.rs`, `handle.rs`, `resolution.rs`, `well_known.rs`) |
| Push-payload plaintext | HPKE-sealed to a per-device key before it leaves the PDS — `crates/crypto/src/hpke.rs`, unsealed only in the wallet's Notification Service Extension |
| Admin authority | Master admin token or per-device signed-request envelope — `crates/pds/src/auth/guards.rs`, [ADR-0018](../architecture/decisions/0018-admin-signed-request-envelope.md) |

## Actors and trust boundaries

| Actor | May do | Must never learn |
| --- | --- | --- |
| Anonymous internet client | Fetch public XRPC reads, `.well-known`, did:web docs | Any session, key material, or private repo content |
| OAuth client / app | Act within its granted scope, DPoP-bound to its own key | Another client's token or `cnf.jkt` private key |
| Account owner (via wallet) | Full session, identity ops, rotation-key operations | Other accounts' keys or data |
| Agent (auth.md flow) | Act as a sovereign child or acts-as-you delegate, per grant | Durable custody of the user's own rotation keys |
| Admin device (admin-companion) | Per-relay operator actions its signed envelope authorizes | Another relay's admin key, or a user's account keys |
| Operator with server shell | Everything — full trust boundary | N/A (see [Accepted risks](#accepted-risks--non-goals)) |
| plc.directory | Receive and serve signed PLC operations | Any rotation private key |
| Firehose relay / crawlers | Read the public repo stream | Private records, blobs behind auth, session tokens |
| Notification relay (blind courier) | Move HPKE-sealed opaque payloads to APNs | Push-payload plaintext, any instance or device key |
| MCP sidecar (hosted tier) | Forward one caller's own credential per request | Any user's durable credential (holds none) |
| Apple / APNs | Deliver an opaque encrypted push | Notification plaintext |

Boundaries and their primary control:

| Boundary | What crosses | Primary control |
| --- | --- | --- |
| Client ↔ PDS HTTP | Bearer/DPoP tokens, XRPC bodies | `auth::extractors::authenticate_access`, TLS |
| PDS ↔ plc.directory | Signed PLC operations | DAG-CBOR canonicalization + signature verification (`crates/crypto/src/plc.rs`) |
| PDS ↔ outbound fetch (handle/did:web/client metadata/JWKS/blob mirror) | Caller-influenced URLs | `AppState::hardened_http_client` + `SsrfResolver` (`crates/pds/src/identity/proxy.rs`) — **except OAuth client-metadata fetch from PAR, see [Open items](#open-items)** |
| PDS ↔ SQLite/filesystem | Queries, blob reads/writes | Per-crate DB module ownership (`crates/pds/AGENTS.md`), path validation |
| Wallet ↔ Secure Enclave/Keychain | Signing requests, key material | `crates/ios-device-key`, no key ever leaves the enclave |
| Wallet ↔ PDS | Session tokens, DPoP proofs | RFC 9449 binding (`crates/pds/src/auth/dpop.rs`) |
| PDS ↔ notify-relay (iroh) | Enrollment RPCs, sealed push payloads | Connection-identity binding (`crates/notify-relay/AGENTS.md`) |
| Sidecar ↔ PDS | Forwarded OAuth bearer, no cached secret | [ADR-0024](../architecture/decisions/0024-hosted-agent-credential-forwarding.md) |
| Admin-companion ↔ PDS | Per-device signed-request envelope or master token | `crates/pds/src/auth/guards.rs` |

## Threats and mitigations

### Token theft/replay

Every access-token check funnels through `auth::extractors::authenticate_access`
(`crates/pds/src/auth/extractors.rs`), which refuses a refresh-scoped token
outright (commit `73505e01`) and enforces the DPoP scheme ↔ `cnf.jkt` binding in
both directions. `just auth-seam-check` fails the build on any new direct
`verify_access_token` call outside that seam. Resource-endpoint DPoP proofs keep
no `jti` replay store by design — see the documented tradeoff in
`crates/pds/src/auth/dpop.rs` (`validate_dpop`'s doc comment: RFC 9449 §11.1
makes `jti` tracking a SHOULD, replay is bounded by the 60s `iat` window plus the
`ath` token binding, and every route behind `AuthenticatedUser` must stay
idempotent for that to be safe).

### OAuth client impersonation

PAR/authorize require `code_challenge_method=S256` (`crates/pds/src/routes/oauth_par.rs`),
an exact `redirect_uri` match against the client's registered `redirect_uris`
(same file), and — for a Private-Use URI Scheme redirect on discoverable
client metadata — the reverse-FQDN rule (`validate_private_use_redirect` in
`crates/pds/src/auth/oauth_client_resolution.rs`). Client identity for a
URL-shaped `client_id` is resolved by fetching its metadata document; a failed
resolution is negative-cached to bound repeated outbound fetches against the
unauthenticated PAR endpoint.

### SSRF via caller-influenced fetches

`crates/pds/src/identity/proxy.rs` is the SSRF guard: a validated scheme/host
check plus a hardened `reqwest::Client` (`AppState::hardened_http_client`)
whose custom `SsrfResolver` re-applies a public-address allowlist at DNS
resolution time, closing the redirect/re-resolution TOCTOU gap. `just
ssrf-client-check` freezes the well-known handle resolver onto that client.
**As of this branch, the OAuth client-metadata fetch called from
`routes/oauth_par.rs` still passes the plain `state.http_client`**, not the
hardened one — `auth::client_attestation`'s client-metadata resolution already
uses `state.hardened_http_client`, but the PAR path doesn't. A sibling PR
(`sec/client-metadata-ssrf`) fixes this; see [Open items](#open-items) rather
than treating it as mitigated here.

### Admin-token brute force/timing

`require_admin_token` (`crates/pds/src/auth/guards.rs`) compares the bearer
token with `subtle::ConstantTimeEq` rather than `==`, so an early byte
mismatch reveals nothing over timing. The admin surface is additionally
covered by the global per-IP rate limiter in `crates/pds/src/rate_limit.rs`.
Per-device admin auth ([ADR-0018](../architecture/decisions/0018-admin-signed-request-envelope.md))
is the preferred path; the master token is a break-glass fallback.

### Key compromise/rotation & recovery

The wallet holds the highest-priority rotation key; the recovery key
(Shamir-derived, `crates/crypto/src/shamir.rs` + `mnemonic.rs`) outranks the
PDS's own key, so a compromised PDS cannot out-rank a user reconstructing
their recovery seed inside plc.directory's recovery window — [ADR-0027](../architecture/decisions/0027-rotation-key-ordering.md),
[ADR-0037](../architecture/decisions/0037-hd-derived-child-custody.md). Master-KEK
loss/compromise has its own runbook: [`docs/operations/master-key-disaster-runbook.md`](../operations/master-key-disaster-runbook.md).
Repo-signing-key rotation is wallet-signed and PDS-submitted under a repo
write lock ([ADR-0025](../architecture/decisions/0025-wallet-driven-repo-key-rotation.md)).

### Identity hijack via handle/DID

Handle structural validation rejects bare single-label handles before they're
baked into a did:plc genesis op (`crates/pds/src/identity/handle.rs`).
`did:web` may be minted or hosted only after proving control of the
user-owned domain ([ADR-0022](../architecture/decisions/0022-did-web-for-user-owned-domains.md)).
The well-known/DNS handle resolvers (`crates/pds/src/identity/well_known.rs`,
`dns.rs`) are the caller-influenced fetch the SSRF guard above protects.

### Data loss

Litestream continuously replicates the SQLite WAL to object storage; blobs
are replicated separately by the PDS's own blob mirror with restore-on-boot
CID verification — both in [`docs/deploy.md`](../deploy.md#master-key-kek-backup-and-disaster-recovery).
`crates/pds/src/blob_gc.rs` pins any blob still referenced (`temp_until`) so
garbage collection cannot delete a blob a repo still points to — the fix for
the 2026-07-25 incident this code's `temp_until`-gating enforces. Separately,
atrium-repo 0.1.8's MST `split_subtree` bug silently dropped sibling subtrees
on a high-layer insert ([2026-08-27 incident](../2026-08-27-mst-data-loss-incident.md));
the fix is vendored and gated by `crates/repo-engine/tests/mst_split_gate.rs`
([ADR-0034](../architecture/decisions/0034-vendored-atrium-repo-mst-patch.md)).

### Push-notification confidentiality

Payloads are HPKE-sealed to a per-device key before they ever reach the
notify-relay (`crates/crypto/src/hpke.rs`); the relay is a **blind courier**
that copies the sealed `kid`/`enc`/`ct` into the APNs envelope without
inspecting it and holds no instance or device key
(`crates/notify-relay/AGENTS.md` → "Security Invariants"). Unsealing happens
only in the wallet's Notification Service Extension, which renders an
explicit unverified notice for anything it cannot authenticate.

### Agent/MCP credential handling

The hosted agent tier authenticates through OAuth and forwards the caller's
own access token on every call; it persists no user credential, agent
assertion, or token ([ADR-0024](../architecture/decisions/0024-hosted-agent-credential-forwarding.md)).
Agents may be sovereign child identities with their own rotation-key custody
rather than acting as the user directly ([ADR-0023](../architecture/decisions/0023-sovereign-child-agent-identities.md)).
Confirmed agent bindings carry a 30-day sliding-renewal assertion TTL, with
revocation — not expiry — as the actual kill switch ([ADR-0036](../architecture/decisions/0036-sliding-agent-assertion-renewal.md)).

### Spaces authorization

Every `com.atproto.space.*` read/sync route authenticates through
`auth::space::authenticate_space_read` (`crates/pds/src/auth/space.rs`), the
one seam accepting a covering OAuth grant *or* a DPoP-bound space credential —
never a bearer credential — with full RFC 9449 proof validation and per-host
`jti` replay tracking (the proposal's one MUST-track case, unlike the
resource-endpoint posture above). `just space-auth-seam-check` confines
`verify_space_credential`/`validate_dpop` calls to that seam.

### Supply chain

`cargo audit` scans `Cargo.lock` against the RustSec DB on every CI run and
weekly on a schedule; accepted advisories and their rationale live in
[`.cargo/audit.toml`](../../.cargo/audit.toml). `cargo deny` (policy in
[`deny.toml`](../../deny.toml)) is the separate license + duplicate-major-version
+ allowed-source gate — `just deny`. The vendored `atrium-repo` MST patch is
guarded by its own gate test (above); GitHub Actions steps are pinned to a
commit SHA (`.github/workflows/ci.yml`), not a floating tag.

### Mobile IPC boundary

Both iOS apps gate every webview→Rust call through Tauri v2 capability
allowlists, with `core:default` and `withGlobalTauri` both refused. Full spec:
[`docs/security/tauri-ipc-boundary.md`](tauri-ipc-boundary.md); enforced by
`just cap-check` (`scripts/capability-check.sh`).

## Accepted risks / non-goals

- **No resource-endpoint DPoP `jti` replay store, by design.** RFC 9449 §11.1
  makes it a SHOULD; the accepted exposure is a captured (token + proof) pair
  replayable against the same method+URI within the ~60s freshness window,
  contingent on every `AuthenticatedUser` route staying idempotent
  (`crates/pds/src/auth/dpop.rs`).
- **An operator with server shell access is fully trusted.** The threat model
  here is external and semi-trusted actors, not the operator's own machine —
  consistent with `require_admin_token`'s master-token fallback existing at
  all ([ADR-0018](../architecture/decisions/0018-admin-signed-request-envelope.md)).
- **Single-node SQLite.** No multi-writer story; Litestream gives durability,
  not horizontal scale ([ADR-0011](../architecture/decisions/0011-sqlite-via-sqlx.md)).
- **The notify-relay is trusted for availability only, never confidentiality**
  by construction — it never holds a key that would let it do otherwise
  (`crates/notify-relay/AGENTS.md`).

## Open items

- **OAuth client-metadata fetch is not yet on the hardened client.**
  `routes/oauth_par.rs`'s `resolve_client_metadata` call passes
  `state.http_client`, not `state.hardened_http_client` — a caller-influenced
  URL fetched without the SSRF allowlist. `auth::client_attestation`'s
  equivalent call already uses the hardened client. Fixed by
  [#638](https://github.com/malpercio-dev/ezpds/pull/638), which also refuses
  an IP-literal `client_id` at a private address before any fetch and extends
  `just ssrf-client-check` to every `resolve_client_metadata` call site; once
  it merges this row moves under SSRF in Threats and mitigations.
- **`unsafe` FFI without `// SAFETY:` comments.** `apps/identity-wallet/src-tauri/src/apns.rs`
  (APNs delegate registration) and the vendored `apple.rs` in
  `apps/identity-wallet/vendor/tauri-plugin-auth-session/src/` both carry
  `unsafe` Objective-C interop blocks with no `// SAFETY:` justification.
- **DIDs are typed as raw `String`, not a validated newtype.** Structural
  validity is enforced at specific call sites (e.g.
  `crates/pds/src/identity/handle.rs`, `did.rs`) rather than at the type
  boundary, so a malformed DID can travel further through the codebase before
  any check runs.

## Keeping this current

The gates that hold specific rows above are `just auth-seam-check`,
`just space-auth-seam-check`, `just ssrf-client-check`, `just cap-check`,
`just capability-docs-check`, `just runbook-parity-check`,
`just bundle-identity-check`, `just audit`, and `just deny` — all part of
`just ci` / `just ci-pds`, listed with what each one freezes in the root
[`AGENTS.md`](../../AGENTS.md). A change that adds a new trust boundary, or an
ADR whose subject is a security decision, adds or updates a row here in the
same change — the same discipline `docs/architecture/decisions/README.md`
asks of a fact doc when an ADR changes it.
