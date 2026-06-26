# v0.1 Linear Issue Plan

Proposed breakdown for the ezpds v0.1 milestone.
Each issue is scoped to be completable in hours by a human or within an agent's context window.

Issues are organized into waves for incremental deployability. Each wave produces a running system you can test.

---

## Wave 0 — Project Scaffolding

Checkpoint: `nix develop` drops into a shell with Rust toolchain, `cargo build` succeeds, `just check` runs, CI is green on an empty workspace, `nix build` produces a PDS binary.

### Dependency graph

```
MM-63 (Cargo workspace) ──┬──> MM-64 (devenv) ──> MM-68 (CI) ⚠️ human-preferred
                          ├──> MM-65 (Nix build) ──┬──> MM-66 (Docker)
                          │                        └──> MM-135 (NixOS module)
                          ├──> MM-67 (Justfile)         ↑
                          ├──> MM-69 (Config) ──────────┘
                          └──> MM-70 (Error types)

All ──> MM-136 (Checkpoint validation)
```

### Issues

1. **MM-63** — Cargo workspace setup (root Cargo.toml, crate directories: PDS, repo-engine, crypto, common)
2. **MM-64** — Nix flake + devenv — dev shell with Rust toolchain, SQLite, just, cargo-audit, clippy; `nix develop` is the single entry point for contributors. *Blocked by: MM-63*
3. **MM-65** — Nix flake — PDS build output (`nix build .#PDS`). *Blocked by: MM-63*
4. **MM-135** — NixOS module for PDS deployment (systemd service, pds.toml config options, user/group). *Blocked by: MM-65, MM-69*
5. **MM-66** — Docker image derived from Nix build (`nix build .#docker-image`) — single-layer OCI image, minimal base. *Blocked by: MM-65*
6. **MM-67** — Justfile with recipes: check, build, test, fmt, clippy, run-PDS, nix-build, docker-build. *Blocked by: MM-63*
7. **MM-68** — Tangled CI pipeline (.tangled/workflows/ — build, test, clippy, fmt, cargo-audit; Nix-native via Nixery). ⚠️ Human-preferred — spindle YAML format is niche. *Blocked by: MM-64*
8. **MM-69** — Configuration system (pds.toml parsing, env var overrides, crate: common). *Blocked by: MM-63*
9. **MM-70** — Error types and shared API envelope (crate: common). *Blocked by: MM-63*
10. **MM-136** — Wave 0 checkpoint validation — run through all checkpoint criteria on a clean checkout. *Blocked by: all above*

---

## Wave 1 — Running Server

Checkpoint: `curl localhost:port/_health` returns OK. `describeServer` returns valid ATProto server metadata.

9. Axum HTTP server skeleton + XRPC routing (crate: PDS)
10. SQLite schema v1 (accounts, devices, sessions, repos, blobs, oauth tables)
11. XRPC: _health endpoint
12. XRPC: com.atproto.server.describeServer

---

## Wave 2 — Auth

Checkpoint: Bluesky app can complete OAuth flow and receive tokens. createSession/getSession work.

13. atproto-oauth-axum integration + server metadata endpoint (/.well-known/oauth-authorization-server)
14. OAuth: Authorization endpoint + minimal server-rendered consent UI
15. OAuth: Token endpoint (DPoP, PKCE, refresh rotation)
16. OAuth: PAR endpoint
17. OAuth: JWKS endpoint
18. XRPC: com.atproto.server.createSession
19. XRPC: com.atproto.server.getSession
20. XRPC: com.atproto.server.refreshSession

---

## Wave 3 — Account Creation + Identity

Checkpoint: Mobile app can create account, DID is resolvable, handle works. User can log into Bluesky.

21. Provisioning: POST /v1/accounts (web dashboard account creation)
22. Provisioning: POST /v1/accounts/mobile (combined mobile account creation + device binding)
23. Provisioning: POST /v1/accounts/sessions (login)
24. Provisioning: POST /v1/accounts/claim-codes
25. Provisioning: POST /v1/devices (device registration via claim code)
26. Provisioning: GET /v1/devices/:id/pds (PDS endpoint discovery)
27. DID creation — did:plc via PLC directory proxy (crate: crypto)
28. Provisioning: POST /v1/dids (DID ceremony endpoint)
29. Provisioning: GET /v1/dids/:did (DID document retrieval)
30. PDS signing key generation — POST /v1/pds/keys (crate: crypto)
31. Shamir 2-of-3 share generation at onboarding (crate: crypto)
32. Provisioning: POST /v1/handles (handle creation + subdomain DNS)
33. Provisioning: GET /v1/handles/:handle/status (DNS propagation polling)
34. Provisioning: DELETE /v1/handles/:handle
35. XRPC: com.atproto.identity.resolveHandle

---

## Wave 4 — Repo CRUD + Blobs

Checkpoint: User can create a post via Bluesky. Records stored in repo, blobs uploadable.

36. Repo engine — MST construction + CAR storage (crate: repo-engine)
37. Repo engine — commit construction + signing integration (crate: repo-engine)
38. XRPC: com.atproto.repo.createRecord
39. XRPC: com.atproto.repo.putRecord
40. XRPC: com.atproto.repo.deleteRecord
41. XRPC: com.atproto.repo.applyWrites
42. XRPC: com.atproto.repo.getRecord
43. XRPC: com.atproto.repo.listRecords
44. XRPC: com.atproto.repo.describeRepo
45. Blob storage backend — local FS, CID generation, MIME sniffing (crate: PDS)
46. XRPC: com.atproto.repo.uploadBlob
47. XRPC: com.atproto.sync.getBlob
48. XRPC: com.atproto.sync.listBlobs
49. Blob garbage collection — 6-hour temp cleanup, dereferenced check

---

## Wave 5 — Federation

Checkpoint: PDS emits firehose. BGS can subscribe. Posts appear in Bluesky AppView. The PDS is a federating PDS.

50. Firehose emitter — subscribeRepos WebSocket event stream (crate: PDS)
51. XRPC: com.atproto.sync.subscribeRepos (WebSocket handler)
52. XRPC: com.atproto.sync.getRepo (full CAR export)
53. XRPC: com.atproto.sync.getRecord (single record as CAR)
54. XRPC: com.atproto.sync.listRepos
55. XRPC: com.atproto.sync.getRepoStatus
56. requestCrawl trigger on new content
57. Iroh tunnel integration — PDS endpoint for device connections (crate: PDS)

---

## Wave 6 — App Proxy + Remaining Endpoints

Checkpoint: Full v0.1 XRPC surface. User preferences persist locally. Chat endpoints proxied.

58. XRPC: app.bsky.* catch-all proxy to appview (bsky.network)
59. XRPC: app.bsky.actor.getPreferences (local storage)
60. XRPC: app.bsky.actor.putPreferences (local storage)
61. XRPC: chat.bsky.convo.getLog (proxy)
62. XRPC: chat.bsky.convo.listConvos (proxy)
63. XRPC: com.atproto.server.activateAccount
64. XRPC: com.atproto.server.deactivateAccount
65. Provisioning: GET /v1/accounts/:id/usage
66. Provisioning: GET /v1/accounts/:id/storage (blob metrics)

---

## Wave 7 — Transfer, Testing, Hardening

Checkpoint: Planned device swap works. Interop tests pass. CI catches regressions.

67. Provisioning: POST /v1/transfer/initiate
68. Provisioning: POST /v1/transfer/accept
69. Provisioning: POST /v1/transfer/complete
70. L1 interop test vectors (atproto-interop-tests + interop-test-files)
71. cargo-audit in CI (already in Wave 0 CI, this adds policy + dep review)
72. Tauri IPC lockdown — minimal allowlist definition

---

## Notes

- Some issues span both an XRPC endpoint and a backend concern (e.g., uploadBlob is XRPC handler in Wave 4, blob storage backend is a separate issue). The XRPC issue implements the handler; the backend issue implements the storage layer it calls.
- subscribeRepos has two issues: the firehose emission pipeline (Wave 5) and the WebSocket handler that serves it.
- DID creation spans the crypto crate (PLC directory integration) and the provisioning API endpoint (POST /v1/dids).
- Wave 0's CI pipeline includes cargo-audit; Wave 7's cargo-audit issue adds dep review policy and Cargo.lock diff checks.
- Total: 74 issues across 8 waves (72 original + MM-135 NixOS module split + MM-136 checkpoint validation).

## Crate Structure

```
ezpds/
├── Justfile
├── Cargo.toml              (workspace root)
├── flake.nix               (devenv, build outputs, NixOS module, Docker image)
├── flake.lock
├── devenv.nix              (dev shell configuration)
├── crates/
│   ├── PDS/              (Axum server, XRPC, OAuth, provisioning API, blob storage)
│   ├── repo-engine/        (MST, CAR, commit construction — atrium-repo integration)
│   ├── crypto/             (signing, Shamir, DID operations — rsky-crypto integration)
│   ├── common/             (shared types, error envelope, config parsing)
│   └── app-desktop/        (Tauri shell — v0.2, not in scope for v0.1)
├── nix/
│   ├── module.nix          (NixOS module for PDS deployment)
│   └── docker.nix          (Docker image derivation from Nix build)
├── .tangled/workflows/     (CI pipelines — Nix-native via Nixery)
├── docs/                   (specs, this plan)
└── tests/                  (integration tests)
```

## License

TBD — decision deferred to pre-v1.0. Options under consideration: AGPL-3.0, Apache-2.0/MIT dual, or BSL-style.
