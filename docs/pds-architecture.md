# Desktop PDS — System Architecture

**v8 — Mobile-First Reconciliation · Four-Phase Milestones**

Sovereign AT Protocol PDS on macOS via Tauri + Repo Engine + Iroh

## Milestone Legend

**v0.1** — Mobile-Only PDS · relay is full PDS

**v0.2** — Desktop Enrollment · relay as proxy+signer

**v1.0** — Public Launch · product-ready

**LATER** — Designed, built post-launch

---

## Changelog

### v8 Changes — Mobile-First Reconciliation

Architecture reconciled with mobile architecture spec v1.2 (canonical). The relay is no longer just a tunnel+proxy — in the mobile-only phase, it IS the PDS.

- **NEW** Four-phase milestone model (v0.1 / v0.2 / v1.0 / v2.0+)
- **NEW** Phase 0: Mobile-Only lifecycle (relay as full PDS)
- **FIX** Signing model: relay always signs, device constructs unsigned commits
- **FIX** Tier model: Free/Pro/Business + BYO as deployment model
- **FIX** Firehose: native emission (mobile-only) vs proxy (desktop-enrolled)
- **FIX** Shamir: basic share generation moves to v0.1 (required at onboarding)
- **FIX** DID keystore: Shamir split required at account creation, not v1.0
- **REF** See unified-milestone-map.md for phase details

### Previous Versions

v2: Corrected relay model (outbound only). v3: Shamir key recovery + repo snapshots. v4: Conformance strategy. v5: Custom PDS shell + atrium/rsky deps. v6: GeoDNS + BYO relay. v7: Milestone scoping + runtime threats.

---

## Device Lifecycle Phases

The product launches mobile-first. The relay is a full PDS before any desktop is involved.

**Phase: Mobile-Only (v0.1)**
- Relay behavior: Full PDS — hosts repo, serves XRPC, signs commits, emits firehose
- Repo location: Relay (primary and only copy)
- Phone role: Identity wallet (key management, device admin)
- Desktop: Does not exist yet

**Phase: Desktop-Enrolled (v0.2)**
- Relay behavior: XRPC proxy + signer — forwards writes to desktop, signs commits, serves reads from cache
- Repo location: Desktop (primary), relay (cache)
- Phone role: Identity wallet + device manager
- Desktop: Runs repo engine, constructs unsigned commits

**Phase: Desktop-Offline (v0.2+)**
- Relay behavior: Serves reads from cache, 503 on writes
- Repo location: Desktop (authoritative but unreachable)
- Phone role: Same as desktop-enrolled
- Desktop: Sleeping / powered off

---

## Layer 01 — Device Layer (Desktop, v0.2+)

*In v0.1 (Mobile-Only), there is no device layer. All operations run on the relay.*

### Tauri Shell

**v0.2**

🖥️ Native macOS app. Process lifecycle, auto-updates, system tray. Minimal IPC allowlist — webview cannot access filesystem, shell, or network directly.

### Repo Engine

**v0.2**

📦 Purpose-built repo construction engine. SQLite-backed, local-first. Builds MST structures, constructs unsigned commits, manages collection storage. In desktop-enrolled mode, the relay proxies XRPC writes here, then signs the resulting commits. Does not serve XRPC directly to the network — the relay is always the network-facing endpoint.

### Dependency Stack

**v0.1**

🧩 **atrium-api** — XRPC types, lexicon defs (auto-generated). **atrium-repo** — MST read/write, CAR export. **rsky-crypto** — P-256/K-256 commit signing.

### Iroh Endpoint

**v0.1**

🔗 QUIC-based tunnel to relay. NAT traversal, connection resumption on wake. Pushes unsigned repo commits to relay for signing when online.

### DID Keystore

**v0.1**

🔐 Signing keys in macOS Keychain (desktop) / Secure Enclave (phone). At account creation, root rotation key is split via 2-of-3 Shamir: Share 1 = iCloud Keychain, Share 2 = relay escrow, Share 3 = user's choice (device-local or BIP-39 paper backup). Basic key management for v0.1. Full recovery UI in v1.0.

### Recovery Share Manager

**v1.0**

🛟 Full UI for Shamir share management and recovery ceremony. View share status, rotate shares, initiate recovery from device loss. Note: basic share GENERATION happens at v0.1 (during account creation). This component adds the management and recovery interface.

### Compat Warning Banner

**v1.0**

⚠️ Non-blocking in-app warning when spec drift detected. Links to update. Never blocks launch.

### XRPC Hardening

**v1.0**

🛡️ Request size limits on all endpoints. Rate limiting at relay. cargo-fuzz targets for CBOR/CAR/MST parsing paths. Adversarial MST key distribution testing per ATProto spec guidance.

*REMOVED: rsky-pds (fork) — Replaced by repo engine in v5. Now tracking a spec, not a codebase.*

---

## Layer 02 — Relay Layer (Managed + BYO)

### Managed Relay (Your Infrastructure)

#### Iroh Relay Node

**v0.1**

🚇 Single-region for v0.1. Always-on tunnel endpoint. In mobile-only mode, serves as full PDS — no tunnel needed, relay handles all XRPC directly. In desktop-enrolled mode, acts as tunnel endpoint for device ↔ relay communication. Receives unsigned commits from device, constructs signed commits, proxies XRPC repo reads.

#### requestCrawl Trigger

**v0.1**

📣 On device reconnect, pings BGS requestCrawl so new content propagates immediately.

#### Firehose Emitter

**v0.1**

📡 Native com.atproto.sync.subscribeRepos WebSocket endpoint. Required for federation — every PDS must emit a firehose. In mobile-only mode, the relay is the PDS and emits directly. In desktop-enrolled mode, emits commits as they're signed.

#### Firehose Proxy

**v0.2**

📡 Maintains persistent BGS WebSocket on behalf of sleeping desktop. Replays commits from buffer when desktop reconnects. Ensures BGS sees continuous uptime even when desktop is offline. Desktop-enrolled feature — not applicable in mobile-only mode. Pro/Business tier on managed relay.

#### Commit Buffer

**v0.2**

💾 Rolling log of signed repo commits. Feeds firehose proxy during offline. Tiered retention: 7d free, 30d paid, 90d business.

#### Provisioning API

**v0.1**

⚙️ Account setup, domain linking, relay config. Onboarding flow for new connections. Core provisioning needed from day one.

#### Key Share Escrow

**v0.1**

🔏 Holds one encrypted Shamir share. Cannot reconstruct alone. Encrypted at rest, access-logged. Relay holds Share 2 from account creation.

#### Health Monitor

**v1.0**

💓 Device liveness, relay uptime, ATProto spec compat. Includes canary account for silent federation failure detection.

#### GeoDNS Multi-Region

**LATER**

🌎 2–3 relay nodes, route to nearest healthy. Simple failover with brief firehose gap. Cross-region replication interface designed but not built.

#### Repo Snapshot

**LATER**

🗄️ Full repo backup on relay. Incremental from commit buffer. Pro+ feature. Enables one-click device migration.

#### CDN / Public Cache

**LATER**

🌐 Serves public repo content during offline windows.

### BYO Relay (User-Hosted, Free)

#### Relay Binary

**v1.0**

📦 Open-source. Nix flake (source of truth) → Docker image + NixOS module. Tunnel + commit forwarding + requestCrawl. No firehose proxy, no snapshots.

#### Device-Relay Protocol Spec

**v1.0**

📜 Documented contract: handshake/auth, commit push, health ping, optional feature negotiation. Includes commit ack for future trust verification.

#### Feature Negotiation

**v1.0**

🔌 App queries relay capabilities on connect. Gracefully degrades when extended features unavailable. Suggests upgrade for missing features.

*REMOVED: Inbound Message Queue — Not needed. ATProto records live in author's repo.*

---

## Data Flow

### Desktop-Enrolled Write Path

1. App creates record via XRPC (Tauri webview → Rust backend)
2. Repo Engine constructs MST diff + unsigned commit
3. Unsigned commit sent to relay via Iroh tunnel
4. Relay signs commit with P-256 signing key
5. Relay stores signed commit in buffer
6. Relay emits to firehose / serves via XRPC

### Mobile-Only Write Path (v0.1)

1. Third-party app (e.g. Bluesky) calls relay XRPC directly
2. Relay constructs record, MST diff, signs commit
3. Relay stores and emits to firehose

### Desktop-Offline Read Path

1. XRPC read request hits relay
2. Relay serves from commit buffer / repo cache
3. Writes return 503 (relay cannot construct commits from stale state)

---

## Data Flow — How Bob's Post Reaches the Network

*Current scenario showing firehose proxy operation during v0.2+:*

**Bob's Mac** (Repo Engine constructs unsigned commit) → **Iroh tunnel** → **Relay** (Signs commit with P-256 key) → **Commit Buffer** (Persists signed commit) → **Firehose Proxy** (Stable WebSocket) → **subscribeRepos** → **BGS** (Network firehose) → **indexes** → **AppView** (Bluesky etc.)

*If Bob's Mac is asleep → relay serves reads from cache, returns 503 on writes. Commit buffer feeds firehose proxy from stored commits on wake.*

---

## Recovery Flow — Device Migration / Dead SSD (v1.0+)

**New Mac** (Installs Tauri app) → **authenticates** → **2-of-3 Shares** (iCloud + relay escrow) → **reconstructs** → **Rotation Key** (Shamir recombination) → **did:plc op** → **Key Rotation** (New signing key) → **syncs** → **Repo Snapshot** (Full repo restore)

**Share sources (any 2 of 3):**
- ① iCloud Keychain
- ② Relay escrow
- ③ Exported recovery file
- Future: ④ Trusted contact (social recovery) — interface designed, not yet shipped

---

## Layer 03 — Infrastructure (ATProto Network)

### Federation

**v0.1**

🌍 PDS participates in ATProto network via relay. DID document points to relay URL as canonical PDS endpoint.

### DNS / Domain Automation

**v1.0**

🔤 Handle-as-domain resolution. Automated DNS config for custom domain handles.

### DID Resolution

**v0.1**

🪪 did:plc or did:web pointing to relay endpoint. Relay always reachable, DID resolution never fails due to offline device.

---

## Layer 04 — Ops (Security, Conformance & Updates)

### Update & Supply Chain Security

#### 2-of-3 Threshold Signing

**v1.0**

🔑 CI key + offline engineer key + cold storage. Compromised CI alone cannot ship malicious updates.

#### Transparency Log

**LATER**

📋 Sigstore-backed. Every release publicly logged.

#### Apple Notarization

**v1.0**

🍎 First verification layer via Tauri build pipeline.

#### Responsible Disclosure

**v1.0**

📬 security@ + published PGP key from day one.

#### cargo-audit in CI

**v0.1**

📦 Dependency vulnerability scanning on every build. Pin exact versions in Cargo.lock. Review diffs on dep updates. Verify atrium codegen input against upstream lexicons.

### Conformance Testing

#### L1: Interop Test Vectors

**v0.1**

🧪 Every commit. Official atproto-interop-tests + interop-test-files. Byte-level checks for MST, CAR, CBOR, CID, commit proofs. Strict MST validation.

#### L2: Oracle Compat Suite

**v1.0**

🔬 Nightly CI. Docker Compose: reference TypeScript PDS vs your Rust PDS. Compare CAR output, firehose events, MST roots.

#### L3: Production Canary

**v1.0**

🐤 Live account on real Bluesky via your relay. Health monitor verifies posts appear in AppView. Catches silent federation failures.

### Runtime Threat Mitigations

#### XRPC Input Hardening

**v1.0**

🔒 Request size limits per endpoint. Rate limiting at relay layer. cargo-fuzz targets for CBOR/CAR/MST parsing. Adversarial MST key testing per spec DoS guidance.

#### Tauri IPC Lockdown

**v0.1**

🏗️ Minimal allowlist: create/list/get records + status. Webview cannot access filesystem, shell, HTTP, or crypto. All sensitive ops in Rust backend only.

#### Relay Trust Verification

**LATER**

🤝 Device verifies commits appear in firehose. Protocol designed now (commit ack with seq number), verification logic built later. Protects against censorship by relay.

---

## Relay Tier Pricing — v1.0 Launch

### Free

**$0/mo**

- Iroh tunnel (NAT traversal)
- Basic XRPC proxy
- 7-day commit buffer
- Key share escrow (1 share)
- Apple notarized updates
- No firehose proxy — BGS drops on sleep
- See "BYO Relay" section for self-hosted option

### Pro

**$X/mo**

- Everything in Free
- Stable firehose proxy (always-on WebSocket)
- 30-day commit buffer
- CDN cache for public content
- requestCrawl auto-trigger
- Custom domain handle
- Multi-region GeoDNS (post-launch)
- Full repo snapshot (post-launch)
- One-click device migration

### Business

**$XX/mo**

- Everything in Pro
- 90-day commit buffer
- Continuous repo snapshot (post-launch)
- Admin dashboard
- Priority support
- Custom relay config
- Audit logs

### BYO Relay (Self-Hosted)

Not a subscription tier — an alternative deployment model. Operators run their own relay binary (distributed via Nix flake or Docker image).

**Includes:**
- Full relay functionality (identical binary to managed relay)
- SQLite or PostgreSQL backend (operator's choice)
- Local or S3-compatible blob storage
- No subscription fees — operator provides their own infrastructure
- No managed monitoring or support

Available at v1.0 launch.

---

## All Questions Resolved

### ✅ Availability — v0.1+

Firehose emitter for native federation. Firehose proxy + commit buffer for v0.2+. In mobile-only phase, relay is the PDS. In desktop-enrolled, relay maintains persistent connection for sleeping device.

### ✅ Durability — v1.0+

2-of-3 Shamir key recovery. Tiered repo snapshots. iCloud + file export + relay escrow.

### ✅ Spec Drift — v0.1+

Repo Engine (atrium + rsky-crypto). 3-layer conformance: interop vectors → oracle → canary.

### ✅ Relay Redundancy — v1.0+

GeoDNS multi-region + BYO relay (Nix/Docker, free). Device-relay protocol spec. Feature negotiation.

### ✅ Runtime Threats — v1.0+

XRPC fuzzing + size limits. Tauri IPC lockdown. Commit ack protocol (designed). cargo-audit. Relay trust verification (designed, deferred).

### ✅ Mobile-First Architecture — v8

Relay is full PDS in v0.1. Desktop enrolls in v0.2 as repo construction engine. Four-phase milestones reconcile mobile and desktop workflows.

---

## Milestone Summary — Four Phases

### v0.1 — Mobile-Only PDS (~3–4 months)

**Goal:** User creates ATProto identity from iPhone, logs into Bluesky.
Relay is a full PDS. No desktop involved.

**Relay:** Axum + SQLite + repo engine + signing + XRPC + firehose emitter
**OAuth:** atproto-oauth-axum integration (blocks Bluesky login)
**Blobs:** upload/serve with local storage
**Identity:** DID creation + Shamir split at onboarding
**Federation:** 25 XRPC endpoints (see unified-milestone-map.md §2.1)
**Testing:** L1 interop tests + cargo-audit

### v0.2 — Desktop Enrollment (~2–3 months)

**Goal:** User pairs desktop Mac, relay becomes proxy+signer.

**Device pairing:** via QR code + desktop promotion
**XRPC write proxying:** relay → desktop → relay signs
**Firehose proxy:** for sleeping desktop
**Blob forwarding:** via Iroh
**Desktop offline:** → 503 on writes, reads from cache

### v1.0 — Production Launch (~3–4 months)

**Goal:** Production-ready product with recovery and self-hosting.

**Shamir recovery ceremony:** + full share management UI
**Tier pricing:** Free/Pro/Business
**BYO relay binary:** Nix/Docker
**S3 blob backend:** + CDN
**PostgreSQL option:** for scale
**L2 oracle suite + L3 canary**
**XRPC hardening:** + rate limiting

### v2.0+ — Signing Sovereignty (TBD)

**Goal:** User's hardware signs commits directly.
**Contingent on:** ATProto protocol evolution (multi-key support).
