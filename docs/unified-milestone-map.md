# Unified Milestone Map

Single source of truth for all ezpds phases.

> **v0.1 — Mobile-Only PDS: COMPLETE (2026-07-13).** Validated end-to-end on the live
> network: identity created from a phone, hosted on Custos production (v0.4.7), full
> official-Bluesky-app service (OAuth/DPoP login, posts, images, **video**, email
> verification), and the live bsky.social migration round trip with the Secure-Enclave
> key at `rotationKeys[0]` throughout. Records: the closed
> [daily-driver readiness audit](archive/2026-07-08-daily-driver-readiness-audit.md) and the
> [MM-241 execution record](validation/2026-07-07-mm-241-live-migration.md). Live issue
> state: Linear (milestone "v0.1 — Mobile-Only PDS", marked complete).

v0.1 Draft — March 2026

Companion to: All spec documents

---

## 1. Phase Model

The architecture defined two milestones (v0.1, v1.0). The mobile spec defined four (v0.1, v0.2, v1.0, v2.0+). The mobile spec is canonical. This document reconciles both into a single timeline.

### 1.1 Why Four Phases

The architecture was written before the mobile-first strategy existed. Its two milestones assumed a desktop-only product. The mobile spec introduced a PDS-as-full-PDS phase that precedes any desktop involvement. The four-phase model reflects the actual build order:

1. **v0.1** — PDS is a full PDS. User creates identity from phone, logs into Bluesky.
2. **v0.2** — Desktop enrolls. PDS becomes a proxy+signer. Device management from phone.
3. **v1.0** — Recovery, polish, production readiness. BYO PDS support.
4. **v2.0+** — Signing sovereignty. Contingent on ATProto protocol evolution.

### 1.2 Timeline Estimates

| Phase | Duration | Cumulative |
|-------|----------|------------|
| v0.1 | 3–4 months | 3–4 months |
| v0.2 | 2–3 months | 5–7 months |
| v1.0 | 3–4 months | 8–11 months |
| v2.0+ | TBD | TBD |

Solo developer estimates from architecture spec. v0.2 is new — estimated at 2–3 months based on scope (device pairing, desktop promotion, XRPC proxying).

---

## 2. Phase Details

### 2.1 v0.1 — Mobile-Only PDS

**Goal:** User creates an ATProto identity from their iPhone and logs into Bluesky.

**Lifecycle phase:** Mobile-Only. PDS is a full PDS — hosts repo, serves XRPC, signs commits, emits firehose.

#### PDS

| Component | Description | Source |
|-----------|-------------|--------|
| Axum HTTP server | Serves all endpoints | architecture |
| SQLite database | Accounts, repos, tokens, OAuth state | architecture |
| Repo engine | CAR file storage, Merkle tree, commit signing | architecture |
| Signing key management | P-256 key generation, Secure Enclave on phone stores root rotation key | mobile §3 |
| XRPC endpoints | `com.atproto.*` read + write | architecture |
| Firehose emitter | Native event stream (not proxy — PDS IS the PDS) | cross-spec §2.6 |
| Iroh tunnel | NAT traversal for phone ↔ PDS | mobile §5 |

#### OAuth (blocks Bluesky login)

| Component | Description | Source |
|-----------|-------------|--------|
| `atproto-oauth-axum` integration | OAuth 2.1 with DPoP, PAR, PKCE | oauth spec §2.1 |
| Server metadata endpoint | `/.well-known/oauth-authorization-server` | oauth spec §5 |
| Authorization UI | Minimal server-rendered consent screen | oauth spec §6 |
| Token storage | SQLite-backed access + refresh tokens | oauth spec §3.2 |

#### Blobs

| Component | Description | Source |
|-----------|-------------|--------|
| `uploadBlob` endpoint | CID-addressed upload | blob spec §4 |
| `getBlob` endpoint | Serve by CID | blob spec §5 |
| Local filesystem storage | Default for v0.1 (S3 optional via config) | blob spec §3 |
| Garbage collection | 6-hour grace for unreferenced temp blobs | blob spec §6 |
| Storage quotas | Per-account enforcement | blob spec §7 |

#### Provisioning API

| Endpoint | Description | Source |
|----------|-------------|--------|
| POST /v1/accounts/mobile | Combined account creation + device binding | cross-spec §2.1 |
| POST /v1/dids | DID creation (PDS constructs did:plc doc from key material) | cross-spec §1.2 |
| POST /v1/sessions | Session creation (login) | provisioning §2 |
| POST /v1/pds/keys | Generate PDS signing key | mobile §9 |

#### Identity & Keys

| Component | Description | Source |
|-----------|-------------|--------|
| DID creation | did:plc via PLC directory (PDS proxies) | provisioning, cross-spec §1.2 |
| Key types | P-256 for rotation key, P-256/secp256k1 for signing | cross-spec §1.1 |
| Shamir share generation | 2-of-3 split during onboarding. Share 1 = iCloud Keychain, Share 2 = PDS escrow, Share 3 = user's choice | cross-spec §2.5 |

#### Migration

| Component | Description | Source |
|-----------|-------------|--------|
| Planned device swap | LAN transfer via Iroh, 6-digit code | migration §3 |

#### XRPC Federation Surface (minimum viable endpoint set)

The following XRPC endpoints are the minimum required for the PDS to join the ATProto network as a federating PDS. Derived from @threddyrex.org's C# PDS implementation (the first non-reference PDS to successfully federate) and cross-referenced with the ATProto spec.

**com.atproto.repo — Repo CRUD + blobs (8 endpoints)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `com.atproto.repo.createRecord` | POST | Create a record in a repo collection |
| `com.atproto.repo.putRecord` | POST | Write a record (create or update) |
| `com.atproto.repo.deleteRecord` | POST | Delete a record |
| `com.atproto.repo.applyWrites` | POST | Batch write (create/update/delete) |
| `com.atproto.repo.getRecord` | GET | Fetch a single record by key |
| `com.atproto.repo.listRecords` | GET | List records in a collection |
| `com.atproto.repo.describeRepo` | GET | Repo metadata (DID, handle, collections) |
| `com.atproto.repo.uploadBlob` | POST | Upload a blob, returns CID ref |

**com.atproto.server — Auth + account lifecycle (6 endpoints)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `com.atproto.server.createSession` | POST | Login (returns access + refresh tokens) |
| `com.atproto.server.getSession` | GET | Validate current session |
| `com.atproto.server.refreshSession` | POST | Rotate session tokens |
| `com.atproto.server.describeServer` | GET | Server capabilities + invite policy |
| `com.atproto.server.activateAccount` | POST | Activate a deactivated account |
| `com.atproto.server.deactivateAccount` | POST | Deactivate account (preserves data) |

**com.atproto.sync — Federation surface (7 endpoints)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `com.atproto.sync.getRepo` | GET | Full repo export (CAR file) |
| `com.atproto.sync.getRecord` | GET | Single record as CAR-encoded block |
| `com.atproto.sync.getBlob` | GET | Fetch blob by CID |
| `com.atproto.sync.listBlobs` | GET | List blob CIDs for a repo |
| `com.atproto.sync.listRepos` | GET | List all repos hosted by this PDS |
| `com.atproto.sync.getRepoStatus` | GET | Repo sync status (active/deactivated) |
| `com.atproto.sync.subscribeRepos` | WS | Firehose — WebSocket event stream of repo commits |

**com.atproto.identity (1 endpoint)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `com.atproto.identity.resolveHandle` | GET | Resolve handle → DID |

**app.bsky.* — Appview proxy (not implemented locally)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `app.bsky.*` (catch-all) | * | Proxy to Bluesky appview (bsky.network) |
| `app.bsky.actor.getPreferences` | GET | Stored locally — survives appview outages |
| `app.bsky.actor.putPreferences` | POST | Stored locally |

**chat.bsky.convo (2 endpoints)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `chat.bsky.convo.getLog` | GET | Chat conversation log |
| `chat.bsky.convo.listConvos` | GET | List chat conversations |

**Infrastructure (1 endpoint)**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/_health` | GET | Liveness check |

**Total: 25 XRPC endpoints + health check.** This is the federation acceptance test — if these all work correctly, the PDS is a functioning PDS on the network.

Note: `app.bsky.*` calls are proxied to the appview, not implemented locally. The PDS only stores preferences locally. The `chat.bsky.convo` endpoints may also be proxied depending on whether ezpds hosts chat state or defers to a chat service.

#### Not in v0.1

- Desktop enrollment/pairing
- Desktop XRPC proxying
- Firehose proxy (desktop sleep)
- Key rotation
- Unplanned device recovery
- Tier pricing (all users on free tier)
- PostgreSQL backend
- CDN/S3 blob storage (optional, not required)
- BYO PDS distribution

---

### 2.2 v0.2 — Desktop Enrollment

**Goal:** User pairs a desktop machine and manages devices from their phone.

**Lifecycle phase:** Desktop-Enrolled. PDS becomes XRPC proxy + signer. Desktop hosts the repo.

#### New in v0.2

| Component | Description | Source |
|-----------|-------------|--------|
| Device pairing | QR code scan, desktop promotion | mobile §5 |
| POST /v1/devices/:id/pair | Pairing endpoint | mobile §9 |
| POST /v1/devices/:id/promote | Promote desktop to repo host | mobile §9 |
| GET /v1/devices/:id/status | Device health/status | mobile §9 |
| DELETE /v1/devices/:id | De-enroll device | mobile §9 |
| XRPC write proxying | PDS forwards createRecord etc. to desktop | mobile §4 |
| POST /v1/pds/commits/sign | Sign unsigned commit from desktop | mobile §9 |
| GET /v1/pds/repo/snapshot | Full repo snapshot (CAR) for desktop sync | mobile §9 |
| GET /v1/pds/mode | Current operating mode (mobile-only vs desktop-enrolled) | mobile §9 |
| Desktop offline handling | 503 on writes when desktop unreachable, reads from cache | mobile §4.3 |
| Firehose proxy | PDS maintains BGS WebSocket on behalf of sleeping desktop | architecture |
| Blob forwarding | Forward uploaded blobs to desktop via Iroh | blob spec §5.2 |
| Blob cache | PDS caches blobs, fetches from desktop on miss | blob spec §5.2 |

#### Unchanged from v0.1

- OAuth (no changes needed — PDS remains the auth endpoint)
- Provisioning API core endpoints
- Firehose native emission (still works alongside proxy)

---

### 2.3 v1.0 — Production Launch

**Goal:** Production-ready identity wallet. Recovery support. BYO PDS.

**Lifecycle phase:** All phases stable and polished.

#### New in v1.0

| Component | Description | Source |
|-----------|-------------|--------|
| Unplanned device recovery | Shamir reconstruction ceremony | migration §4 |
| POST /v1/recovery/initiate | Begin recovery | migration §9 |
| POST /v1/recovery/verify-key | Prove DID key reconstruction | migration §9 |
| GET /v1/recovery/restore | Stream repo + blobs from PDS | migration §9 |
| PUT /v1/keys/shares/:id | Update PDS-held Shamir share | migration §9 |
| GET /v1/keys/rotation-log | Audit log of Shamir rotations | migration §9 |
| Key rotation | Shamir-based rotation via PDS | architecture |
| DELETE /v1/pds/keys/:keyId | Revoke PDS signing key | mobile §9 |
| Tier pricing | Free/Pro/Business subscription tiers | architecture, cross-spec §1.4 |
| BYO PDS binary | Nix/Docker distribution for self-hosted operators | architecture |
| PostgreSQL option | Alternative to SQLite for larger deployments | oauth spec §8, architecture |
| S3 blob backend | Default for managed PDS (R2 recommended) | blob spec §9 |
| CDN integration | R2 + Workers for Pro/Business blob serving | blob spec §9 |
| Local → S3 migration tool | For operators upgrading storage | blob spec §9 |
| OAuth rate limiting | Per-endpoint limits | oauth spec §8 |
| OAuth audit logging | Authorization grant logging | oauth spec §8 |
| Customizable auth UI | Branding for BYO PDS operators | oauth spec §6 |
| Token revocation endpoint | Active session management | oauth spec §8 |
| Client metadata caching | TTL-based re-validation (24h) | oauth spec §7.2 |
| Blob manifest in transfer | Include blobs in device transfer bundle | blob spec §9 |
| PLC directory mirror | Read-only cache for DID resolution | provisioning |
| Dereferenced blob cleanup | Remove blobs no longer referenced by any record | blob spec §9 |
| MinIO docs | BYO PDS blob storage documentation | blob spec §9 |

---

### 2.4 v2.0+ — Signing Sovereignty

**Goal:** User's own hardware signs commits. Desktop holds the signing key.

**Contingency:** Requires ATProto protocol changes (multi-key support or key delegation).

| Component | Description | Source |
|-----------|-------------|--------|
| Pluggable signer: desktop-remote | Desktop signs commits directly, PDS no longer signs | mobile §10 |
| Multi-device sync | Share key across devices without full migration | migration §8 |
| Scoped OAuth tokens | Read-only grants for specific collections | oauth spec §8 |
| Token introspection endpoint | RFC 7662 | oauth spec §8 |
| OAuth admin dashboard | Manage active sessions | oauth spec §8 |
| Video transcoding | Multiple resolutions for video blobs | blob spec §9 |
| Blob deduplication | Cross-account content-addressed dedup | blob spec §9 |
| PLC read-write authority | Participate as PLC directory peer | provisioning |

---

## 3. Cross-Document Phase Mapping

How each document's milestones map to the unified phases:

| Unified Phase | Architecture | Mobile | Provisioning | Migration | OAuth | Blobs |
|---------------|-------------|--------|-------------|-----------|-------|-------|
| **v0.1** | v0.1 (technical preview) | iOS v0.1 (identity wallet) | Core endpoints | v0.1 (planned swap) | v0.1 (basic OAuth) | v0.1 (basic blobs) |
| **v0.2** | — (not represented) | iOS v0.2 (device mgmt) | Device endpoints | — | — (no changes) | Desktop blob sync |
| **v1.0** | v1.0 (public launch) | iOS v1.0 (recovery) | Full API + milestones | v1.0 (full recovery) | v1.0 (production) | v1.0 (production) |
| **v2.0+** | — | v2.0+ (signing sovereignty) | PLC authority | Multi-device sync | Later | Later |

### 3.1 Architecture Gap

The architecture document has no v0.2 milestone. It needs a "Phase 1: Desktop Enrollment" between its technical preview and public launch. The architecture's v0.1 scope includes some items that belong in v0.2 (device pairing, desktop promotion).

### 3.2 Provisioning API Gap

The provisioning API has no milestone tags at all. Every endpoint group needs a phase assignment. The 17 endpoints from the mobile and migration specs need to be integrated and tagged.

---

## 4. Dependency Graph

Critical path items that block subsequent phases:

```
v0.1 Critical Path:
  Axum server → SQLite schema → Repo engine → XRPC endpoints
                                            → OAuth (blocks Bluesky login)
                                            → Blob upload/serve
                → DID creation → Account creation → Shamir split
                → Iroh tunnel (blocks device transfer)

v0.2 Critical Path:
  v0.1 complete → Device pairing protocol → Desktop promotion
                → XRPC proxy layer → Commit signing endpoint
                → Firehose proxy
                → Blob forwarding via Iroh

v1.0 Critical Path:
  v0.2 complete → Recovery ceremony → Shamir reconstruction
                → Tier pricing → BYO PDS packaging
                → S3 migration → CDN setup
                → PostgreSQL option
```

---

## 5. Feature ↔ Phase Matrix

Quick reference: which phase delivers which user-visible capability.

| User Capability | Phase |
|----------------|-------|
| Create ATProto identity from iPhone | v0.1 |
| Log into Bluesky | v0.1 |
| Post, like, follow via third-party apps | v0.1 |
| Transfer identity to new phone (planned) | v0.1 |
| Pair a desktop Mac | v0.2 |
| Desktop runs full PDS, PDS proxies | v0.2 |
| Manage devices from phone | v0.2 |
| Desktop sleeps, PDS keeps firehose alive | v0.2 |
| Recover from lost device | v1.0 |
| Self-host your own PDS | v1.0 |
| Choose subscription tier | v1.0 |
| CDN-accelerated media serving | v1.0 |
| Desktop signs its own commits | v2.0+ |

---

## 6. Action Items

This document resolves cross-spec-analysis items:

- **#7** (architecture: move basic Shamir to v0.1) — Resolved: Shamir split is in v0.1 (§2.1)
- **#8** (architecture: add unified milestone map) — This document
- **#14** (provisioning: add milestone tags) — Phase assignments listed in §2.1–2.4
- **#23** (new document: unified milestone map) — This document

### Remaining updates needed in individual documents

The architecture (items 1–6), provisioning API (items 9–13, 15), migration spec (items 16–18), and mobile spec (items 19–20) still need their own text updated to reference these unified phases. Those are separate action items tracked in [archive/cross-spec-analysis.md](archive/cross-spec-analysis.md).
