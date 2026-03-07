# Cross-Spec Gap & Inconsistency Analysis

**Documents analyzed:**
- PDS Architecture v7 (HTML) — "architecture"
- Provisioning API Spec v0.2 (docx) — "provisioning"
- Data Migration & Recovery Spec v0.1 (docx) — "migration"
- Mobile Architecture Spec v1.2 (docx) — "mobile"

**Canonical source:** The mobile architecture spec (v1.2) represents the most recent thinking and takes precedence where documents conflict.

---

## Decisions Made

The following contradictions were identified and resolved during review:

| # | Issue | Decision | Affects |
|---|-------|----------|---------|
| 1.3 | **Signing key custody** — architecture says device signs; mobile says relay always signs | **Relay always signs.** Desktop constructs Merkle tree, relay signs commits. Desktop-local signing is a future option (mobile spec §10). | architecture (data flow, PDS shell desc, v0.1 scope) |
| 1.1 | **Key types** — provisioning API uses Ed25519; mobile uses P-256; ATProto requires P-256/secp256k1 | **Fix to P-256/secp256k1.** All Ed25519 references in provisioning API are wrong. | provisioning (POST /v1/devices, POST /v1/dids/:did/rotate) |
| 1.2 | **DID ceremony** — provisioning says client builds full DID doc; mobile says client sends keys, relay assembles | **Relay constructs it.** Client sends key material, relay orchestrates did:plc creation. | provisioning (POST /v1/dids request body) |
| 1.4 | **Tier naming** — architecture has Free/Pro/Business; provisioning has Free/Pro/Self-Hosted | **Three tiers + BYO.** Free/Pro/Business are subscription tiers. Self-Hosted (BYO relay) is an orthogonal deployment model, not a tier. | architecture, provisioning |
| 2.5 | **Shamir shares** — migration has device/relay/iCloud; mobile has iCloud/relay/BIP-39 phrase | **User chooses Share 3.** Share 1 = iCloud Keychain, Share 2 = relay escrow, Share 3 = user's choice of device-local OR BIP-39 paper/USB. | migration, mobile |
| 2.1 | **Mobile account creation** — provisioning API only supports web-first flow | **Add dedicated mobile endpoint.** New POST /v1/accounts/mobile combines account creation + device binding. Web flow unchanged. | provisioning |
| 2.4 | **No OAuth spec** | **Spec it now.** ATProto OAuth (DPoP, PAR, client metadata) needs its own document. Blocks third-party app integration. | new document |
| 2.8 | **Desktop offline writes** — architecture implies offline compose+sync; mobile says 503 | **Resolved by signing decision.** Relay signs all commits, so writes return 503 when desktop is offline (relay can't construct commits from stale state). Architecture needs updating. | architecture |

---

## Remaining Gaps (Not Yet Resolved)

### 2.2 + 2.3: API endpoint fragmentation

15+ endpoints defined in the mobile and migration specs are not in the provisioning API:

**From mobile spec (9 endpoints):**
- POST /v1/relay/keys — generate relay signing key
- DELETE /v1/relay/keys/:keyId — revoke relay signing key
- GET /v1/relay/repo/snapshot — full repo snapshot (CAR)
- POST /v1/devices/:id/pair — device pairing
- POST /v1/devices/:id/promote — desktop promotion to repo host
- DELETE /v1/devices/:id — de-enroll device
- GET /v1/devices/:id/status — device health/status
- POST /v1/relay/commits/sign — sign unsigned commit
- GET /v1/relay/mode — current operating mode

**From migration spec (8 endpoints):**
- POST /v1/transfer/initiate — generate transfer session + code
- POST /v1/transfer/accept — new device submits transfer code
- POST /v1/transfer/complete — finalize transfer + lease handover
- POST /v1/recovery/initiate — begin recovery ceremony
- POST /v1/recovery/verify-key — prove DID key reconstruction
- GET /v1/recovery/restore — stream repo + blobs from relay
- PUT /v1/keys/shares/:id — update relay-held Shamir share
- GET /v1/keys/rotation-log — audit log of Shamir rotations

**Action needed:** Consolidate into provisioning API v0.3 or create a unified Relay API Reference.

### 2.6: Firehose in mobile-only phase

Architecture tags Firehose Proxy as v1.0 and says "BGS drops on sleep" for free tier in v0.1. But in the mobile-only phase (mobile spec), the relay IS a full PDS and must emit firehose events from day one — there's no "sleep" because the relay is always on.

The architecture's firehose proxy concept (relay maintains a persistent BGS WebSocket on behalf of a desktop that sleeps) is a *desktop-enrolled* feature. In mobile-only mode, the relay just emits firehose natively like any hosted PDS.

**Action needed:** Architecture needs to distinguish between "relay as native PDS firehose emitter" (mobile-only, always available) and "relay as firehose proxy for sleeping desktop" (desktop-enrolled, v1.0 paid feature).

### 2.7: No blob handling spec

No document specifies how blobs (images, media) are uploaded, stored, or served through the relay. The migration spec discusses blob loss on free tier, but the upload/storage/proxy path is unspecified.

**Action needed:** Add blob handling to the provisioning API or create a separate spec. Covers: upload endpoint, storage limits per tier, proxy behavior in desktop-enrolled mode, CDN caching.

### 3.1: Migration spec doesn't reference mobile recovery

The migration spec covers desktop-to-desktop migration but not phone-to-phone migration (lost iPhone). The mobile spec covers phone recovery in §7.2. These share Shamir infrastructure and should cross-reference.

**Action needed:** Add cross-references between migration spec §4 and mobile spec §7.

### 3.2: Architecture doesn't mention mobile at all

The architecture is entirely desktop-centric. The mobile-only lifecycle phase (relay as full hosted PDS) isn't represented.

**Action needed:** Add a "Phase 0: Mobile-Only" to the architecture showing the relay as a complete PDS before any desktop is enrolled.

### 3.3: No relay internals spec

All four docs describe the relay from the outside. None covers database schema, process architecture, deployment model, or scaling strategy.

**Action needed:** Not blocking for now, but will be needed before implementation.

---

## Milestone Alignment Issues

### 4.1: Shamir timing

Migration spec puts basic Shamir in v0.1. Architecture puts Recovery Share Manager in v1.0. Since mobile onboarding (§3.1 Step 7) generates Shamir shares during account creation, basic Shamir support is required from the mobile v0.1 launch.

**Action needed:** Architecture should move basic Shamir to v0.1 (or acknowledge it's a relay-side feature available from mobile launch).

### 4.2: Provisioning API has no milestone tags

No endpoints are marked v0.1 vs v1.0.

**Action needed:** Tag each endpoint group with a milestone.

### 4.3: Mobile has 4 phases, architecture has 2

Mobile: v0.1 (identity wallet) → v0.2 (device mgmt) → v1.0 (recovery) → v2.0+ (signing sovereignty).
Architecture: v0.1 (technical preview) → v1.0 (public launch).

Mobile v0.1 has no architecture milestone — it's relay-only.

**Action needed:** Create a unified milestone map across all four documents.

---

## Action List by Document

### Architecture (v8 needed)
1. Update signing model: device constructs, relay signs
2. Update data flow diagram: show unsigned commit → relay → signed commit
3. Update PDS shell description: "repo construction engine" not "owns XRPC surface"
4. Add "Phase 0: Mobile-Only" lifecycle phase
5. Fix tier model: Free/Pro/Business + BYO relay as deployment option
6. Distinguish native firehose (mobile-only) from firehose proxy (desktop-enrolled)
7. Move basic Shamir to v0.1 scope
8. Add unified milestone map

### Provisioning API (v0.3 needed)
9. Replace all Ed25519 references with P-256/secp256k1
10. Rewrite POST /v1/dids: accept key material, not full DID document
11. Add POST /v1/accounts/mobile endpoint
12. Integrate 17 endpoints from mobile + migration specs
13. Fix tier model: Free/Pro/Business + Self-Hosted as deployment option
14. Add milestone tags to all endpoints
15. Add blob upload/storage endpoints

### Migration Spec (v0.2 needed)
16. Update Shamir share model: Share 1=iCloud, Share 2=relay, Share 3=user's choice
17. Cross-reference mobile spec §7 for phone recovery
18. Align milestone timing with architecture

### Mobile Spec (minor updates)
19. Update Shamir share model: Share 3 = user's choice (device-local or BIP-39)
20. Cross-reference migration spec for desktop-to-desktop flows

### New Documents Needed
21. **ATProto OAuth Spec** — DPoP, PAR, client metadata discovery, token lifecycle
22. **Blob Handling Spec** — upload, storage, proxy, CDN, tier limits
23. **Unified Milestone Map** — single source of truth for all phases across all docs
