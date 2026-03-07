# Architecture v8 Amendments

Changes required to update the PDS Architecture from v7 to v8. Each section maps to an action item from cross-spec-analysis.md.

---

## Changelog Entry (replace v7 changelog)

```
v8 Changes — Mobile-First Reconciliation

Architecture reconciled with mobile architecture spec v1.2 (canonical).
The relay is no longer just a tunnel+proxy — in the mobile-only phase,
it IS the PDS.

NEW   Four-phase milestone model (v0.1 / v0.2 / v1.0 / v2.0+)
NEW   Phase 0: Mobile-Only lifecycle (relay as full PDS)
FIX   Signing model: relay always signs, device constructs unsigned commits
FIX   Tier model: Free/Pro/Business + BYO as deployment model
FIX   Firehose: native emission (mobile-only) vs proxy (desktop-enrolled)
FIX   Shamir: basic share generation moves to v0.1 (required at onboarding)
FIX   DID keystore: Shamir split required at account creation, not v1.0
REF   See unified-milestone-map.md for phase details
```

---

## Item 1: Update Signing Model

**Current (v7):** The architecture implies the device signs commits. The Iroh Endpoint description says "Pushes signed repo commits to relay when online." The Custom PDS Shell description says "Owns XRPC surface and sync protocol."

**Change:** The relay always holds the signing key and signs all commits. The desktop constructs the Merkle tree and unsigned commits, sends them to the relay via Iroh, and the relay signs.

### Iroh Endpoint — new description

```
QUIC-based tunnel to relay. NAT traversal, connection resumption on wake.
Pushes unsigned repo commits to relay for signing when online.
```

### Custom PDS Shell — new description

```
Purpose-built embedded repo engine. SQLite-backed, local-first. Constructs
Merkle tree, builds unsigned commits, manages local repo state. Does NOT
hold signing keys — relay signs all commits. The core technical risk —
repo construction must produce valid MST structures that the relay can sign
and federate.
```

---

## Item 2: Update Data Flow

**Current (v7):** No explicit data flow diagram, but the component descriptions imply: device creates → device signs → pushes to relay → relay proxies.

**Change:** Add a data flow section or update descriptions to show:

```
Desktop-Enrolled Write Path:
  1. App creates record via XRPC (Tauri webview → Rust backend)
  2. PDS shell constructs MST diff + unsigned commit
  3. Unsigned commit sent to relay via Iroh tunnel
  4. Relay signs commit with P-256 signing key
  5. Relay stores signed commit in buffer
  6. Relay emits to firehose / serves via XRPC

Mobile-Only Write Path (v0.1):
  1. Third-party app (e.g. Bluesky) calls relay XRPC directly
  2. Relay constructs record, MST diff, signs commit
  3. Relay stores and emits to firehose

Desktop-Offline Read Path:
  1. XRPC read request hits relay
  2. Relay serves from commit buffer / repo cache
  3. Writes return 503 (relay cannot construct commits from stale state)
```

---

## Item 3: Update PDS Shell Description

**Current (v7):** "Owns XRPC surface and sync protocol."

**Change:** The PDS shell is a repo construction engine, not the XRPC authority. In mobile-only mode, the relay owns the XRPC surface. In desktop-enrolled mode, the relay proxies writes to the desktop's PDS shell, which constructs the commit, then the relay signs it.

### Custom PDS Shell — new name suggestion: "Repo Engine"

```
Purpose-built repo construction engine. SQLite-backed, local-first.
Builds MST structures, constructs unsigned commits, manages collection
storage. In desktop-enrolled mode, the relay proxies XRPC writes here,
then signs the resulting commits. Does not serve XRPC directly to the
network — the relay is always the network-facing endpoint.
```

---

## Item 4: Add Phase 0 — Mobile-Only Lifecycle

**Current (v7):** The architecture is entirely desktop-centric. Layer 01 is "Device Layer — User's Mac." There's no representation of the mobile-only phase where no desktop exists.

**Change:** Add a new lifecycle section before the layer diagram, or add a prominent callout:

### New Section: "Device Lifecycle Phases"

Place before Layer 01. This section frames the entire architecture:

```
Device Lifecycle Phases

The product launches mobile-first. The relay is a full PDS before any
desktop is involved.

Phase: Mobile-Only (v0.1)
  Relay behavior: Full PDS — hosts repo, serves XRPC, signs commits,
                  emits firehose
  Repo location:  Relay (primary and only copy)
  Phone role:     Identity wallet (key management, device admin)
  Desktop:        Does not exist yet

Phase: Desktop-Enrolled (v0.2)
  Relay behavior: XRPC proxy + signer — forwards writes to desktop,
                  signs commits, serves reads from cache
  Repo location:  Desktop (primary), relay (cache)
  Phone role:     Identity wallet + device manager
  Desktop:        Runs repo engine, constructs unsigned commits

Phase: Desktop-Offline (v0.2+)
  Relay behavior: Serves reads from cache, 503 on writes
  Repo location:  Desktop (authoritative but unreachable)
  Phone role:     Same as desktop-enrolled
  Desktop:        Sleeping / powered off
```

### Impact on Layer 01

The current "Device Layer — User's Mac" heading should change to acknowledge that in v0.1, there is no Mac. Options:

- Rename to "Device Layer — Desktop (v0.2+)" and note that v0.1 has no device layer
- Or add a "Mobile-Only" badge to relay components that serve as the PDS in v0.1

### Impact on Layer 02

The relay layer needs a dual identity:

```
In mobile-only phase: Relay IS the PDS (not just a proxy)
In desktop-enrolled phase: Relay is proxy + signer (current description)
```

The Iroh Relay Node description should add:

```
In mobile-only mode, serves as full PDS — no tunnel needed, relay handles
all XRPC directly. In desktop-enrolled mode, acts as tunnel endpoint for
device ↔ relay communication.
```

---

## Item 5: Fix Tier Model

**Current (v7):** The tier section is titled "Relay Tier Pricing — v1.0 Launch." The Free tier includes "BYO relay supported (Nix / Docker)."

**Change:** BYO relay is a deployment model, not a tier feature. Free/Pro/Business are subscription tiers for the managed relay. BYO is orthogonal — a BYO operator runs their own relay and doesn't subscribe to any tier.

### Tier Section — changes

1. Remove "BYO relay supported (Nix / Docker)" from Free tier bullet list.
2. Add a separate section after tiers:

```
BYO Relay (Self-Hosted)

Not a subscription tier — an alternative deployment model. Operators run
their own relay binary (distributed via Nix flake or Docker image).

Includes:
- Full relay functionality (identical binary to managed relay)
- SQLite or PostgreSQL backend (operator's choice)
- Local or S3-compatible blob storage
- No subscription fees — operator provides their own infrastructure
- No managed monitoring or support

Available at v1.0 launch.
```

3. In the Free tier, replace the BYO line with:
```
- See "BYO Relay" section for self-hosted option
```

---

## Item 6: Distinguish Firehose Native vs Proxy

**Current (v7):** The Firehose Proxy component is tagged v1.0 with description: "Persistent WebSocket to BGS on behalf of PDS. Streams commits continuously. BGS sees 100% uptime. Key paid feature."

This conflates two different things:

1. **Native firehose emission** — the relay emitting events from its own repo (mobile-only mode). This is required at v0.1 for federation. Every PDS must emit a firehose.
2. **Firehose proxy** — the relay maintaining a BGS WebSocket on behalf of a sleeping desktop. This is a v0.2+ feature for desktop-enrolled mode.

**Change:** Split into two components:

### Firehose Emitter (new, v0.1)

```
Badge: v0.1
Name: Firehose Emitter
Description: Native com.atproto.sync.subscribeRepos WebSocket endpoint.
Required for federation — every PDS must emit a firehose. In mobile-only
mode, the relay is the PDS and emits directly. In desktop-enrolled mode,
emits commits as they're signed.
```

### Firehose Proxy (keep, reclassify to v0.2)

```
Badge: v0.2
Name: Firehose Proxy
Description: Maintains persistent BGS WebSocket on behalf of sleeping
desktop. Replays commits from buffer when desktop reconnects. Ensures BGS
sees continuous uptime even when desktop is offline. Desktop-enrolled
feature — not applicable in mobile-only mode. Pro/Business tier on
managed relay.
```

---

## Item 7: Move Basic Shamir to v0.1

**Current (v7):** "Recovery Share Manager" is tagged v1.0. "DID Keystore" is tagged v0.1 with note "Basic key management for v0.1. Shamir split added in v1.0."

**Change:** Mobile onboarding (mobile spec §3.1 Step 7) generates Shamir shares during account creation. Basic Shamir support is required from day one. The full Recovery Share Manager UI can stay at v1.0, but the crypto primitives and share generation must be v0.1.

### DID Keystore — new description

```
Badge: v0.1
Name: DID Keystore
Description: Signing keys in macOS Keychain (desktop) / Secure Enclave
(phone). At account creation, root rotation key is split via 2-of-3
Shamir: Share 1 = iCloud Keychain, Share 2 = relay escrow, Share 3 =
user's choice (device-local or BIP-39 paper backup). Basic key
management for v0.1. Full recovery UI in v1.0.
```

### Recovery Share Manager — clarify scope

```
Badge: v1.0
Name: Recovery Share Manager
Description: Full UI for Shamir share management and recovery ceremony.
View share status, rotate shares, initiate recovery from device loss.
Note: basic share GENERATION happens at v0.1 (during account creation).
This component adds the management and recovery interface.
```

---

## Item 8: Unified Milestones

**Current (v7):** Two milestones — v0.1 (technical preview, 3–4 months) and v1.0 (public launch, 3–4 months after).

**Change:** Four phases. See unified-milestone-map.md for full details. The architecture's milestone summary section should be updated:

### Milestone Summary — replace current 2-column grid with 4 phases

```
v0.1 — Mobile-Only PDS (~3-4 months)
  Goal: User creates ATProto identity from iPhone, logs into Bluesky.
  Relay is a full PDS. No desktop involved.

  Relay: Axum + SQLite + repo engine + signing + XRPC + firehose emitter
  OAuth: atproto-oauth-axum integration (blocks Bluesky login)
  Blobs: upload/serve with local storage
  Identity: DID creation + Shamir split at onboarding
  Federation: 25 XRPC endpoints (see unified-milestone-map.md §2.1)
  Testing: L1 interop tests + cargo-audit

v0.2 — Desktop Enrollment (~2-3 months)
  Goal: User pairs desktop Mac, relay becomes proxy+signer.

  Device pairing via QR code + desktop promotion
  XRPC write proxying (relay → desktop → relay signs)
  Firehose proxy for sleeping desktop
  Blob forwarding via Iroh
  Desktop offline → 503 on writes, reads from cache

v1.0 — Production Launch (~3-4 months)
  Goal: Production-ready product with recovery and self-hosting.

  Shamir recovery ceremony + full share management UI
  Tier pricing (Free/Pro/Business)
  BYO relay binary (Nix/Docker)
  S3 blob backend + CDN
  PostgreSQL option
  L2 oracle suite + L3 canary
  XRPC hardening + rate limiting

v2.0+ — Signing Sovereignty (TBD)
  Goal: User's hardware signs commits directly.
  Contingent on ATProto protocol evolution (multi-key support).
```

### Milestone Legend — add v0.2

Add a v0.2 badge/swatch to the legend at the top:

```
v0.2  Desktop enrollment · device management
```

And reclassify components accordingly:
- Firehose Proxy: v1.0 → v0.2
- Provisioning API: v1.0 → split (core at v0.1, full at v1.0)
- Key Share Escrow: v1.0 → v0.1 (needed for Shamir at onboarding)

---

## Summary of Badge Reclassifications

| Component | v7 Badge | v8 Badge | Reason |
|-----------|----------|----------|--------|
| DID Keystore | v0.1 | v0.1 | Unchanged but description updated (Shamir at creation) |
| Key Share Escrow | v1.0 | v0.1 | Relay holds Share 2 from account creation |
| Recovery Share Manager | v1.0 | v1.0 | Unchanged — UI for managing/recovering shares |
| Firehose Proxy | v1.0 | v0.2 | Desktop-enrolled feature, not v1.0 |
| Firehose Emitter | — | v0.1 | NEW — native emission required for federation |
| Provisioning API | v1.0 | v0.1 | Core provisioning needed from day one |
| Commit Buffer | v1.0 | v0.2 | Feeds firehose proxy, needed at desktop enrollment |
| Custom PDS Shell | v0.1 | v0.2 | Not needed until desktop enrolls (relay is PDS in v0.1) |
| Tauri Shell | v0.1 | v0.2 | No desktop app in mobile-only phase |

### Major implication

In v7, the Custom PDS Shell and Tauri Shell were both v0.1 because the architecture assumed desktop-first. With mobile-first, these move to v0.2. The v0.1 work is all relay-side: building a federating PDS that runs on the relay, not on the desktop.

This significantly changes what v0.1 development looks like. Instead of building Tauri + PDS shell + Iroh, you're building a hosted PDS service (the relay) with an iOS companion for key management.
