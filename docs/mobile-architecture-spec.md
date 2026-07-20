**Mobile Architecture Specification**

iOS Identity Wallet with Mobile-First Onboarding

*v1.3 — Shamir Share 3 User's Choice + Migration Spec Cross-References*

*Companion to: Provisioning API Spec, Data Migration & Recovery Spec*

**Table of Contents**

1 Architectural Overview

> 1.1 Design Principles
>
> 1.2 ATProto Signing Constraint
>
> 1.3 The PDS as Permanent Proxy and Signer
>
> 1.4 Device Lifecycle Phases
>
> 1.5 Sovereignty Model

2 Identity and Key Management

> 2.1 Key Architecture
>
> 2.2 DID Document Structure
>
> 2.3 Secure Enclave / Keychain Integration

3 Mobile-First Onboarding

> 3.1 Onboarding Sequence
>
> 3.2 UX Considerations

4 PDS Architecture

> 4.1 PDS Responsibilities
>
> 4.2 XRPC Proxying to Desktop
>
> 4.3 Pluggable Signer Interface
>
> 4.4 Durability Requirements

5 Desktop Promotion

> 5.1 Device Pairing
>
> 5.2 Repo Migration to Desktop
>
> 5.3 Post-Promotion Data Flow
>
> 5.4 Desktop Offline Behavior

6 iOS App: Identity Wallet

> 6.1 What the App Is (and Is Not)
>
> 6.2 Core Capabilities
>
> 6.3 Technology Stack
>
> 6.4 App Store Considerations

7 Key Recovery

> 7.1 Shamir Share Distribution
>
> 7.2 Recovery Scenarios

8 API Surface

9 Edge Cases and Failure Modes

10 Future: Desktop-Local Signing

11 Implementation Milestones

12 Design Decisions Log

**1. Architectural Overview**

**1.1 Design Principles**

The iOS app is an identity wallet. It is not a social client. Users interact with the ATProto network through third-party applications like Bluesky, which connect to the user's PDS via XRPC to create records. The iOS app's job is to provision and manage the infrastructure that makes that possible.

Three principles govern the design:

-   **Sovereignty by rotation key custody.** The user's root rotation key lives on their device (iOS Keychain or macOS Keychain). This key is the ultimate authority over the identity. It can revoke the signing key, change the PDS endpoint, and migrate the account. No server operator can override it.

-   **Mobile-first onboarding.** A user can create an account, establish their DID, and start using Bluesky using only an iPhone. No desktop required.

-   **Progressive data sovereignty.** The PDS holds the signing key in all phases. Data sovereignty increases as the user adds a desktop: the repo moves to their hardware, the PDS becomes a proxy, and the user's rotation key can revoke the PDS's signing authority at any time. The architecture is designed so that signing sovereignty can follow if ATProto adds multi-key support.

**1.2 ATProto Signing Constraint**

A critical constraint in the current ATProto specification: a DID document supports exactly one active atproto signing key. The verificationMethods field in a did:plc operation is a key-value map with a single "atproto" slot. The spec explicitly states that the first valid atproto signing key in the verificationMethod array should be used, and any others ignored.

This means:

-   Only one entity can sign repo commits at any given time.

-   Switching the signing key from the PDS to a desktop (or vice versa) requires a DID document update via the PLC directory.

-   There is no mechanism for "fall back to the PDS when the desktop is offline" without performing a DID update each time.

-   Key scoping (e.g., "this key can sign posts but not rotate identity") does not exist beyond the inherent rotation-key vs. signing-key distinction.

Rotation keys, by contrast, do support multiple entries with a priority ordering. This is the basis of the user's sovereignty: they hold a higher-priority rotation key than the PDS, giving them the ability to revoke the PDS's signing key and reissue to a different provider at any time.

This constraint is the single most important architectural fact in this spec. Every design decision flows from it.

**1.3 The PDS as Permanent Proxy and Signer**

The PDS serves two permanent roles:

-   **XRPC proxy.** The desktop PDS may be behind CGNAT or a home firewall and cannot be directly reached from the public internet. The PDS's URL is the service endpoint in the DID document. It forwards XRPC requests to the desktop via the Iroh tunnel when a desktop is enrolled. This endpoint never changes.

-   **Commit signer.** The PDS holds the single atproto signing key registered in the DID document. When third-party apps (Bluesky, etc.) call XRPC to create records, the PDS signs the resulting commits. In desktop-enrolled mode, the PDS still signs, but it does so by forwarding the unsigned commit to the desktop for repo construction, receiving the commit data back, and signing it.

This dual role means the PDS is always in the critical path. The user's sovereignty comes not from removing the PDS, but from holding the rotation key that controls it. The user can swap to a different PDS at any time by revoking the current PDS's signing key and provisioning a new one --- the same migration pattern used when switching PDS hosts today.

**1.4 Device Lifecycle Phases**

  ---------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------- -------------------------------------------------------------------- ------------------------------------------------------------
  **Phase**              **PDS Behavior**                                                                                                                                                   **Repo Location**                                                    **Phone Role**
  **Mobile-Only**        Full PDS: hosts repo, serves XRPC, signs commits, emits firehose. Identical to any hosted PDS.                                                                       PDS (primary). Phone maintains periodic backup.                    Identity wallet: holds root rotation key, manages account.
  **Desktop Enrolled**   XRPC proxy + signer: forwards record-creation requests to desktop for repo construction, signs the resulting commits, serves public reads from cache.                Desktop (primary). PDS caches public data.                         Identity wallet + device manager.
  **Desktop Offline**    Serves public reads from cache. Write requests return 503 (desktop unreachable). PDS cannot create valid commits alone because the desktop holds the repo state.   Desktop (authoritative but unreachable). PDS cache serves reads.   Same. May receive push alert that desktop went offline.
  ---------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------- -------------------------------------------------------------------- ------------------------------------------------------------

**1.5 Sovereignty Model**

The sovereignty story has two layers that mature at different rates:

-   **Identity sovereignty (available from day one).** The user holds the highest-priority rotation key. They can: revoke the PDS's signing key, change their PDS endpoint to a different provider, migrate their account, and recover their identity even if the PDS disappears. This is the same level of identity control as running your own PDS today --- the standard pattern is for the PDS to hold a rotation key, but the user holds a higher-priority one.

-   **Data sovereignty (available when desktop is enrolled).** The user's repo lives on their hardware. The PDS is a cache/proxy that cannot unilaterally modify the repo (it signs commits, but the desktop constructs the Merkle tree and validates consistency). If the PDS misbehaves, the user's local repo is the authoritative copy.

A third layer, signing sovereignty (the user's own hardware signs commits), is architecturally prepared for but not available in v1.0 due to ATProto's single-key constraint. See Section 10 for the future design.

**2. Identity and Key Management**

**2.1 Key Architecture**

The system uses three keys with clearly separated roles:

  ----------------------- ----------------------------------------------------------------------- ---------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------
  **Key**                 **Location**                                                            **Role**                                                                                                                           **ATProto Mechanism**
  **Root rotation key**   iOS Keychain (Secure Enclave-backed where possible) or macOS Keychain   Ultimate identity authority. Can modify the DID document: add/remove keys, change service endpoint, rotate itself.                 Highest-priority entry in the did:plc rotationKeys array. Signed PLC operations.
  **PDS signing key**   PDS server (HSM or software key)                                      Signs all repo commits. The only key that third-party apps and the AppView see on commits.                                         The single "atproto" entry in verificationMethods. Also a lower-priority rotation key (so PDS can update handles).
  **Phone device key**    iOS Keychain                                                            Authenticates the phone to the PDS's management API (account settings, device operations). Not registered in the DID document.   None. This is an application-layer key for the PDS's REST API, not an ATProto key.
  ----------------------- ----------------------------------------------------------------------- ---------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------

When a desktop is enrolled, no new key is added to the DID document. The desktop connects to the PDS via Iroh and participates in repo construction (building the Merkle tree, validating records), but the PDS still signs all commits. The desktop may hold a local key for authenticating to the PDS's management API, analogous to the phone's device key.

**2.2 DID Document Structure**

The DID document is the same in all lifecycle phases. No DID updates are required when enrolling or removing a desktop:

-   rotationKeys: \[user\_root\_key (highest priority), PDS\_rotation\_key\]

-   verificationMethods: { atproto: PDS\_signing\_key }

-   services: { atproto\_pds: PDS\_url }

-   alsoKnownAs: \[at://handle\]

This stability is a significant advantage: desktop enrollment and removal are internal operations between the user's devices and the PDS. No PLC directory interaction is needed. The DID document only changes for identity operations: handle changes, PDS migration, or key rotation.

**2.3 Secure Enclave / Keychain Integration**

The root rotation key is the most security-critical asset. It must be protected against extraction while remaining usable for signing PLC operations.

ATProto requires secp256k1 or P-256 for rotation keys. The iOS Secure Enclave natively supports P-256 but not secp256k1. For v1.0:

-   Use P-256 for the root rotation key. This is natively supported in the Secure Enclave, providing hardware-backed key isolation where the private key never leaves the enclave.

-   The signing key (held by the PDS) uses secp256k1 or P-256 per the PDS's configuration. This is independent of the user's rotation key curve.

-   Shamir recovery shares are derived from a recovery seed that can reconstruct the rotation key (see Section 7).

This approach provides genuine hardware-backed protection for the rotation key, which is the most important key the user holds.

**3. Mobile-First Onboarding**

**3.1 Onboarding Sequence**

The user goes from app install to a working ATProto identity in a single session. At the end, they can open Bluesky and log in.

1.  **Step 1: Account creation.** User downloads the iOS app, creates an account via the provisioning API (POST /v1/accounts). This allocates a PDS instance and returns the PDS endpoint URL.

2.  **Step 2: Root key generation.** The app generates a P-256 key pair in the Secure Enclave. The public key is extracted (the private key never leaves the enclave). A phone device key is also generated in the Keychain for API authentication.

3.  **Step 3: PDS key provisioning.** The PDS generates its own signing key pair server-side and returns the public key to the phone.

4.  **Step 4: DID creation.** The app calls the DID ceremony endpoint (POST /v1/dids) with the user's rotation public key and the PDS's signing and rotation public keys. The PDS orchestrates did:plc creation with the PLC directory. The service endpoint is set to the PDS URL.

5.  **Step 5: Handle assignment.** User selects a handle (user.yourapp.social for free tier, or custom domain). The PDS configures DNS and verifies resolution.

6.  **Step 6: Repo initialization.** The PDS creates an empty ATProto repo. The PDS is now a fully functional PDS. Third-party apps can authenticate and create records.

7.  **Step 7: Shamir share generation.** The app generates 2-of-3 Shamir shares for the root rotation key's recovery seed: Share 1 in iCloud Keychain, Share 2 escrowed to PDS, Share 3 as user's choice at account creation.

    The onboarding flow presents both options with a brief explanation:

    - **Option A: Device-local** (Secure Enclave / Keychain on a second device) — More convenient but requires a second device.
    - **Option B: BIP-39 mnemonic phrase** (paper backup or USB storage) — More resilient but requires physical safekeeping.

    Default recommendation: BIP-39 (safer for users with only one device).

8.  **Step 8: Federation activation.** The PDS calls requestCrawl on the configured AppView. The user can now open Bluesky, log in with their handle, and start posting.

**3.2 UX Considerations**

Steps 2--4 should present as a single "Creating your identity..." moment (1--3 seconds, bottlenecked by the PLC directory).

Step 7 is the critical UX challenge. Recommended approach: iCloud Keychain backup is automatic and silent; the choice between device-local and BIP-39 gets a dedicated full-screen with clear explanation and safekeeping guidance; PDS escrow is explained in an optional "Learn more" flow.

Step 8 should conclude with: "Your identity is ready. Open Bluesky and log in with \[handle\]." Deep-link to Bluesky if installed, App Store link if not.

**4. PDS Architecture**

**4.1 PDS Responsibilities**

The PDS is the user's PDS as seen by the ATProto network. Its responsibilities vary by lifecycle phase but it is always the public-facing endpoint:

  -------------------- ------------------------------------------------------------------------------------------------ ----------------------------------------------------------------------------------------------------------------------------------------------------
  **Responsibility**   **Mobile-Only Phase**                                                                            **Desktop Enrolled Phase**
  **XRPC endpoint**    Terminates all XRPC directly. Serves reads from local repo. Handles writes by signing commits.   Proxies writes to desktop for repo construction, signs the resulting commit. Serves reads from cache (fast) or proxies to desktop (authoritative).
  **Commit signing**   Signs all commits using the DID-registered signing key.                                          Same. The PDS always signs. The desktop constructs the commit (Merkle tree update), the PDS signs it.
  **Repo storage**     Primary repo host. Durable storage with daily backups to object storage.                         Cache of public data. Desktop is authoritative. PDS pulls updates after each commit.
  **Firehose**         Emits commit events to subscribers and calls requestCrawl on AppViews.                           Same. Emits after signing each commit.
  **OAuth / auth**     Handles OAuth flows for third-party app authentication.                                          Same. OAuth state is managed at the PDS, not forwarded to desktop.
  -------------------- ------------------------------------------------------------------------------------------------ ----------------------------------------------------------------------------------------------------------------------------------------------------

**4.2 XRPC Proxying to Desktop**

When a desktop is enrolled, the PDS's write path changes. A write request (e.g., com.atproto.repo.createRecord from Bluesky) follows this flow:

1.  **Step 1.** PDS receives the XRPC request and validates the OAuth session.

2.  **Step 2.** PDS forwards the record data to the desktop PDS via the Iroh QUIC tunnel.

3.  **Step 3.** Desktop constructs the repo commit: creates the record, updates the Merkle tree, computes the new root hash, and builds the unsigned commit object.

4.  **Step 4.** Desktop sends the unsigned commit back to the PDS.

5.  **Step 5.** PDS signs the commit with the DID-registered signing key.

6.  **Step 6.** PDS sends the signed commit back to the desktop for storage.

7.  **Step 7.** PDS emits the commit to the firehose and responds to the XRPC caller.

Read requests (com.atproto.repo.getRecord, etc.) can be served from the PDS's cache for low latency, or proxied to the desktop for authoritative reads. Cached reads have a configurable TTL.

**4.3 Pluggable Signer Interface**

The PDS's signing logic is implemented behind a clean interface. In v1.0, the only implementation is "PDS-local key." The interface is designed so that a "desktop-remote key" implementation can be added later without architectural changes:

  ----------------------- --------------------------------------------- ----------------------------------------------------------------------------------------------------
  **Interface Method**    **v1.0: PDS-Local Signer**                  **Future: Desktop-Remote Signer**
  **sign(commitBytes)**   PDS signs using its local key.              PDS forwards to desktop for signing via Iroh. Requires DID doc update to register desktop's key.
  **getPublicKey()**      Returns the PDS's signing key public key.   Returns the desktop's signing key public key.
  **isAvailable()**       Always true (key is local).                   True when desktop is reachable. False when offline.
  ----------------------- --------------------------------------------- ----------------------------------------------------------------------------------------------------

This interface is the extension point. If ATProto adds multi-key signing support, or if users demand desktop-local signing despite the DID-update latency, the "desktop-remote" implementation can be activated per-account as a configuration change. See Section 10 for the full future design.

**4.4 Durability Requirements**

During the mobile-only phase, the PDS is the primary repo host:

-   Storage: SQLite with WAL mode on persistent volumes.

-   Backup: daily repo snapshots to object storage (S3/R2).

-   SLA: 99.9% uptime target. Downtime means the identity is unreachable.

-   Free tier: full repo hosting with storage cap from provisioning spec.

The phone maintains a periodic backup (BGAppRefreshTask, 6-hour interval) as a resilience measure. This is a snapshot for disaster recovery, not a sync mechanism.

**5. Desktop Promotion**

**5.1 Device Pairing**

Pairing is initiated via QR code. Because no DID document update is needed (the PDS's signing key doesn't change), this is purely an internal configuration change:

1.  **Step 1.** Desktop displays a QR code: one-time pairing token, ephemeral X25519 public key, PDS endpoint URL.

2.  **Step 2.** Phone scans QR, derives shared secret via X25519 key agreement.

3.  **Step 3.** Phone and desktop exchange device management keys over the encrypted channel (relayed through the PDS as message broker).

4.  **Step 4.** PDS registers the desktop as an enrolled device and establishes the Iroh tunnel endpoint.

5.  **Step 5.** Both devices confirm the pairing is active.

Critically: no PLC directory operation is required. The DID document is unchanged. This means pairing is instant, reversible, and invisible to the ATProto network.

**5.2 Repo Migration to Desktop**

After pairing, the desktop needs a copy of the repo:

1.  **Step 1.** Desktop requests a full repo export from the PDS (GET /v1/export/repo). Streamed as a CAR file.

2.  **Step 2.** Desktop imports the repo, validates the Merkle root against the latest commit.

3.  **Step 3.** Desktop signals readiness (POST /v1/devices/:id/promote).

4.  **Step 4.** PDS switches to proxy mode: write requests are now forwarded to the desktop for repo construction before the PDS signs them.

**5.3 Post-Promotion Data Flow**

After promotion, the write path is: Bluesky → PDS (XRPC) → desktop (repo construction via Iroh) → PDS (signing) → desktop (storage) → PDS (firehose emission + XRPC response).

The desktop is the authoritative repo. The PDS holds a cache. This gives the user data sovereignty: their posts, follows, and all records live on their hardware. The PDS cannot unilaterally modify the repo because the desktop validates Merkle tree consistency --- any commit the PDS signs must be built from the desktop's repo state.

**5.4 Desktop Offline Behavior**

When the desktop is unreachable (lid closed, power off, network down):

-   Read requests: PDS serves from its cache. The user's profile, posts, and public data remain available.

-   Write requests: PDS returns 503 to XRPC callers. Third-party apps like Bluesky see "PDS temporarily unavailable" and may retry or show an error. The user cannot post until the desktop comes online.

-   Why not fall back to PDS-local writes? Because the PDS doesn't have the current repo state. The desktop holds the authoritative Merkle tree. If the PDS signed a commit built from stale state, the repo would fork. This is an integrity constraint, not a policy choice.

This is the primary UX tradeoff of desktop enrollment. Users who find this unacceptable can delay enrolling a desktop and remain in the mobile-only phase (where the PDS handles everything). The identity wallet should clearly communicate this tradeoff during the promotion flow.

Mitigation: the desktop PDS should be configured as a launchd daemon (macOS) that starts at boot and runs even with the lid closed (if connected to power and network). Users should be educated that their Mac is now infrastructure.

**6. iOS App: Identity Wallet**

**6.1 What the App Is (and Is Not)**

The iOS app is:

-   An identity provisioning tool (create DID, set up handle, generate keys).

-   A key management interface (view rotation key status, initiate recovery).

-   A device manager (pair desktop, trigger promotion, monitor device health).

-   A recovery tool (Shamir share management, root key reconstruction).

-   An account settings interface (display name, avatar, handle changes, account deletion).

-   A PDS health monitor (uptime, storage usage, federation status).

The iOS app is not:

-   A social client. No feeds, timelines, notifications, or post content.

-   A content creation tool. Users do not compose posts or replies here.

-   A Bluesky client. It does not implement app.bsky.\* lexicons.

**6.2 Core Capabilities**

-   **Onboarding wizard:** account creation, key generation, DID ceremony, handle selection, Shamir setup, "Open Bluesky" CTA.

-   **Identity dashboard:** DID, handle, service endpoint, rotation key status, signing key info (PDS-held), last federation crawl.

-   **Device management:** pair desktop (QR scanner), promote desktop, view device status (online/offline/last seen), de-enroll desktop.

-   **Recovery center:** Shamir share status (iCloud sync verified? PDS escrow healthy? device-local backup available?), initiate recovery ceremony, regenerate shares.

-   **Account settings:** display name, avatar (uploaded via PDS), handle management, account deletion (exit ceremony).

-   **PDS health:** uptime, storage usage vs. tier cap, current operating mode (hosted PDS vs. proxy).

-   **Sovereignty actions:** revoke PDS signing key (nuclear option --- identity goes offline until a new key is provisioned), migrate to a different PDS provider.

**6.3 Technology Stack**

-   **UI:** SwiftUI. Native is required for Secure Enclave / Keychain integration.

-   **Networking:** URLSession for HTTPS to PDS API. No Iroh on iOS in v1.0.

-   **Crypto:** CryptoKit for P-256 Secure Enclave key generation and signing (rotation key). No secp256k1 library needed on the phone --- the PDS handles signing.

-   **Local storage:** SQLite (via GRDB.swift) for repo backup. Core Data for app state.

-   **Background:** BGAppRefreshTask for periodic repo backup (6-hour interval).

-   **Push:** APNs for PDS health alerts (desktop offline, storage cap approaching).

**6.4 App Store Considerations**

-   Crypto export compliance: uses CryptoKit (system framework). No custom cryptography. Should qualify for CCATS exemption.

-   Account deletion: maps to exit ceremony (DELETE /v1/accounts/:id). 30-day grace period is compliant.

-   Minimum functionality: position as "decentralized identity wallet" with onboarding wizard, device management, recovery tools, and PDS dashboard. The onboarding flow alone provides sufficient interactive surface.

-   IAP considerations: if tier upgrades are offered in-app, Apple takes 30%. Consider directing upgrades to web dashboard.

**7. Key Recovery**

> **⚠️ Superseded model — do not implement from this section as written.** The
> recovery scenarios below say the reconstructed secret is imported as a *root
> rotation key* "in new Secure Enclave" (§7.2). That is cryptographically
> impossible: Secure-Enclave private keys are non-extractable and cannot be
> imported. The as-built system works differently: the onboarding split is
> generated **client-side** over a fresh recovery *seed* that HKDF-derives a
> **separate software recovery rotation key** (installed at `rotationKeys[1]`),
> and the reconstruction ceremony now exists — the wallet combines ≥2 shares,
> re-derives that recovery key, and signs a PLC op *installing a freshly generated
> Secure-Enclave device key* at `rotationKeys[0]` (the reconstructed key is never
> the device key). See
> [Key recovery from Shamir shares](archive/design-plans/2026-07-17-key-recovery-from-shares.md)
> for the authoritative design and
> [identity-and-key-custody.md](architecture/identity-and-key-custody.md) for the
> current custody model.

**7.1 Shamir Share Distribution**

The root rotation key's recovery seed is split into 2-of-3 Shamir shares:

  ------------- ---------------------------------- ----------------------------------------------------------------------------------------------------------
  **Share**     **Location**                       **Availability**
  **Share 1**   iCloud Keychain                    Survives phone loss if iCloud account is intact. Available on any Apple device signed into the same iCloud.
  **Share 2**   PDS escrow                       Retrieved via account authentication (email + password or OAuth). Available as long as PDS is operational.
  **Share 3**   User's choice (device-local or BIP-39)   Device-local: stored on designated backup device. BIP-39 phrase: paper or USB backup. User's responsibility.
  ------------- ---------------------------------- ----------------------------------------------------------------------------------------------------------

**7.2 Recovery Scenarios**

-   **Lost phone, iCloud intact:** Share 1 + Share 2 = recovery. Install app on new phone, authenticate to iCloud and PDS, reconstruct root key in new Secure Enclave. If share 3 is device-local on another device, access it there for redundancy.

-   **Lost phone, iCloud compromised:** Share 2 + Share 3 = recovery. Authenticate to PDS, retrieve device-local share from backup device or enter BIP-39 recovery phrase. Same key reconstruction flow.

-   **Lost phone + PDS down:** Share 1 + Share 3 = recovery. Reconstruct root key locally, provision new PDS, update DID doc with new service endpoint.

-   **Compromised PDS signing key:** Phone's root rotation key signs a DID doc update revoking the PDS's key. PDS generates a new key, root key authorizes it via another DID update. Brief service interruption.

Important: because the PDS holds the only signing key, losing access to the PDS is a service interruption but not an identity loss. The rotation key (held by the user) can always provision a new PDS with a new signing key.

**7.3 Planned Device Upgrades**

For planned device upgrades (e.g., new iPhone), see the Data Migration & Recovery Spec §3 which covers the Iroh-based peer transfer with 6-digit verification code. The same transfer protocol works for phone-to-phone and desktop-to-desktop swaps.

For desktop-specific migration (desktop-to-desktop), see the Data Migration & Recovery Spec §3. The phone acts as the authorization device during desktop transfers — the user confirms the transfer from the mobile app.

**8. API Surface**

New endpoints extending the provisioning API:

  ------------ ------------------------- ---------------------------------------------------------------------------------------------------------------------------
  **Method**   **Path**                  **Description**
  POST         /v1/pds/keys            Generate a new PDS signing key. Returns public key. Called during onboarding and after key rotation.
  DELETE       /v1/pds/keys/:keyId     Revoke the PDS's signing key. Requires root rotation key signature. PDS stops signing immediately.
  GET          /v1/pds/repo/snapshot   Full repo snapshot (CAR file). For phone backup and desktop repo import.
  POST         /v1/devices/:id/pair      Initiate device pairing. Body: pairing token, ephemeral public key. Returns encrypted channel ID.
  POST         /v1/devices/:id/promote   Promote desktop to repo host. PDS switches to proxy mode for writes.
  DELETE       /v1/devices/:id           De-enroll a device. If desktop, PDS reverts to hosted PDS mode.
  GET          /v1/devices/:id/status    Device status: online/offline, last seen, role, lifecycle phase.
  POST         /v1/pds/commits/sign    Sign an unsigned commit. Used by the desktop in proxy mode. Desktop sends unsigned commit bytes, PDS returns signature.
  GET          /v1/pds/mode            Current PDS operating mode (hosted-pds or proxy). Includes desktop connectivity status.
  ------------ ------------------------- ---------------------------------------------------------------------------------------------------------------------------

Modified existing endpoints:

-   **POST /v1/dids:** accepts PDS\_signing\_key and PDS\_rotation\_key fields. DID ceremony registers all keys atomically.

-   **GET /v1/export/repo:** supports chunked transfer encoding for cellular. Also used during desktop promotion.

-   **POST /v1/keys/shares:** called during mobile onboarding (Step 7), not just desktop setup.

**9. Edge Cases and Failure Modes**

  -------------------------------------------- ------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------
  **Scenario**                                 **Behavior**                                                                          **Recovery**
  PDS compromised (signing key leaked)       Attacker can sign repo commits. Cannot rotate identity (no root key).                 Phone's root key revokes signing key via PLC update. PDS generates new key, root key authorizes it. Brief outage.
  Desktop offline, user tries to post          PDS returns 503 to Bluesky. User sees "PDS unavailable."                            User opens Mac / wakes from sleep. Desktop reconnects via Iroh. Writes resume.
  Desktop offline, user reads own profile      PDS serves from cache. Profile and posts remain visible.                            No action needed. Reads always work from cache.
  PDS down during mobile-only                Identity unreachable. No reads or writes. Phone has local backup.                     Wait for restoration, or: root key provisions new PDS, updates DID doc, restores repo from phone backup.
  PDS down during desktop-enrolled           Identity unreachable (PDS is the service endpoint). Desktop has full repo.          Same: provision new PDS, update DID doc. Desktop's repo is authoritative. No data loss.
  Phone lost, root key gone                    PDS and desktop continue operating. No identity operations possible.                Shamir recovery (Section 7). Reconstruct root key on new phone. Normal service is uninterrupted during recovery.
  DID update fails during PDS key rotation   Old signing key still active. New key not yet authorized.                             Retry the PLC operation. Old key continues working until rotation completes. No service interruption.
  Desktop de-enrolled while offline            PDS switches back to hosted PDS but has stale repo (last cache).                    PDS's cache becomes the new source of truth. Some recent commits may be lost if they were only on the desktop. Phone backup can supplement.
  iCloud Keychain sync fails for Share 1       Share 1 only on local device. Phone loss leaves Shares 2 + 3.                         App verifies sync success, warns if failed. Device-local or BIP-39 backup is available as fallback.
  User wants to switch PDS providers         Standard PDS migration: provision new PDS, export repo, root key updates DID doc.   This is the credible exit story. Fully supported by ATProto's existing migration protocol.
  -------------------------------------------- ------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------

**10. Future: Desktop-Local Signing**

This section documents the architectural path to full signing sovereignty, for when ATProto adds multi-key support or when the DID-update-per-switch tradeoff becomes acceptable.

**10.1 If ATProto Adds Multi-Key Signing**

If the verificationMethods field is expanded to support multiple atproto signing keys (e.g., via an array instead of a single-entry map), the architecture is ready:

-   Register the desktop's signing key alongside the PDS's key in the DID doc.

-   Activate the "desktop-remote signer" implementation behind the pluggable signer interface (Section 4.3).

-   When the desktop is online, commits are signed by the desktop's key. When offline, the PDS signs with its key. No DID update needed for failover.

-   This is the "sovereignty dial" from v1.1 of this spec, deferred until the protocol supports it.

**10.2 If Users Demand Desktop Signing Now**

Even under current ATProto constraints, desktop-local signing is technically possible at the cost of DID updates:

-   Desktop holds the signing key. DID doc's atproto verificationMethod points to the desktop's key.

-   PDS proxies unsigned commits to the desktop for signing (reversing the current flow).

-   When the desktop goes offline, the user has two options: accept write downtime, or trigger a DID update to swap the signing key to the PDS (and swap back when the desktop returns).

-   The DID update path adds 1--3 seconds of latency per switch. The PLC directory also rate-limits operations per DID. Frequent switching (daily lid-close/open cycles) would be impractical.

Recommendation: offer this as an "advanced" option for power users who explicitly want signing sovereignty, with clear warnings about the downtime tradeoff. The pluggable signer interface supports this with no PDS code changes --- it's purely a configuration and DID doc update.

**10.3 Abstraction Checklist**

To ensure the architecture stays flexible, the following must remain true:

-   The PDS's signing logic is behind the signer interface (Section 4.3). No commit-signing code exists outside this interface.

-   The desktop's repo construction is signing-agnostic: it builds unsigned commits and expects a signature from an external source (today the PDS, potentially itself in the future).

-   The DID ceremony endpoint accepts the signing key as a parameter, not a hardcoded PDS key. The key source can be the PDS or the desktop.

-   The phone's identity wallet UI has a placeholder for "signing authority" in the identity dashboard, even if it's always "PDS" in v1.0.

**11. Implementation Milestones**

**11.1 Phase 1: Identity Wallet MVP (iOS v0.1)**

Goal: user can create an ATProto identity from their iPhone and log into Bluesky.

-   P-256 key generation in Secure Enclave (root rotation key).

-   Account creation via provisioning API.

-   PDS signing key provisioning.

-   DID ceremony (root rotation key + PDS keys).

-   Handle selection (yourapp.social subdomain).

-   Shamir share generation (iCloud + PDS + user's choice of device-local or BIP-39).

-   Federation activation (requestCrawl).

-   Onboarding wizard with "Open Bluesky" CTA.

-   Basic identity dashboard.

**11.2 Phase 2: Device Management (iOS v0.2)**

Goal: user can pair a desktop and manage devices.

-   QR-code device pairing.

-   Desktop promotion (repo migration + proxy mode activation).

-   Device list with status and health.

-   De-enrollment flow.

-   Periodic repo backup via BGAppRefreshTask.

-   Push notifications for PDS health alerts.

**11.3 Phase 3: Recovery and Polish (iOS v1.0)**

Goal: production-ready identity wallet.

-   Shamir recovery ceremony (all three share combinations).

-   Custom domain handle setup.

-   Account deletion (exit ceremony).

-   PDS signing key rotation (revoke and reissue).

-   PDS migration (switch to different provider).

-   Share status monitoring.

-   Storage usage dashboard.

**11.4 Future: Signing Sovereignty (v2.0+)**

Goal: user's own hardware signs commits (contingent on ATProto evolution).

-   Desktop-remote signer implementation behind pluggable interface.

-   DID doc update automation for signing key swaps.

-   Multi-key support (if ATProto adds it).

-   Sovereignty dial UI in identity wallet.

**12. Design Decisions Log**

  --------------------------------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- -------------------------------------------------------------------------------------------------------------------------------------
  **Decision**                                        **Rationale**                                                                                                                                                                                                                                                             **Alternatives Rejected**
  PDS always holds the signing key                  ATProto supports exactly one active signing key per DID. The PDS must be always-available for third-party apps. Switching keys requires DID updates (1--3s latency, rate-limited). Architecture is designed with a pluggable signer interface for future flexibility.   Desktop signs (503 on offline). Dual signing keys (not supported by ATProto). Phone as signing oracle (iOS throttles pushes).
  PDS is the permanent service endpoint             Desktop may be behind CGNAT/firewall. PDS proxies via Iroh. No DID doc changes when enrolling/removing desktop. Network-invisible promotion.                                                                                                                            Direct desktop exposure (CGNAT blocks). DID endpoint swap on promotion (complex, visible).
  P-256 for rotation key (not secp256k1)              P-256 is natively supported in iOS Secure Enclave, providing hardware-backed key isolation. ATProto accepts both P-256 and secp256k1 for rotation keys. No need to use a software key with weaker protection.                                                             secp256k1 software key with Keychain protection (weaker than Secure Enclave). Wait for Secure Enclave secp256k1 support (unlikely).
  No DID doc changes for desktop enrollment           The PDS's signing key and service endpoint don't change. Desktop is an internal infrastructure detail. This makes enrollment instant, reversible, and invisible to the network.                                                                                         Register desktop key in DID doc (unnecessary, adds PLC latency, visible to network).
  iOS app is identity wallet, not social client       Users interact with ATProto through third-party apps. Building a social client duplicates work and competes with the ecosystem. The wallet serves the infrastructure layer.                                                                                               Full Bluesky client (scope expansion). Companion with feed viewing (half-measure).
  503 on desktop-offline writes (no fallback)         The PDS cannot construct valid commits from stale repo state. The desktop holds the authoritative Merkle tree. Signing a commit from stale state would fork the repo. This is an integrity constraint.                                                                  PDS signs from stale cache (repo fork risk). Queue writes until desktop wakes (complex, stale commits).
  Pluggable signer interface for future flexibility   If ATProto adds multi-key signing, or users demand desktop-local signing despite DID update costs, the PDS can swap implementations with a config change. No architectural redesign needed.                                                                             Hard-code PDS signing (inflexible). Build desktop signing now (premature, protocol doesn't support it cleanly).
  SwiftUI native (not cross-platform)                 Secure Enclave P-256 integration requires native CryptoKit. Core function is key management. Cross-platform abstraction over crypto is a security risk.                                                                                                                   React Native, Flutter (abstraction over security primitives).
  QR-code pairing (not BLE/NFC)                       Works at any distance, no hardware requirements, familiar UX (Signal, WhatsApp). BLE is fragile, NFC requires proximity.                                                                                                                                                  Bluetooth LE (unreliable). NFC (proximity). Manual key entry (bad UX).
  Share 3 as user's choice                            Balances convenience (device-local for multi-device users) with resilience (BIP-39 for air-gap backup). Accommodates diverse user security preferences.                                                                                                                   Single-option model (less flexible). PDS-held share (breaks sovereignty model).
  --------------------------------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- -------------------------------------------------------------------------------------------------------------------------------------
