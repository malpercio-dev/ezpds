**Data Migration Spec**

Device Swap, Recovery & Key Migration

v0.2 — Shamir Model Update + Mobile Cross-References

March 2026

Companion to Provisioning API Spec v0.2

**Changelog**

```
v0.2 Changes — Shamir Model Update + Mobile Cross-References

FIX   Shamir share model: Share 3 is user's choice (device-local or BIP-39)
NEW   Cross-references to mobile spec §7 for phone recovery
FIX   Milestone alignment with unified-milestone-map.md
```

**1. Overview**

This document specifies the data migration system for the desktop PDS application. It covers two primary scenarios: planned device swaps (user voluntarily moves to a new machine) and unplanned device loss (hardware failure, theft, or accidental damage). Both scenarios share core infrastructure but diverge in their recovery ceremony.

The migration system builds on three foundational components from the existing architecture: the Shamir secret sharing scheme for DID key protection, the PDS layer's configurable caching behavior, and the Iroh peer-to-peer transport.

**1.1 Design Principles**

-   **Zero key exposure:** DID signing keys never transit the network unencrypted, even during migration. All key material is wrapped before leaving the source device or reconstructed only on the destination device.

-   **Sovereignty preserved:** The PDS never holds sufficient key material to impersonate the user. Recovery always requires at least two of three Shamir shares, and the PDS holds at most one.

-   **Grandma-proof UX:** The planned swap happy path requires entering a 6-digit code. Unplanned recovery requires signing into iCloud on the new device (which most users have already done).

-   **Tier-aware restoration:** Paid users get full repo mirrors for instant recovery. Free users reconstruct from the network, accepting possible blob loss.

**1.2 Migration Assets**

Each asset has a distinct risk profile and recovery strategy:

  ----------------------- ------------------ ------------------------------- -----------------------------------------------------------
  **Asset**               **Risk if Lost**   **Recovery Source**             **Notes**
  DID signing key         **Catastrophic**   Shamir reconstruction           Identity is permanently lost without 2-of-3 shares
  ATProto repo (CAR)      High               PDS mirror or network crawl   Signed commit history; can be re-fetched if crawled
  Blob store              Medium             PDS mirror or CDN             Images/media; may be lost if never crawled by AppView
  App config              Low                PDS account metadata          Handle, PDS endpoint, preferences; easily reconstructed
  iCloud Keychain share   Low (redundant)    Apple iCloud sync               Auto-syncs to new device via Apple ID
  ----------------------- ------------------ ------------------------------- -----------------------------------------------------------

**2. Shamir Key Recovery Model**

> **⚠️ Superseded model — do not implement from §§2, 4 as written.** These
> sections predate both the passwordless-auth work and the shipped key-recovery
> ceremony. Three claims are wrong today: (a) the split input is described as the
> DID/root signing key, but the onboarding split is a fresh recovery *seed* whose
> *derived* key sits at `rotationKeys[1]` — not the signing key itself, which a
> Secure-Enclave key could never be; (b) Share 2 is described as "HSM-wrapped" and
> released "after account authentication (email + password)" — it is AES-256-GCM
> KEK-wrapped in the `recovery_escrow` table (only pre-inversion/`did:web`
> accounts use the legacy `accounts.recovery_share` column), and escrow release is
> gated by an emailed OTP plus a delay window, not a password; (c) the §4.1/§4.4
> ceremony has "the PDS reconstruct rotation key from 2 shares" — the PDS must
> never reconstruct the user's key, and it does not: the reconstruction ceremony
> now exists and runs **client-side** (the wallet combines ≥2 shares, re-derives
> the recovery keypair, and signs the rotation op itself). See
> [Key recovery from Shamir shares](archive/design-plans/2026-07-17-key-recovery-from-shares.md)
> (authoritative) and
> [identity-and-key-custody.md](architecture/identity-and-key-custody.md).

The DID signing key is split into three shares using Shamir's Secret Sharing (2-of-3 threshold). Any two shares are sufficient to reconstruct the key; no single share reveals any information about the key.

**2.1 Share Distribution**

  ----------- ------------------------------------------ ----------------------------------------------------- ------------------------------------------------------------------
  **Share**   **Holder**                                 **Storage**                                           **Recovery Access**
  Share 1     iCloud Keychain                            Keychain (E2E encrypted by Apple)                     Available on any device signed into the same iCloud account
  Share 2     PDS service                              Encrypted at rest, server-side HSM-wrapped            Released after account authentication (email + password)
  Share 3     User's choice (device-local OR BIP-39)    Secure Enclave / Keychain (device-local) or paper/USB export   Auto-available on configured device, or manual entry from backup
  ----------- ------------------------------------------ ----------------------------------------------------- ------------------------------------------------------------------

**2.2 Share Holder Rationale**

The user's choice for share 3 balances convenience and resilience. For device-local storage, the user designates a second device (e.g., iPad) where share 3 is stored in the Secure Enclave/Keychain, making recovery seamless across their ecosystem if they lose their primary device. For BIP-39 backup, power users who want full air-gap sovereignty can export share 3 as a recovery phrase for paper or USB storage. The recovery ceremony code is identical in both cases; only the share retrieval step differs.

iCloud Keychain (share 1) was chosen as the default anchor for UX simplicity: most macOS users are already signed into iCloud, making unplanned recovery require zero additional user action beyond installing the app on a new device.

**2.3 Threat Model**

-   **PDS compromise alone:** Attacker obtains share 2 only. Insufficient for key reconstruction.

-   **iCloud compromise alone:** Attacker obtains share 1 only. Insufficient.

-   **PDS + iCloud compromise:** Attacker can reconstruct key. Mitigation: PDS share is HSM-wrapped and requires account auth; iCloud Keychain is E2E encrypted and requires Apple ID + device passcode. Combined compromise is a sophisticated, targeted attack.

-   **Device theft (unlocked):** Attacker has share 3 if device-local, or nothing if BIP-39 is in a separate location. Mitigation: biometric/password gate on the app's key export flow.

**3. Planned Device Swap**

The happy path. The user's old machine is still accessible. This flow uses a direct Iroh peer connection for local transfer, with PDS-mediated fallback for remote swaps.

**3.1 Flow**

1.  **Initiate transfer.** User opens Settings → Transfer to New Device on the old machine. The app generates a one-time 6-digit transfer code and displays it on screen. Internally, the app bundles: full repo snapshot (CAR file export), blob archive, DID signing key (encrypted with the transfer code as symmetric key via AES-256-GCM), app config (handle, PDS endpoint, preferences), and a manifest with checksums.

2.  **Establish peer connection.** User installs the app on the new machine, selects "Transfer from Existing Device," and enters the 6-digit code. The app uses Iroh's peer discovery to find the old machine on the local network. If both machines are on the same LAN, the transfer is direct (no PDS involvement). If remote, the transfer routes through the Iroh PDS, encrypted end-to-end with the transfer code as the shared secret.

3.  **Transfer and verify.** The bundle streams from old → new. The new machine verifies the manifest checksums, decrypts the DID key, and validates it can sign a test commit against the repo's Merkle root.

4.  **Device lease handover.** The new machine calls POST /v1/devices/:id/lease to acquire the primary device lease from the PDS. The old machine's lease is released. The PDS begins routing traffic to the new device's Iroh node ID.

5.  **Shamir share rotation.** The new machine generates a fresh Shamir split of the DID key and updates share 1 (iCloud Keychain), share 2 (PDS via PUT /v1/keys/shares/:id), and share 3 (device-local Keychain or BIP-39 export). This ensures the old machine's local share is invalidated.

6.  **Decommission old device.** The old machine's app detects the lease release and prompts: "Transfer complete. Wipe local data?" On confirmation, it securely erases the local repo, blobs, and key material.

**3.2 Transfer Code Security**

The 6-digit code provides approximately 20 bits of entropy, which is intentionally low for usability. Security relies on the transfer window being short-lived (default: 10 minutes), the Iroh connection requiring the code for handshake, and rate limiting on connection attempts (3 failures = code invalidated, regenerate required). For power users, a "Show full code" option reveals a 24-character alphanumeric code for higher entropy.

**4. Unplanned Device Loss**

The old machine is gone. Recovery depends entirely on the Shamir shares and the PDS's cached data.

**4.1 Recovery Ceremony**

1.  **Install and select recovery.** User installs the app on a new machine and selects "Recover Existing Identity."

2.  **Authenticate with PDS.** User signs in with their account credentials (email + password from initial provisioning). The PDS verifies identity and releases Shamir share 2.

3.  **Retrieve share 3.** If the user chose device-local storage: the app attempts to retrieve share 3 from the configured backup device (via iCloud Keychain sync or local network if available). If the configured device is inaccessible, the user can enter a BIP-39 backup phrase if one was exported during setup. If the user chose BIP-39 backup: the app prompts for manual entry of the recovery phrase.

4.  **Reconstruct DID key.** Shares 2 + 3 are combined via Shamir reconstruction. The app verifies the key by checking its public component against the DID document retrieved from the PLC directory.

5.  **Restore repo and blobs.** Restoration behavior depends on the user's tier (see section 4.2).

6.  **Re-establish PDS presence.** Register new device lease, publish DID rotation operation if key was rotated, and resume Iroh tunnel to PDS.

7.  **Rotate Shamir shares.** Same as planned swap step 5: generate fresh split, update all three share holders. This invalidates the lost device's share 3.

**4.2 Tier-Based Repo Restoration**

  ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Tier**   **Behavior**                                                                                                                                                                                                                                                                                **Tradeoffs**
  **Paid**   PDS holds a full repo mirror (synced continuously). On recovery, the PDS streams the complete CAR file + blobs to the new device. Target: \< 5 min for a typical repo.                                                                                                                  Near-instant, zero data loss. PDS storage cost scales with repo size. User pays for this via subscription.
  **Free**   PDS holds only the recent activity buffer (configurable, default 7 days). On recovery, the app: (a) imports the buffer from the PDS, (b) calls com.atproto.sync.getRepo against the AppView/BGS to fetch the historical repo, (c) attempts to recover blobs from known CDN endpoints.   Slower recovery (minutes to hours depending on repo size and network). Blobs that were never crawled by the AppView are permanently lost. Commit history intact if the BGS indexed it.
  ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**4.3 The Blob Loss Problem (Free Tier)**

On the free tier, blobs (images, media) that were uploaded but never crawled by the AppView or any PDS are unrecoverable after device loss. This is an inherent tradeoff of not paying for PDS-side mirroring.

Mitigations:

-   **Proactive crawl requests:** After every blob upload, the app calls requestCrawl to the configured AppView, increasing the likelihood the blob is indexed before any loss event.

-   **Blob inventory warnings:** The health monitor tracks which blobs have been confirmed crawled vs. uncrawled. Settings → Data Health shows a "X blobs not yet backed up by the network" count, with an upgrade prompt.

-   **Grace period on tier downgrade:** If a paid user downgrades to free, the PDS retains the full mirror for 30 days before pruning to buffer-only.

**4.4 Phone Recovery**

Phone-to-phone recovery uses the same Shamir infrastructure as desktop recovery. The mobile architecture spec (§7) details the iOS-specific flow:

1.  New phone signs into iCloud → Share 1 is available
2.  User authenticates with PDS → Share 2 is available
3.  PDS reconstructs rotation key from 2 shares
4.  PDS re-generates signing key, updates DID document
5.  New phone stores new rotation key in Secure Enclave

The key difference from desktop recovery: in phone recovery, the PDS already holds the repo (it's the PDS in mobile-only mode), so there's no repo transfer step. Recovery is purely a key reconstruction + DID update operation.

See: mobile-architecture-spec-v1.3 §7.2 for the complete flow.

**5. API Surface**

These endpoints extend the existing provisioning API. All endpoints require bearer token authentication.

**5.1 Transfer Endpoints**

  ----------------------- ------------ ----------------------------------------------------------------------------------------------------
  **Endpoint**            **Method**   **Purpose**
  /v1/transfer/initiate   POST         Generate transfer session + code. Returns session ID and encrypted bundle metadata.
  /v1/transfer/accept     POST         New device submits transfer code. PDS brokers Iroh peer introduction if direct connection fails.
  /v1/transfer/complete   POST         Finalize transfer. Triggers lease handover and old device notification.
  ----------------------- ------------ ----------------------------------------------------------------------------------------------------

**5.2 Recovery Endpoints**

  ------------------------- ----------------- ------------------------------------------------------------------------------------------------------
  **Endpoint**              **Method**        **Purpose**
  /v1/recovery/initiate     POST              Begin recovery ceremony. Requires account credentials. Returns share 2 (encrypted to session key).
  /v1/recovery/verify-key   POST              Client proves it reconstructed the correct DID key by signing a challenge. Unlocks repo restoration.
  /v1/recovery/restore      GET (streaming)   Stream repo + blobs from PDS cache. Paid tier: full mirror. Free tier: buffer only.
  ------------------------- ----------------- ------------------------------------------------------------------------------------------------------

**5.3 Key Management Endpoints**

  ----------------------- ------------ ---------------------------------------------------------------------------------------------
  **Endpoint**            **Method**   **Purpose**
  /v1/keys/shares/:id     PUT          Update the PDS-held Shamir share after rotation. Requires proof of current key ownership.
  /v1/keys/shares/:id     DELETE       Permanently delete PDS-held share (account deletion flow).
  /v1/keys/rotation-log   GET          Audit log of all Shamir rotations and share updates for the account.
  ----------------------- ------------ ---------------------------------------------------------------------------------------------

**6. Sequence Summaries**

**6.1 Planned Swap Sequence**

Old Device → generates transfer code → bundles repo + encrypted key

New Device → enters code → discovers old device via Iroh LAN / PDS fallback

Old Device → streams bundle → New Device

New Device → verifies checksums + decrypts key → POST /v1/devices/:id/lease

New Device → generates fresh Shamir split → updates all 3 share holders

Old Device → detects lease release → prompts wipe → securely erases

**6.2 Unplanned Loss Sequence**

New Device → POST /v1/recovery/initiate (credentials) → receives share 2

New Device → retrieves share 3 from device-local storage (automatic) or paper (manual)

New Device → Shamir reconstruct → POST /v1/recovery/verify-key (signed challenge)

New Device → GET /v1/recovery/restore (streaming) → imports repo + blobs

New Device → POST /v1/devices/:id/lease → DID rotation → Iroh tunnel up

New Device → fresh Shamir split → updates all 3 share holders

**7. Edge Cases and Risks**

**7.1 Lost Share 3 (Paper or Device)**

If the user chose BIP-39 backup and loses the paper, only shares 1 + 2 (iCloud + PDS) remain. If the user chose device-local and loses the backup device, share 3 is inaccessible. Mitigation: during onboarding, the app clearly explains both options and recommends exporting a BIP-39 backup even for device-local mode. The app also offers periodic "recovery key health check" reminders.

**7.2 PDS Downtime During Recovery**

If the PDS is unreachable when the user attempts recovery, share 2 is temporarily inaccessible. Mitigation: the PDS is the only infrastructure component the user depends on, and its SLA is part of the service tier. Multi-region PDS failover (designed in the provisioning spec) covers this. The recovery ceremony gracefully retries with exponential backoff.

**7.3 Stale PDS Mirror**

For paid users, the PDS mirror may lag behind the device's latest commits if the device was actively posting when it was lost. The PDS sync interval determines the maximum data loss window. Default: 5-minute sync interval, meaning up to 5 minutes of commits could be lost. Configurable per account.

**7.4 Concurrent Recovery Attempts**

If an attacker attempts recovery while the legitimate user is also recovering, the PDS's recovery/initiate endpoint enforces a single active session per account. Second attempts return 409 Conflict with a "recovery already in progress" message. Sessions expire after 30 minutes.

**7.5 Transfer Interrupted Mid-Stream**

If the Iroh connection drops during a planned swap, the transfer session remains valid for 10 minutes. The new device can reconnect and resume from the last acknowledged chunk (the bundle is transferred in content-addressed blocks). After timeout, a new transfer code must be generated.

**8. Implementation Milestones**

**v0.1 — Basic Migration + Shamir Generation**

-   Planned device swap (LAN transfer via Iroh, 6-digit code)
-   Shamir share generation during account creation
-   Share 1 → iCloud Keychain storage
-   Share 2 → PDS escrow
-   Share 3 → user's choice (device-local or BIP-39)
-   Note: Share GENERATION is v0.1. Share RECOVERY is v1.0.

**v1.0 — Full Recovery**

-   Unplanned device loss recovery ceremony
-   Shamir reconstruction (2-of-3)
-   DID key rotation after recovery
-   Recovery UI in mobile app
-   PDS-side recovery session management

**Later**

-   Multi-device sync (share key across devices without migration)

See unified-milestone-map.md for how these milestones align with the architecture, provisioning API, and mobile spec phases.

**9. Design Decisions Log**

  ------------------------------------------- ----------------------------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------
  **Decision**                                **Rationale**                                                                                                     **Alternatives Considered**
  iCloud Keychain as share 1                  Best UX for target audience (non-technical macOS users). Zero user action on recovery. E2E encrypted by Apple.    Paper-only (too fragile for grandma), PDS holds 2 shares (breaks sovereignty model).
  Share 3 as user's choice                    Balances convenience (device-local for multi-device users) with resilience (BIP-39 for air-gap backup).         Single-option model (less flexible for different user preferences).
  6-digit transfer code for planned swap      Balances usability (easy to read aloud) with security (short-lived session, rate-limited attempts).               QR code (requires camera), Bluetooth pairing (unreliable), pre-shared key (complex UX).
  Shamir rotation on every migration          Ensures the old device's local share cannot be used even if physically recovered by an attacker after the swap.   Reuse shares (simpler but leaves old share 1 valid indefinitely).
  Configurable PDS caching per tier         Aligns cost with value. Full mirror is expensive; free users accept the tradeoff. Upgrade path is clear.          Full mirror for all (unsustainable at scale), no caching (too risky).
  Proactive requestCrawl after blob upload    Reduces blob loss risk on free tier without requiring PDS storage. Leverages existing ATProto infrastructure.   Accept blob loss (bad UX), require paid tier for blob uploads (too restrictive).
  ------------------------------------------- ----------------------------------------------------------------------------------------------------------------- -----------------------------------------------------------------------------------------
