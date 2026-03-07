# Provisioning API v0.3 Amendments

Changes required to update the Provisioning API from v0.2 to v0.3. Each section maps to an action item from cross-spec-analysis.md.

---

## Changelog Entry

```
v0.3 Changes — Mobile-First Reconciliation + Endpoint Consolidation

Reconciled with mobile architecture spec v1.2 (canonical) and
migration spec v0.1. All endpoints tagged with milestone phase.

FIX   Ed25519 → P-256/secp256k1 throughout (ATProto requirement)
FIX   DID ceremony: client sends key material, relay constructs DID doc
FIX   Tier model: Free/Pro/Business + BYO as deployment model
NEW   POST /v1/accounts/mobile — combined mobile account creation
NEW   9 endpoints from mobile spec (relay keys, device mgmt, signing)
NEW   8 endpoints from migration spec (transfer, recovery, Shamir)
NEW   Blob endpoints (uploadBlob, getBlob, listBlobs)
NEW   Milestone tags on all endpoint groups
REF   See unified-milestone-map.md for phase details
```

---

## Item 9: Replace Ed25519 with P-256/secp256k1

ATProto uses P-256 (secp256r1) and secp256k1. All Ed25519 references in the provisioning API are incorrect.

### Affected Locations

**Section 3 — POST /v1/devices request body:**

Current:
```
device_public_key  string  yes  Ed25519 public key, base64url-encoded
```

Change to:
```
device_public_key  string  yes  P-256 (secp256r1) public key, base64url-encoded
```

**Section 4 — POST /v1/dids/:did/rotate request body:**

Current:
```
new_public_key  string  yes  New Ed25519 public key, base64url-encoded
```

Change to:
```
new_public_key  string  yes  New P-256 public key, base64url-encoded
```

**Section 6.1 — Setup wizard step 1:**

Current:
```
Tauri generates an Ed25519 keypair and calls POST /v1/devices.
```

Change to:
```
Tauri generates a P-256 keypair and calls POST /v1/devices.
```

**Section 9.2 — Key Management:**

No explicit curve mention, but add clarification:
```
Device keys use P-256 (secp256r1). The relay signing key uses
P-256 or secp256k1 per ATProto spec. Ed25519 is NOT supported
by the ATProto network.
```

---

## Item 10: Rewrite DID Ceremony (POST /v1/dids)

The current spec has the client building a full DID document and submitting it. Per the mobile spec (canonical), the client sends key material and the relay constructs the DID document.

### Current Request Body

```
did_document   object  yes  W3C DID Document with verification methods
method         string  no   "did:plc" (default) or "did:web"
rotation_keys  array   no   Additional recovery keys for did:plc
```

### New Request Body

```
Field               Type    Required  Description
signing_pub_key     string  yes       P-256 public key for signing, base64url-encoded
rotation_pub_key    string  yes       P-256 public key for DID rotation, base64url-encoded
method              string  no        "did:plc" (default) or "did:web" (requires custom domain)
handle              string  no        Desired handle (if not already set via POST /v1/handles)
recovery_keys       array   no        Additional rotation keys for did:plc recovery
```

### Updated Description

```
Initiate a DID ceremony. The client submits key material (public keys
only — private keys never leave the device). The relay constructs the
DID document, including:
  - verification methods from submitted keys
  - service endpoint pointing to the relay
  - handle (atproto_handle alias)

For did:plc, the relay constructs and signs the genesis operation,
then submits it to plc.directory. For did:web, the relay begins
serving /.well-known/did.json through the user's custom domain.

The relay holds the signing key and uses it for all commit signing.
The rotation key stays on the device (Secure Enclave on iOS,
Keychain on macOS) and is only needed for DID recovery/rotation.
```

### Updated Response

Add field:
```
relay_signing_key_id  string  Identifier of the relay-generated signing key
```

### Updated Error Responses

Replace:
```
422  KEY_MISMATCH  DID document key doesn't match device's registered public key
```

With:
```
422  INVALID_KEY_FORMAT  Public key is malformed or not on a supported curve (P-256/secp256k1)
```

### Design Decision to Add

```
Design Decision: Relay constructs DID document
The client sends raw key material, not a pre-built DID document.
This ensures the relay controls the document structure, service
endpoints, and signing key binding. The client only needs to
provide public keys — no DID document assembly logic required
on the client side. This simplifies mobile clients significantly.
```

---

## Item 11: Add POST /v1/accounts/mobile

New endpoint for mobile account creation. Combines account creation + device binding + DID ceremony in a single call, avoiding the web dashboard → claim code → Tauri handoff flow.

### New Endpoint

```
POST /v1/accounts/mobile                                    [v0.1]

Combined account creation for mobile clients. Creates the account,
binds the device, generates the relay signing key, and initiates
the DID ceremony in one request. Replaces the multi-step web
dashboard flow for iOS users.

Request Body:
  Field               Type    Required  Description
  email               string  yes       User's email address
  password            string  yes       Minimum 12 characters
  display_name        string  no        Optional display name
  device_public_key   string  yes       P-256 public key from Secure Enclave
  device_name         string  no        e.g. "iPhone 15 Pro"
  rotation_pub_key    string  yes       P-256 rotation key (stays on device)
  handle              string  no        Desired handle (subdomain assigned if omitted)
  did_method          string  no        "did:plc" (default) or "did:web"

Response (200 OK):
  Field               Type    Description
  account_id          string  UUID v7 account identifier
  device_id           string  UUID v7 device identifier
  device_token        string  Long-lived opaque token
  session_token       string  JWT, 24-hour expiry
  did                 string  Fully qualified DID string
  did_document        object  The constructed DID document
  handle              string  Assigned handle
  relay_endpoint      object  Relay Endpoint Object (see §3.2)
  relay_signing_key   string  Key ID of the relay's signing key
  tier                string  Always "free" on creation

Error Responses:
  Status  Code              Description
  409     ACCOUNT_EXISTS    Email already registered
  422     WEAK_PASSWORD     Password doesn't meet requirements
  422     INVALID_KEY       Public key is malformed or unsupported curve
  409     HANDLE_TAKEN      Requested handle is already in use
  429     RATE_LIMITED      Too many signup attempts

Note: This endpoint performs Shamir share generation as part of
account creation. Share 1 is returned in the response for the
client to store in iCloud Keychain. Share 2 is escrowed at the
relay. Share 3 handling depends on user choice (communicated in
a follow-up call or during onboarding flow).

Additional Response Fields (Shamir):
  shamir_share_1      string  Encrypted share for iCloud Keychain storage
  shamir_share_3_options  array  Available storage methods for Share 3
```

---

## Item 12: Integrate 17 Endpoints from Mobile + Migration Specs

These endpoints are defined in the mobile and migration specs but missing from the provisioning API. They should be added as new sections.

### New Section: Relay Key Management

```
11. Relay Key Management                                    [v0.1]

The relay holds the ATProto signing key. These endpoints manage
the relay's key lifecycle.

POST /v1/relay/keys                                         [v0.1]
  Generate a new relay signing key. Called during account creation
  or key rotation. The relay generates the key internally — the
  private key is never exposed.

  Response (200 OK):
    key_id          string  Key identifier
    public_key      string  P-256 public key, base64url-encoded
    algorithm       string  "ES256" (P-256) or "ES256K" (secp256k1)
    created_at      string  ISO 8601

DELETE /v1/relay/keys/:keyId                                [v1.0]
  Revoke a relay signing key. Triggers DID rotation to update
  the signing key in the DID document.

  Response (200 OK):
    revoked_at      string  ISO 8601
    rotation_status string  "pending" | "complete"

POST /v1/relay/commits/sign                                 [v0.2]
  Sign an unsigned commit constructed by the desktop PDS.
  Desktop-enrolled mode only.

  Request Body:
    unsigned_commit  bytes   CAR-encoded unsigned commit
    repo_did         string  DID of the repo

  Response (200 OK):
    signed_commit    bytes   CAR-encoded signed commit
    commit_cid       string  CID of the signed commit

GET /v1/relay/repo/snapshot                                 [v0.2]
  Full repo export as CAR file. Used by desktop during initial
  sync after enrollment.

  Response: streaming CAR file (same format as com.atproto.sync.getRepo)

GET /v1/relay/mode                                          [v0.2]
  Current relay operating mode for this account.

  Response (200 OK):
    mode             string  "mobile-only" | "desktop-enrolled" | "desktop-offline"
    primary_device   string  Device ID of repo host (null in mobile-only)
    signing_key_id   string  Active signing key identifier
```

### New Section: Device Management (Mobile)

```
12. Device Management                                       [v0.2]

Extended device operations for the mobile app. These supplement
the existing device registration endpoints in §3.

POST /v1/devices/:id/pair                                   [v0.2]
  Initiate device pairing via QR code. The phone generates a
  pairing session, the desktop scans the QR code containing
  the session details.

  Request Body:
    pairing_code    string  Code from QR scan
    device_type     string  "desktop" | "mobile"

  Response (200 OK):
    paired_at       string  ISO 8601
    device_id       string  The paired device's ID
    pairing_status  string  "paired" | "pending_promotion"

POST /v1/devices/:id/promote                                [v0.2]
  Promote a paired desktop to repo host. Transitions the relay
  from mobile-only to desktop-enrolled mode. The relay transfers
  the repo to the desktop via Iroh.

  Response (200 OK):
    promoted_at     string  ISO 8601
    mode            string  "desktop-enrolled"
    repo_transfer   string  "in_progress" | "complete"

GET /v1/devices/:id/status                                  [v0.2]
  Device health and connectivity status.

  Response (200 OK):
    device_id       string  Device identifier
    status          string  "online" | "offline" | "degraded"
    last_seen       string  ISO 8601
    is_primary      boolean Whether this device hosts the repo
    mode            string  Current lifecycle phase

DELETE /v1/devices/:id                                      [v0.2]
  De-enroll a device. Already exists in §3 — this note confirms
  mobile app can also call it (not just web dashboard).

  Note: Update §3 to allow device_token auth (not just session_token)
  for mobile-initiated device removal.
```

### New Section: Data Transfer

```
13. Data Transfer                                           [v0.1]

Planned device swap (e.g., upgrading phones). Uses Iroh for
direct peer-to-peer transfer with a 6-digit verification code.

POST /v1/transfer/initiate                                  [v0.1]
  Generate a transfer session. Returns a 6-digit code for the
  new device to enter.

  Response (200 OK):
    transfer_id     string  Transfer session identifier
    code            string  6-digit verification code
    expires_at      string  ISO 8601 (15 minutes)
    iroh_ticket     string  Iroh connection ticket for direct transfer

POST /v1/transfer/accept                                    [v0.1]
  New device submits the transfer code to join the session.

  Request Body:
    code            string  6-digit code from old device
    device_public_key string P-256 public key of new device

  Response (200 OK):
    transfer_id     string  Transfer session ID
    status          string  "accepted" | "transferring"

POST /v1/transfer/complete                                  [v0.1]
  Finalize the transfer. Old device's token is revoked, new
  device receives a fresh device_token.

  Response (200 OK):
    new_device_id   string  New device's identifier
    device_token    string  New device's long-lived token
    old_device_revoked boolean  Confirmation old token is dead
```

### New Section: Recovery

```
14. Recovery                                                [v1.0]

Unplanned device loss recovery via Shamir share reconstruction.

POST /v1/recovery/initiate                                  [v1.0]
  Begin a recovery ceremony. User must present 2 of 3 Shamir
  shares to reconstruct the rotation key.

  Request Body:
    email           string  Account email for verification
    share_1         string  First Shamir share (e.g., from iCloud)
    share_source_1  string  "icloud" | "relay" | "device" | "paper"

  Response (200 OK):
    recovery_id     string  Recovery session identifier
    shares_needed   integer Number of additional shares required
    status          string  "awaiting_shares" | "ready_to_verify"

POST /v1/recovery/verify-key                                [v1.0]
  Submit reconstructed key material to prove DID ownership.

  Request Body:
    recovery_id     string  Recovery session ID
    share_2         string  Second Shamir share
    share_source_2  string  Source of the second share

  Response (200 OK):
    status          string  "verified" | "failed"
    rotation_key    string  Reconstructed rotation public key (for verification)

GET /v1/recovery/restore                                    [v1.0]
  Stream the repo and blobs from the relay to the new device
  after successful key verification.

  Response: streaming CAR file + blob manifest

PUT /v1/keys/shares/:id                                     [v1.0]
  Update the relay-held Shamir share (Share 2). Used after
  key rotation to re-split with new shares.

  Request Body:
    encrypted_share string  New encrypted share data

  Response (200 OK):
    updated_at      string  ISO 8601

GET /v1/keys/rotation-log                                   [v1.0]
  Immutable audit log of all Shamir share rotations and
  recovery attempts.

  Response (200 OK):
    entries         array   List of rotation/recovery events with timestamps
```

---

## Item 13: Fix Tier Model

### Section 1.4 — Rate Limiting Table

Current:
```
Self-Hosted  Unlimited  Unlimited  Configurable
```

Change to:
```
Business     300/min    1200/min   50 concurrent
```

And add a note:
```
Note: BYO relay operators configure their own rate limits.
BYO is a deployment model, not a subscription tier.
See §6.3 for BYO relay configuration.
```

### Section 2 — GET /v1/accounts/:id/usage

Current response field:
```
tier  string  Current tier: "free" | "pro" | "self_hosted"
```

Change to:
```
tier  string  Current tier: "free" | "pro" | "business"
```

### Section 8 — Free Tier Enforcement Table

Add Business column and remove Self-Hosted references. BYO operators don't hit the managed relay's enforcement — they run their own.

### Section 10.2 — Business Metrics

Current:
```
accounts_by_tier  Count of accounts per tier (free/pro/self-hosted)
```

Change to:
```
accounts_by_tier  Count of accounts per tier (free/pro/business)
```

---

## Item 14: Add Milestone Tags to All Endpoints

Every endpoint group should have a milestone badge. Here's the complete mapping:

### v0.1 — Mobile-Only PDS

```
POST /v1/accounts              Account creation (web)
POST /v1/accounts/mobile       Account creation (mobile) [NEW]
POST /v1/accounts/sessions     Login
POST /v1/accounts/claim-codes  Generate claim code
GET  /v1/accounts/:id/usage    Usage metrics
POST /v1/devices               Device registration
GET  /v1/devices/:id/relay     Relay endpoint discovery
POST /v1/dids                  DID ceremony
GET  /v1/dids/:did             DID resolution
POST /v1/handles               Handle creation
GET  /v1/handles/:handle/status Handle status
DELETE /v1/handles/:handle     Handle release
POST /v1/relay/keys            Generate relay signing key [NEW]
POST /v1/transfer/initiate     Device transfer [NEW]
POST /v1/transfer/accept       Device transfer [NEW]
POST /v1/transfer/complete     Device transfer [NEW]
```

### v0.2 — Desktop Enrollment

```
POST /v1/devices/:id/pair      Device pairing [NEW]
POST /v1/devices/:id/promote   Desktop promotion [NEW]
GET  /v1/devices/:id/status    Device health [NEW]
POST /v1/devices/:id/lease     Write lease management
POST /v1/relay/commits/sign    Commit signing [NEW]
GET  /v1/relay/repo/snapshot   Repo export [NEW]
GET  /v1/relay/mode            Operating mode [NEW]
```

### v1.0 — Production Launch

```
POST /v1/dids/:did/rotate      Key rotation
POST /v1/dids/:did/migrate     DID migration (exit)
GET  /v1/export/repo           Full repo export
DELETE /v1/accounts/:id        Account deletion
POST /v1/accounts/:id/restore  Cancel deletion
DELETE /v1/devices/:id         Device revocation
DELETE /v1/relay/keys/:keyId   Key revocation [NEW]
POST /v1/recovery/initiate     Recovery ceremony [NEW]
POST /v1/recovery/verify-key   Recovery verification [NEW]
GET  /v1/recovery/restore      Recovery restore [NEW]
PUT  /v1/keys/shares/:id       Share update [NEW]
GET  /v1/keys/rotation-log     Rotation audit [NEW]
```

---

## Item 15: Add Blob Endpoints

These are the provisioning API's view of blob operations. The full blob handling spec covers storage architecture; these are the XRPC-adjacent endpoints the relay serves.

```
15. Blob Management                                         [v0.1]

Blob endpoints follow the ATProto spec. See blob-handling-spec.md
for storage architecture and lifecycle details.

POST /v1/blobs/upload                                       [v0.1]
  Alias for com.atproto.repo.uploadBlob. Accepts multipart upload,
  returns CID reference. Subject to per-account storage quotas.

  Note: This is the same endpoint as the XRPC uploadBlob — listed
  here for completeness. The provisioning API does not add a
  separate blob upload path.

GET /v1/accounts/:id/storage                                [v0.1]
  Blob storage usage for an account. Extends the existing usage
  endpoint with blob-specific metrics.

  Response (200 OK):
    blob_count      integer  Total blobs stored
    blob_bytes      integer  Total blob storage consumed
    blob_limit      integer  Tier storage limit for blobs
    largest_blob    integer  Size of largest blob (bytes)
```

---

## Summary: New Endpoint Count

| Phase | Existing (v0.2) | New in v0.3 | Total |
|-------|-----------------|-------------|-------|
| v0.1 | 11 | 5 | 16 |
| v0.2 | 0 | 7 | 7 |
| v1.0 | 5 | 7 | 12 |
| **Total** | **16** | **19** | **35** |

The provisioning API grows from 16 untagged endpoints to 35 milestone-tagged endpoints across three phases.
