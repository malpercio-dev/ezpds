**Provisioning API**

Design Specification

Desktop PDS PDS Layer

Version 0.3 --- Mobile-First Reconciliation

March 2026

*v0.3 Changes — Mobile-First Reconciliation + Endpoint Consolidation*

*Reconciled with mobile architecture spec v1.2 (canonical) and migration spec v0.1.*
*All endpoints tagged with milestone phase.*

*FIX   Ed25519 → P-256/secp256k1 throughout (ATProto requirement)*
*FIX   DID ceremony: client sends key material, PDS constructs DID doc*
*FIX   Tier model: Free/Pro/Business + BYO as deployment model*
*NEW   POST /v1/accounts/mobile — combined mobile account creation*
*NEW   9 endpoints from mobile spec (PDS keys, device mgmt, signing)*
*NEW   8 endpoints from migration spec (transfer, recovery, Shamir)*
*NEW   Blob endpoints (uploadBlob, getBlob, listBlobs)*
*NEW   Milestone tags on all endpoint groups*

**CONFIDENTIAL**

1\. Overview

This document specifies the provisioning API for the Desktop PDS PDS layer. The API orchestrates five flows: account creation, device binding, DID ceremony, handle/domain setup, and account exit. Two client types consume the API: the web dashboard (account lifecycle, billing) and the Tauri desktop app (device binding, runtime operations).

All endpoints are served over HTTPS at the PDS's base URL. The API follows REST conventions with JSON request/response bodies. Authentication uses Bearer tokens with three scopes: account, session, and device.

1.1 Base URL

> https://PDS.{service-domain}/v1

1.2 Identity Model

The PDS supports two DID methods. The choice is made during the setup wizard and cannot be changed after the DID ceremony completes.

  ------------ ------------- ----------------------------------- ---------------------------------------------------------------------------------------------
  **Method**   **Default**   **Requirement**                     **Exit Story**
  did:plc      Yes           Available to all tiers              User signs a PLC operation to repoint service endpoint. Clean exit, zero ongoing liability.
  did:web      No            Custom domain required (Pro tier)   User controls the domain, repoints DNS at new PDS. Zero ongoing liability.
  ------------ ------------- ----------------------------------- ---------------------------------------------------------------------------------------------

> ***Design Decision:** did:web is only available to users who bring their own domain. Subdomain-based did:web is not offered because it creates exit liability --- the PDS would be obligated to host the DID document indefinitely after the user leaves.*

1.3 Authentication Model

The API uses three token types, each scoped to a specific client and lifetime:

  ---------------- --------------------- ---------------------------- --------------------------------------------
  **Token**        **Issued To**         **Lifetime**                 **Scope**
  session\_token   Web dashboard         24 hours (renewable)         Account management, billing, handle config
  device\_token    Tauri app             Long-lived (until revoked)   PDS connection, DID ops, sync
  claim\_code      Web → Tauri handoff   15 minutes (single-use)      Device registration only
  ---------------- --------------------- ---------------------------- --------------------------------------------

All authenticated requests must include the token in the Authorization header:

> Authorization: Bearer {token}
>
> ***Design Decision:** All users authenticate through the web dashboard, including self-hosted PDS operators. There is no static\_token bypass. One auth path means one security model to audit.*

1.4 Rate Limiting

All endpoints are rate-limited per token. Free-tier accounts have stricter limits. When a limit is hit, the API returns 429 Too Many Requests with a Retry-After header.

  ------------- ------------ ----------- ---------------
  **Tier**      **Writes**   **Reads**   **Burst**
  Free          30/min       120/min     5 concurrent
  Pro           120/min      600/min     20 concurrent
  Business      300/min      1200/min    50 concurrent
  ------------- ------------ ----------- ---------------

Note: BYO PDS operators configure their own rate limits. BYO is a deployment model, not a subscription tier. See §6.3 for BYO PDS configuration.

1.5 Error Envelope

All error responses use a consistent JSON envelope:

> {
>
> \"error\": {
>
> \"code\": \"ACCOUNT\_EXISTS\",
>
> \"message\": \"An account with this email already exists.\",
>
> \"details\": { \... } // optional, endpoint-specific
>
> }
>
> }

2\. Account Lifecycle

Account endpoints are consumed by the web dashboard. They handle signup, authentication, and account management. Accounts start on the free tier with usage caps enforced at the PDS level.

**POST /v1/accounts**                                [v0.1]

Create a new account. Returns session credentials and a one-time claim code for device binding.

**Request Body**

  --------------- ---------- -------------- -----------------------
  **Field**       **Type**   **Required**   **Description**
  email           string     yes            User's email address
  password        string     yes            Minimum 12 characters
  display\_name   string     no             Optional display name
  --------------- ---------- -------------- -----------------------

**Response (200 OK)**

  ---------------- ---------- --------------------------------------------
  **Field**        **Type**   **Description**
  account\_id      string     UUID v7 account identifier
  session\_token   string     JWT, 24-hour expiry
  claim\_code      string     6-character alphanumeric, 15-minute expiry
  tier             string     Always \"free\" on creation
  ---------------- ---------- --------------------------------------------

**Error Responses**

  ------------ ----------------- ---------------------------------------
  **Status**   **Code**          **Description**
  409          ACCOUNT\_EXISTS   Email already registered
  422          WEAK\_PASSWORD    Password doesn't meet requirements
  429          RATE\_LIMITED     Too many signup attempts from this IP
  ------------ ----------------- ---------------------------------------

> ***Note:** The claim\_code is displayed in the web dashboard for the user to paste into their Tauri app. It is single-use and expires after 15 minutes. A new one can be generated via POST /v1/accounts/claim-codes.*

**POST /v1/accounts/mobile**                                [v0.1]

Combined account creation for mobile clients. Creates the account, binds the device, generates the PDS signing key, and initiates the DID ceremony in one request. Replaces the multi-step web dashboard flow for iOS users.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  email                   string     yes            User's email address
  password                string     yes            Minimum 12 characters
  display_name            string     no             Optional display name
  device_public_key       string     yes            P-256 public key from Secure Enclave
  device_name             string     no             e.g. "iPhone 15 Pro"
  rotation_pub_key        string     yes            P-256 rotation key (stays on device)
  handle                  string     no             Desired handle (subdomain assigned if omitted)
  did_method              string     no             "did:plc" (default) or "did:web"
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  account_id              string     UUID v7 account identifier
  device_id               string     UUID v7 device identifier
  device_token            string     Long-lived opaque token
  session_token           string     JWT, 24-hour expiry
  did                     string     Fully qualified DID string
  did_document            object     The constructed DID document
  handle                  string     Assigned handle
  pds_endpoint          object     PDS Endpoint Object (see §3.2)
  pds_signing_key       string     Key ID of the PDS's signing key
  tier                    string     Always "free" on creation
  shamir_share_1          string     Encrypted share for iCloud Keychain storage
  shamir_share_3_options  array      Available storage methods for Share 3
  ----------------------- ---------- -------------------------------------------------------

**Error Responses**

  ------------ ----------------------- -------------------------------------------------------
  **Status**   **Code**                **Description**
  409          ACCOUNT_EXISTS          Email already registered
  422          WEAK_PASSWORD           Password doesn't meet requirements
  422          INVALID_KEY             Public key is malformed or unsupported curve
  409          HANDLE_TAKEN            Requested handle is already in use
  429          RATE_LIMITED            Too many signup attempts
  ------------ ----------------------- -------------------------------------------------------

Note: This endpoint performs Shamir share generation as part of account creation. Share 1 is returned in the response for the client to store in iCloud Keychain. Share 2 is escrowed at the PDS. Share 3 handling depends on user choice (communicated in a follow-up call or during onboarding flow).

**POST /v1/accounts/sessions**                        [v0.1]

Authenticate and obtain a session token. Supports email/password and refresh token flows.

**Request Body**

  ---------------- ---------- -------------- ----------------------------------------
  **Field**        **Type**   **Required**   **Description**
  email            string     yes\*          Required for password auth
  password         string     yes\*          Required for password auth
  refresh\_token   string     yes\*          Alternative: renew an existing session
  ---------------- ---------- -------------- ----------------------------------------

**Response (200 OK)**

  ---------------- ---------- -----------------------------
  **Field**        **Type**   **Description**
  session\_token   string     JWT, 24-hour expiry
  refresh\_token   string     Opaque token, 30-day expiry
  account\_id      string     UUID v7
  ---------------- ---------- -----------------------------

**Error Responses**

  ------------ ---------------------- ---------------------------
  **Status**   **Code**               **Description**
  401          INVALID\_CREDENTIALS   Email/password mismatch
  401          TOKEN\_EXPIRED         Refresh token has expired
  423          ACCOUNT\_LOCKED        Too many failed attempts
  ------------ ---------------------- ---------------------------

**POST /v1/accounts/claim-codes**                    [v0.1]

Generate a new device claim code. Invalidates any previously active claim code for this account.

**Response (200 OK)**

  ------------- ---------- --------------------------------------------
  **Field**     **Type**   **Description**
  claim\_code   string     6-character alphanumeric, 15-minute expiry
  expires\_at   string     ISO 8601 timestamp
  ------------- ---------- --------------------------------------------

**Error Responses**

  ------------ --------------- ----------------------------------
  **Status**   **Code**        **Description**
  401          UNAUTHORIZED    Invalid or missing session token
  429          RATE\_LIMITED   Max 5 claim codes per hour
  ------------ --------------- ----------------------------------

> ***Note:** Requires session\_token authentication.*

**GET /v1/accounts/:id/usage**                        [v0.1]

Returns usage metrics for the account. `:id` is the account DID. Operator-only: requires the admin token. Reports on the account regardless of activation state (a deactivated account still has usage figures).

**Response (200 OK)** — fields are camelCase, matching the rest of the /v1 API.

  ---------------- ---------- -------------------------------------------------------
  **Field**        **Type**   **Description**
  recordsCount     integer    Total records across every collection in the repo (0 when empty or no repo)
  commitsCount     integer    Distinct commit revisions still represented among the account\'s blocks. GC reclaims superseded blocks, so this is a lower bound on the full commit history, not an exact total.
  blobsCount       integer    Number of blobs stored for the account
  storageBytes     integer    Total bytes stored: repo block bytes plus blob bytes
  lastActive       string     ISO 8601 of the most recent repo-block write or blob upload; falls back to the account\'s creation time when it has neither
  ---------------- ---------- -------------------------------------------------------

**Error Responses**

  ------------ -------------- --------------------------------
  **Status**   **Code**       **Description**
  401          UNAUTHORIZED   Missing or invalid admin token
  404          NOT\_FOUND     No account exists for the DID
  ------------ -------------- --------------------------------

> ***Note:** Richer billing/tier metrics (tier, billing period, bandwidth, proxied request counts) are future work and not part of the v0.1 contract.*

3\. Device Registration

Device endpoints are consumed by the Tauri app. The claim code handoff binds a specific device to an account, and the device\_token becomes the app's long-lived credential for all PDS interactions.

3.1 Multi-Device Model

Pro accounts support up to 5 devices. To maintain a linear commit chain on the ATProto repo (required for federation), the PDS enforces a primary-device model with lease-based write ownership.

-   **Primary device:** Holds the write lease. Can commit to the repo, push to the PDS, and trigger federation events.

-   **Secondary devices:** Read-only replicas that sync from the PDS. They see the full repo but cannot commit. A secondary can request promotion to primary.

-   **Lease transfer:** Explicit via the web dashboard or Tauri app. The current primary relinquishes the lease, the requesting device acquires it. If the primary is offline for longer than the lease TTL (configurable, default 24 hours), the lease expires and any device can claim it.

> ***Design Decision:** Primary-device with lease was chosen over last-write-wins or conflict queues. LWW risks lost writes on rebase; conflict queues require users to resolve Merkle tree forks. Primary-device sidesteps the problem entirely and matches how most people use desktop apps.*

**POST /v1/devices**                                   [v0.1]

Register a device by redeeming a claim code. The Tauri app generates a keypair locally and sends the public key. The PDS binds the device and returns a device token. The first device registered to an account automatically receives the primary write lease.

**Request Body**

  --------------------- ---------- -------------- --------------------------------------------
  **Field**             **Type**   **Required**   **Description**
  claim\_code           string     yes            6-character code from web dashboard
  device\_public\_key   string     yes            P-256 (secp256r1) public key, base64url-encoded
  device\_name          string     no             Human-readable label, e.g. \"MacBook Pro\"
  os                    string     no             Operating system identifier
  app\_version          string     no             Tauri app version string
  --------------------- ---------- -------------- --------------------------------------------

**Response (200 OK)**

  ----------------- ---------- -------------------------------------------
  **Field**         **Type**   **Description**
  device\_id        string     UUID v7 device identifier
  device\_token     string     Long-lived opaque token
  account\_id       string     Bound account UUID
  is\_primary       boolean    Whether this device holds the write lease
  PDS\_endpoint   object     See PDS Endpoint Object below
  ----------------- ---------- -------------------------------------------

**Error Responses**

  ------------ ---------------- ---------------------------------------------------
  **Status**   **Code**         **Description**
  400          INVALID\_CLAIM   Claim code is invalid, expired, or already used
  409          DEVICE\_LIMIT    Account has reached maximum device count for tier
  422          INVALID\_KEY     Public key is malformed or unsupported curve
  ------------ ---------------- ---------------------------------------------------

> ***Note:** The device private key never leaves the Tauri app. The PDS stores only the public key for challenge-response verification during reconnection.*

3.2 PDS Endpoint Object

Returned by device registration and the PDS info endpoint:

  ---------------- ---------- --------------------------------------------
  **Field**        **Type**   **Description**
  host             string     PDS hostname
  port             integer    PDS port (typically 443)
  iroh\_node\_id   string     Iroh node identifier for direct connection
  region           string     PDS region code, e.g. \"us-east-1\"
  protocol         string     Connection protocol: \"iroh\" \| \"wss\"
  ---------------- ---------- --------------------------------------------

**GET /v1/devices/:id/pds**                         [v0.1]

Retrieve the assigned PDS endpoint for a device. Used by the Tauri app on startup to discover where to connect.

**Response (200 OK)**

  ----------------- ---------- ---------------------------------------------------------
  **Field**         **Type**   **Description**
  PDS\_endpoint   object     PDS Endpoint Object (see 3.2)
  status            string     PDS status: \"online\" \| \"degraded\" \| \"offline\"
  buffer\_depth     integer    Messages buffered while device was offline
  ----------------- ---------- ---------------------------------------------------------

**Error Responses**

  ------------ -------------------- ----------------------------------------
  **Status**   **Code**             **Description**
  401          UNAUTHORIZED         Invalid device token
  404          DEVICE\_NOT\_FOUND   Device ID doesn't exist or was revoked
  ------------ -------------------- ----------------------------------------

**POST /v1/devices/:id/lease**                       [v1.0]

Request or release the primary write lease for a device.

**Request Body**

  ----------- ---------- -------------- ----------------------------
  **Field**   **Type**   **Required**   **Description**
  action      string     yes            \"acquire\" or \"release\"
  ----------- ---------- -------------- ----------------------------

**Response (200 OK)**

  -------------------- ---------- ---------------------------------------------------------------
  **Field**            **Type**   **Description**
  is\_primary          boolean    Whether this device now holds the lease
  lease\_expires\_at   string     ISO 8601, when the lease auto-expires if not renewed
  previous\_primary    string     Device ID of the previous primary (null if lease was expired)
  -------------------- ---------- ---------------------------------------------------------------

**Error Responses**

  ------------ ---------------------- ---------------------------------------------------------------------------------
  **Status**   **Code**               **Description**
  409          LEASE\_HELD            Another device holds an active lease. Must wait for expiry or explicit release.
  403          SINGLE\_DEVICE\_TIER   Free tier accounts have only one device; lease management is not applicable.
  ------------ ---------------------- ---------------------------------------------------------------------------------

> ***Note:** The Tauri app should silently renew the lease by calling this endpoint periodically (recommended: every 6 hours). If the primary device is offline beyond the lease TTL (default 24h), any other device can acquire the lease.*

**DELETE /v1/devices/:id**                              [v1.0]

Revoke a device. Invalidates its device\_token and disconnects it from the PDS. If the revoked device was primary, the lease is released. Buffered messages are held for 72 hours before purging.

**Response (200 OK)**

  ------------------- ---------- -----------------------------------------------------------
  **Field**           **Type**   **Description**
  revoked\_at         string     ISO 8601 timestamp
  buffer\_purge\_at   string     ISO 8601, when buffered messages will be deleted
  lease\_released     boolean    Whether the primary lease was released by this revocation
  ------------------- ---------- -----------------------------------------------------------

**Error Responses**

  ------------ -------------- -------------------------------
  **Status**   **Code**       **Description**
  401          UNAUTHORIZED   Invalid token
  403          FORBIDDEN      Token doesn't own this device
  ------------ -------------- -------------------------------

> ***Note:** Requires session\_token (web dashboard). Device tokens cannot self-revoke.*

4\. DID Ceremony

The DID ceremony binds a decentralized identifier to the user's device and PDS. The Tauri app generates the DID document locally (the private key never leaves the device) and submits it to the PDS for registration. The DID is the user's identity --- the follow graph, repo, and all social connections reference it. There is no such thing as migrating from one DID to another; that would be creating a new account.

4.1 PLC Mirror

The PDS operates a PLC directory mirror to improve resolution speed and provide resilience against upstream outages. The mirror starts as read-only (caching and serving existing PLC documents) and may graduate to a read-write authority in a future version.

  ----------- ---------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Phase**   **Mode**               **Behavior**
  v1.0        Read-only cache        Mirrors the PLC directory. Serves cached DID documents for faster resolution. Falls back to upstream plc.directory if cache misses. Provides resilience if upstream is temporarily unavailable.
  Future      Read-write authority   Can accept and validate new PLC operations independently. Participates in the PLC directory network as a peer.
  ----------- ---------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

> ***Note:** New DID operations (creation, rotation) are submitted to plc.directory via the PDS as a proxy in v1.0. The mirror is purely for read-side performance and resilience.*

**POST /v1/dids**                                      [v0.1]

Initiate a DID ceremony. The client submits key material (public keys only — private keys never leave the device). The PDS constructs the DID document, including verification methods from submitted keys, service endpoint pointing to the PDS, and handle (atproto_handle alias).

For did:plc, the PDS constructs and signs the genesis operation, then submits it to plc.directory. For did:web, the PDS begins serving /.well-known/did.json through the user's custom domain.

The PDS holds the signing key and uses it for all commit signing. The rotation key stays on the device (Secure Enclave on iOS, Keychain on macOS) and is only needed for DID recovery/rotation.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  signing_pub_key         string     yes            P-256 public key for signing, base64url-encoded
  rotation_pub_key        string     yes            P-256 public key for DID rotation, base64url-encoded
  method                  string     no             "did:plc" (default) or "did:web" (requires custom domain)
  handle                  string     no             Desired handle (if not already set via POST /v1/handles)
  recovery_keys           array      no             Additional rotation keys for did:plc recovery
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  did                     string     Fully qualified DID string
  did_document            object     W3C DID Document
  pds_signing_key_id    string     Identifier of the PDS-generated signing key
  ----------------------- ---------- -------------------------------------------------------

**Error Responses**

  ------------ -------------------------------- -------------------------------------------------------
  **Status**   **Code**                         **Description**
  409          ACCOUNT_NOT_FOUND                Account does not exist
  422          INVALID_KEY_FORMAT               Public key is malformed or not on supported curve (P-256/secp256k1)
  422          UNSUPPORTED_DID_METHOD           Requested method is not supported or missing required fields
  429          RATE_LIMITED                     Too many DID ceremonies initiated
  ------------ -------------------------------- -------------------------------------------------------

> ***Note:** For did:plc, the PDS submits the signed genesis operation to plc.directory and status will be "pending_propagation" until confirmed. For did:web, the PDS begins serving /.well-known/did.json through the user's custom domain.*

**GET /v1/dids/:did**                                  [v0.1]

Retrieve the current DID document and resolution status. For did:plc, resolution checks the PLC mirror first, then falls back to upstream.

**Response (200 OK)**

  ------------------- ---------- -----------------------------------------------------------
  **Field**           **Type**   **Description**
  did                 string     Fully qualified DID string
  did\_document       object     Current DID document
  method              string     \"did:plc\" \| \"did:web\"
  status              string     \"active\" \| \"pending\_propagation\" \| \"deactivated\"
  resolution\_url     string     Public resolution URL
  last\_rotated\_at   string     ISO 8601, last key rotation timestamp
  mirror\_age\_ms     integer    For did:plc: staleness of the PLC mirror cache entry
  ------------------- ---------- -----------------------------------------------------------

**Error Responses**

  ------------ ----------------- ---------------------------------
  **Status**   **Code**          **Description**
  404          DID\_NOT\_FOUND   DID doesn't exist in this PDS
  ------------ ----------------- ---------------------------------

**POST /v1/dids/:did/rotate**                        [v1.0]

Rotate the signing key for a DID. The Tauri app generates a new keypair, signs the rotation operation with the current key, and submits it. Critical for key compromise recovery.

**Request Body**

  ------------------ ---------- -------------- --------------------------------------------------------
  **Field**          **Type**   **Required**   **Description**
  new\_public\_key   string     yes            New P-256 (secp256r1) public key, base64url-encoded
  rotation\_proof    string     yes            Signed proof from the current key authorizing rotation
  ------------------ ---------- -------------- --------------------------------------------------------

**Response (200 OK)**

  --------------------- ---------- ----------------------------------------
  **Field**             **Type**   **Description**
  did\_document         object     Updated DID document with new key
  previous\_key\_hash   string     Hash of the rotated-out key for audit
  status                string     \"active\" \| \"pending\_propagation\"
  --------------------- ---------- ----------------------------------------

**Error Responses**

  ------------ ------------------------ -------------------------------------
  **Status**   **Code**                 **Description**
  400          INVALID\_PROOF           Rotation proof signature is invalid
  409          ROTATION\_IN\_PROGRESS   A rotation is already pending
  ------------ ------------------------ -------------------------------------

> ***Note:** Key rotation also updates the device's registered public key at the PDS. For did:plc, the signed rotation operation is submitted to plc.directory. The old key remains valid for challenge-response for a 24-hour grace period to handle in-flight requests.*

5\. Handle & Domain Management

Handle endpoints manage the user's ATProto handle (e.g., alice.yourservice.net or alice.com). Free-tier users get a subdomain on the service domain. Pro users can bring their own domain. The PDS automates DNS record provisioning via Cloudflare or Route53.

> ***Note:** Custom domains serve double duty: they are required for both custom handles AND did:web identity. When a Pro user verifies a custom domain, both the handle and the did:web option become available in the setup wizard.*

**POST /v1/handles**                                   [v0.1]

Request a handle. For subdomain handles, the PDS provisions DNS immediately. For custom domains, the PDS returns required DNS records for the user to configure.

**Request Body**

  ----------- ---------- -------------- --------------------------------------------------------------------------
  **Field**   **Type**   **Required**   **Description**
  handle      string     yes            Desired handle (e.g., \"alice\" for subdomain, \"alice.com\" for custom)
  type        string     no             \"subdomain\" (default) or \"custom\"
  ----------- ---------- -------------- --------------------------------------------------------------------------

**Response (200 OK)**

  --------------------- ---------- -------------------------------------------------------------
  **Field**             **Type**   **Description**
  handle                string     Full handle (e.g., \"alice.PDS.example.net\")
  type                  string     \"subdomain\" \| \"custom\"
  status                string     \"active\" \| \"pending\_dns\" \| \"pending\_verification\"
  dns\_records          array      Required DNS records (for custom domains)
  verification\_token   string     TXT record value for domain ownership proof
  didweb\_eligible      boolean    Whether this domain unlocks did:web as a DID method option
  --------------------- ---------- -------------------------------------------------------------

**Error Responses**

  ------------ ------------------ ---------------------------------------------------
  **Status**   **Code**           **Description**
  409          HANDLE\_TAKEN      Handle is already in use
  403          TIER\_RESTRICTED   Custom domains require Pro tier
  422          INVALID\_HANDLE    Handle contains invalid characters or is reserved
  ------------ ------------------ ---------------------------------------------------

5.1 DNS Records Object

For custom domains, the response includes an array of DNS records the user must create:

  -------------- ---------- ------------------------------------------------
  **Field**      **Type**   **Description**
  record\_type   string     DNS record type: \"CNAME\" \| \"TXT\" \| \"A\"
  name           string     Record name (e.g., \"\_atproto.alice.com\")
  value          string     Record value
  ttl            integer    Recommended TTL in seconds
  -------------- ---------- ------------------------------------------------

**GET /v1/handles/:handle/status**                 [v0.1]

Poll DNS propagation and verification status for a handle. The Tauri app and web dashboard poll this endpoint after handle creation.

**Response (200 OK)**

  ----------------- ---------- ---------------------------------------------------------------------------
  **Field**         **Type**   **Description**
  handle            string     The handle being checked
  status            string     \"active\" \| \"pending\_dns\" \| \"pending\_verification\" \| \"failed\"
  dns\_checks       array      Per-record check results with pass/fail and last\_checked timestamps
  verified\_at      string     ISO 8601, null until verified
  failure\_reason   string     Present only if status is \"failed\"
  ----------------- ---------- ---------------------------------------------------------------------------

**Error Responses**

  ------------ -------------------- ---------------------------------------
  **Status**   **Code**             **Description**
  404          HANDLE\_NOT\_FOUND   Handle doesn't exist for this account
  ------------ -------------------- ---------------------------------------

> ***Note:** For subdomain handles, status transitions directly to \"active\". For custom domains, expect 5--30 minutes for DNS propagation. The PDS checks every 60 seconds.*

**DELETE /v1/handles/:handle**                       [v0.1]

Release a handle. For subdomain handles, the DNS record is removed immediately. For custom domains, the PDS stops serving resolution but does not modify the user's DNS.

**Response (200 OK)**

  ----------------- ---------- ---------------------------------------------------------------
  **Field**         **Type**   **Description**
  released\_at      string     ISO 8601 timestamp
  cooldown\_until   string     ISO 8601, handle is reserved for 30 days to prevent squatting
  ----------------- ---------- ---------------------------------------------------------------

**Error Responses**

  ------------ -------------- -------------------------------
  **Status**   **Code**       **Description**
  401          UNAUTHORIZED   Invalid token
  403          FORBIDDEN      Token doesn't own this handle
  ------------ -------------- -------------------------------

6\. Setup Wizard Flow

The Tauri app includes a first-run setup wizard that guides the user through the complete provisioning flow in a single sitting. The wizard orchestrates the API calls described in sections 2--5 into a linear, non-technical experience.

6.1 Wizard Steps

1.  **Enter claim code** --- User copies the 6-character code from the web dashboard. Tauri generates a P-256 keypair and calls POST /v1/devices.

2.  **Choose a handle** --- Wizard offers a subdomain handle immediately. If the account has a verified custom domain (Pro tier), the custom domain option also appears. Calls POST /v1/handles.

3.  **DID ceremony** --- Wizard pre-selects did:plc. If the user selected a custom domain handle in step 2, a toggle appears offering did:web as an alternative. Wizard prompts for optional recovery key setup (Shamir shares). Calls POST /v1/dids.

4.  **Wait for propagation** --- Wizard polls GET /v1/dids/:did and GET /v1/handles/:handle/status until both are active. Shows a progress indicator with estimated time.

5.  **Federation handshake** --- PDS calls requestCrawl to the BGS. Wizard confirms the PDS is discoverable on the ATProto network. Displays a \"You're live\" confirmation.

6.2 Failure Recovery

Each wizard step is independently retryable. If the Tauri app loses connection or is closed mid-wizard, it resumes from the last completed step on next launch. The wizard state is persisted locally.

  ---------------------------- ------------------------------------------------------------------------
  **Failure Point**            **Recovery**
  Claim code expired           Generate new code via web dashboard; wizard restarts at step 1
  Device registration failed   Retry with a new claim code
  Handle taken                 Wizard prompts for an alternative handle
  DID propagation timeout      Wizard continues polling; user can skip and check later
  DNS verification timeout     Wizard shows manual DNS instructions; polling continues in background
  PDS unreachable            Tauri retries with exponential backoff; wizard shows connection status
  ---------------------------- ------------------------------------------------------------------------

6.3 BYO PDS Configuration

Self-hosted users who run their own PDS can point the Tauri app at their PDS before entering the setup wizard. The wizard writes a config file that the app reads on subsequent launches.

6.3.1 Config File

  --------------- ----------------------------
  **Platform**    **Path**
  macOS / Linux   \~/.config/pds/pds.toml
  Windows         %APPDATA%\\pds\\pds.toml
  --------------- ----------------------------

Minimal config shape:

> \[PDS\]
>
> url = \"https://my-PDS.example.com\"
>
> iroh\_node\_id = \"abc123\...\" \# optional, discovered via API
>
> \# Auth method is always claim\_code (web dashboard flow)

If the config file exists when the Tauri app launches for the first time, the wizard uses the configured PDS URL instead of the default managed service. All subsequent wizard steps (claim code, device binding, DID ceremony) proceed identically.

7\. Exit Ceremony

The exit ceremony allows a user to leave the PDS and take their identity and data with them. The DID is the user's identity --- what moves is the PDS hosting, not the identity itself. The follow graph, followers, and all social connections remain intact because the DID never changes.

> ***Design Decision:** The exit story is a sovereignty requirement, not an afterthought. If users can't leave cleanly, the product's sovereignty promise is hollow.*

7.1 Exit Flow

6.  **Export repo** --- User downloads a full CAR file of their ATProto repo via the export endpoint. This is the portable data package.

7.  **Prepare new PDS** --- User imports the CAR file into their new PDS host (outside the scope of this API, but the export format follows the ATProto spec for com.atproto.sync.getRepo).

8.  **Repoint DID** --- For did:plc: user signs a PLC operation updating the service endpoint to their new PDS. The PDS submits this to plc.directory. For did:web: user updates their domain's DNS / .well-known/did.json to point to the new PDS. No PDS involvement needed.

9.  **Grace period** --- The PDS continues serving the repo and forwarding requests for 30 days after the DID repoints. This gives the network time to update resolution caches and ensures no dropped interactions during transition.

10. **Account teardown** --- After the grace period (or immediately if the user confirms), the PDS purges the repo data, revokes all device tokens, and marks the account as closed.

**GET /v1/export/repo**                                [v1.0]

Export the full ATProto repo as a CAR (Content Addressable aRchive) file. This is a potentially large download --- the PDS streams the response.

**Response (200 OK)**

  --------------------- ---------- --------------------------------------------------
  **Field**             **Type**   **Description**
  Content-Type          header     application/vnd.ipld.car
  Content-Disposition   header     attachment; filename=\"{did}.car\"
  X-Repo-Rev            header     The repo revision (commit CID) at time of export
  --------------------- ---------- --------------------------------------------------

**Error Responses**

  ------------ ---------------------- ----------------------------------------------------
  **Status**   **Code**               **Description**
  401          UNAUTHORIZED           Invalid token
  503          EXPORT\_IN\_PROGRESS   Another export is already running for this account
  ------------ ---------------------- ----------------------------------------------------

> ***Note:** Requires device\_token from the primary device, or session\_token. The response is streamed --- clients should handle large payloads. Recommended: pipe to disk rather than buffering in memory.*

**POST /v1/dids/:did/migrate**                       [v1.0]

Construct and submit a signed DID operation that repoints the service endpoint to a new PDS. For did:plc, this submits the operation to plc.directory. For did:web, this is a no-op (the user controls their own DNS).

**Request Body**

  ------------------------ ---------- -------------- ------------------------------------------------------------
  **Field**                **Type**   **Required**   **Description**
  new\_service\_endpoint   string     yes            URL of the new PDS (e.g., \"https://pds.alice.com\")
  signing\_proof           string     yes            Proof signed by the device's key authorizing the migration
  ------------------------ ---------- -------------- ------------------------------------------------------------

**Response (200 OK)**

  ------------------------ ---------- -----------------------------------------------------
  **Field**                **Type**   **Description**
  did                      string     The DID that was migrated
  new\_service\_endpoint   string     The endpoint now in the DID document
  operation\_id            string     PLC operation ID (for did:plc)
  status                   string     \"pending\_propagation\" \| \"active\"
  grace\_period\_ends      string     ISO 8601, when the PDS stops serving the old repo
  ------------------------ ---------- -----------------------------------------------------

**Error Responses**

  ------------ ------------------------- -------------------------------------------------------------------------
  **Status**   **Code**                  **Description**
  400          INVALID\_PROOF            Signing proof is invalid
  400          INVALID\_ENDPOINT         New service endpoint is unreachable or malformed
  409          MIGRATION\_IN\_PROGRESS   A migration is already pending for this DID
  422          DIDWEB\_SELF\_SERVICE     did:web migration is handled via user's own DNS; no PDS action needed
  ------------ ------------------------- -------------------------------------------------------------------------

> ***Note:** The PDS validates that the new service endpoint is reachable and responds to basic ATProto XRPC calls before submitting the PLC operation. This prevents accidental lockout from typos.*

**DELETE /v1/accounts/:id**                            [v1.0]

Initiate account teardown. By default, enters a 30-day grace period during which the PDS continues serving the repo. The user can force immediate deletion by passing force=true.

**Request Body**

  -------------- ---------- -------------- ----------------------------------------------------------------------------
  **Field**      **Type**   **Required**   **Description**
  force          boolean    no             Skip grace period and delete immediately (default: false)
  confirmation   string     yes            Must be the string \"DELETE {account\_id}\" to prevent accidental deletion
  -------------- ---------- -------------- ----------------------------------------------------------------------------

**Response (200 OK)**

  --------------------- ---------- --------------------------------------------------------------
  **Field**             **Type**   **Description**
  status                string     \"grace\_period\" \| \"deleted\"
  grace\_period\_ends   string     ISO 8601, when data will be purged (null if force=true)
  devices\_revoked      integer    Number of device tokens invalidated
  data\_purge\_at       string     ISO 8601, when repo and account data are permanently deleted
  --------------------- ---------- --------------------------------------------------------------

**Error Responses**

  ------------ ----------------------- ----------------------------------------------------
  **Status**   **Code**                **Description**
  401          UNAUTHORIZED            Invalid session token
  400          INVALID\_CONFIRMATION   Confirmation string doesn't match
  409          ACTIVE\_MIGRATION       Cannot delete while a DID migration is in progress
  ------------ ----------------------- ----------------------------------------------------

> ***Note:** Requires session\_token. During the grace period, the account is read-only: the PDS serves existing repo data and DID resolution but rejects new commits. The user can cancel the deletion during this period via POST /v1/accounts/:id/restore.*

**POST /v1/accounts/:id/restore**                     [v1.0]

Cancel a pending account deletion during the grace period. Restores full write access and re-activates device tokens.

**Response (200 OK)**

  ------------------- ---------- -------------------------------------
  **Field**           **Type**   **Description**
  status              string     \"active\"
  devices\_restored   integer    Number of device tokens reactivated
  ------------------- ---------- -------------------------------------

**Error Responses**

  ------------ ------------------------ -----------------------------------------------------
  **Status**   **Code**                 **Description**
  401          UNAUTHORIZED             Invalid session token
  404          NOT\_IN\_GRACE\_PERIOD   Account is not currently in a deletion grace period
  410          ALREADY\_DELETED         Grace period has expired; data has been purged
  ------------ ------------------------ -----------------------------------------------------

8\. Free Tier Enforcement

Usage is tracked at the PDS level and enforced per-account. When a cap is reached, the PDS returns 429 on write operations but continues serving reads (eventually consistent). This ensures the PDS remains visible on the network even when the account is over quota.

  ----------------------- --------------- --------------- -----------------------------------------
  **Resource**            **Free Tier**   **Pro Tier**    **Enforcement**
  Repo storage            500 MB          50 GB           Reject commits over limit
  PDS bandwidth         2 GB/month      100 GB/month    Throttle to 128 kbps over limit
  XRPC proxied requests   10,000/month    500,000/month   429 on writes, reads continue
  Devices per account     1               5               Reject new device registrations
  Custom domains          0               3               Reject handle creation with type=custom
  ----------------------- --------------- --------------- -----------------------------------------

Approaching-limit warnings are surfaced through the usage endpoint (GET /v1/accounts/:id/usage), via a custom X-Usage-Warning response header when utilization exceeds 80%, and through the Iroh channel as push notifications to the Tauri app.

Critical account events (usage at 90%, device revoked, DID rotation) trigger email notifications to the account's registered email address. This does not require a user-facing event API.

9\. Security Considerations

9.1 Token Security

-   Session tokens are JWTs signed with RS256. The PDS's public key is published at /.well-known/jwks.json.

-   Device tokens are opaque (server-side lookup), not JWTs, to allow instant revocation without token refresh lag.

-   Claim codes are cryptographically random, 6-character alphanumeric (36⁶ ≈ 2.2 billion possibilities), rate-limited to 5 attempts per code.

9.2 Key Management

-   Device private keys are generated and stored in the OS keychain (macOS Keychain, Windows Credential Manager) via Tauri's secure storage API.

-   The PDS never sees, transmits, or stores private keys. All cryptographic proofs are generated device-side.

-   Key rotation invalidates the previous key after a 24-hour grace period. Rotation events are logged immutably.

-   Recovery keys (Shamir shares) are configured during the DID ceremony step of the setup wizard. Loss of all signing keys without recovery shares means the DID is permanently orphaned.

9.3 Transport

-   All API traffic is TLS 1.3 only. The PDS does not support TLS 1.2 fallback.

-   Device-to-PDS data sync uses Iroh's encrypted transport (QUIC-based, end-to-end encrypted).

-   CORS is restricted to the service's web dashboard origin. The Tauri app uses direct HTTPS, not browser fetch.

10\. Internal Observability

The PDS exposes internal metrics for operating the SaaS product. These endpoints are not public-facing --- they are served on a separate internal port (default: 9090) accessible only from the ops network.

> ***Design Decision:** User-facing event streams (webhooks, SSE) are deferred. Device-side notifications use the existing Iroh channel. Email handles critical account events. A public event API will be added if self-hosted operators request it.*

10.1 Infrastructure Metrics

Prometheus-compatible metrics endpoint for standard monitoring infrastructure (Grafana, Datadog, PagerDuty).

> GET :9090/metrics

  ----------------------------------- ----------- ------------------------------------------------
  **Metric**                          **Type**    **Description**
  PDS\_active\_connections          gauge       Currently connected Iroh tunnels
  PDS\_request\_duration\_seconds   histogram   XRPC request latency distribution
  PDS\_error\_total                 counter     Errors by type and status code
  PDS\_buffer\_depth                gauge       Messages buffered per device (offline devices)
  PDS\_bandwidth\_bytes\_total      counter     Bytes proxied, labeled by account tier
  plc\_mirror\_resolution\_ms         histogram   DID resolution latency from PLC mirror
  plc\_mirror\_cache\_hit\_ratio      gauge       PLC mirror cache hit rate
  iroh\_tunnel\_health                gauge       Per-tunnel health score (0--1)
  ----------------------------------- ----------- ------------------------------------------------

10.2 Business Metrics

Higher-level metrics for product health monitoring. Served as JSON on the internal port.

> GET :9090/internal/stats

  ------------------------------------- -------------------------------------------------------------
  **Metric**                            **Description**
  accounts\_by\_tier                    Count of accounts per tier (free/pro/business)
  storage\_utilization\_p50\_p95\_p99   Storage consumption distribution across accounts
  federation\_health                    requestCrawl success rate, BGS ingestion lag
  did\_resolution\_latency              P50/P95 DID resolution time via PLC mirror vs upstream
  active\_devices\_24h                  Devices that connected in the last 24 hours
  stale\_devices\_72h                   Devices that haven't connected in 72+ hours (churn signal)
  exit\_ceremonies\_in\_progress        Active DID migrations and account deletions in grace period
  ------------------------------------- -------------------------------------------------------------

> ***Note:** Business metrics power internal dashboards and customer support tooling. They are not exposed to users. The /internal/stats endpoint requires a separate ops-scoped token and is never routed through the public load balancer.*

## 11. PDS Key Management                                    [v0.1]

The PDS holds the ATProto signing key. These endpoints manage the PDS's key lifecycle.

**POST /v1/pds/keys**                                         [v0.1]

Generate a new PDS signing key. Called during account creation or key rotation. The PDS generates the key internally — the private key is never exposed.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  key_id                  string     Key identifier
  public_key              string     P-256 public key, base64url-encoded
  algorithm               string     "ES256" (P-256) or "ES256K" (secp256k1)
  created_at              string     ISO 8601
  ----------------------- ---------- -------------------------------------------------------

**DELETE /v1/pds/keys/:keyId**                                [v1.0]

Revoke a PDS signing key. Triggers DID rotation to update the signing key in the DID document.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  revoked_at              string     ISO 8601
  rotation_status         string     "pending" | "complete"
  ----------------------- ---------- -------------------------------------------------------

**POST /v1/pds/commits/sign**                                 [v0.2]

Sign an unsigned commit constructed by the desktop PDS. Desktop-enrolled mode only.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  unsigned_commit         bytes      yes            CAR-encoded unsigned commit
  repo_did                string     yes            DID of the repo
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  signed_commit           bytes      CAR-encoded signed commit
  commit_cid              string     CID of the signed commit
  ----------------------- ---------- -------------------------------------------------------

**GET /v1/pds/repo/snapshot**                                 [v0.2]

Full repo export as CAR file. Used by desktop during initial sync after enrollment.

**Response:** streaming CAR file (same format as com.atproto.sync.getRepo)

**GET /v1/pds/mode**                                          [v0.2]

Current PDS operating mode for this account.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  mode                    string     "mobile-only" | "desktop-enrolled" | "desktop-offline"
  primary_device          string     Device ID of repo host (null in mobile-only)
  signing_key_id          string     Active signing key identifier
  ----------------------- ---------- -------------------------------------------------------

## 12. Device Management                                       [v0.2]

Extended device operations for the mobile app. These supplement the existing device registration endpoints in Section 3.

**POST /v1/devices/:id/pair**                                   [v0.2]

Initiate device pairing via QR code. The phone generates a pairing session, the desktop scans the QR code containing the session details.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  pairing_code            string     yes            Code from QR scan
  device_type             string     yes            "desktop" | "mobile"
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  paired_at               string     ISO 8601
  device_id               string     The paired device's ID
  pairing_status          string     "paired" | "pending_promotion"
  ----------------------- ---------- -------------------------------------------------------

**POST /v1/devices/:id/promote**                                [v0.2]

Promote a paired desktop to repo host. Transitions the PDS from mobile-only to desktop-enrolled mode. The PDS transfers the repo to the desktop via Iroh.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  promoted_at             string     ISO 8601
  mode                    string     "desktop-enrolled"
  repo_transfer           string     "in_progress" | "complete"
  ----------------------- ---------- -------------------------------------------------------

**GET /v1/devices/:id/status**                                  [v0.2]

Device health and connectivity status.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  device_id               string     Device identifier
  status                  string     "online" | "offline" | "degraded"
  last_seen               string     ISO 8601
  is_primary              boolean    Whether this device hosts the repo
  mode                    string     Current lifecycle phase
  ----------------------- ---------- -------------------------------------------------------

**DELETE /v1/devices/:id**                                      [v0.2]

De-enroll a device. Already exists in Section 3. This note confirms mobile app can also call it (not just web dashboard).

Note: Update Section 3 to allow device_token auth (not just session_token) for mobile-initiated device removal.

## 13. Data Transfer                                           [v0.1]

Planned device swap (e.g., upgrading phones). Uses Iroh for direct peer-to-peer transfer with a 6-digit verification code.

**POST /v1/transfer/initiate**                                  [v0.1]

Generate a transfer session. Returns a 6-digit code for the new device to enter.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  transfer_id             string     Transfer session identifier
  code                    string     6-digit verification code
  expires_at              string     ISO 8601 (15 minutes)
  iroh_ticket             string     Iroh connection ticket for direct transfer
  ----------------------- ---------- -------------------------------------------------------

**POST /v1/transfer/accept**                                    [v0.1]

New device submits the transfer code to join the session.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  code                    string     yes            6-digit code from old device
  device_public_key       string     yes            P-256 public key of new device
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  transfer_id             string     Transfer session ID
  status                  string     "accepted" | "transferring"
  ----------------------- ---------- -------------------------------------------------------

**POST /v1/transfer/complete**                                  [v0.1]

Finalize the transfer. Old device's token is revoked, new device receives a fresh device_token.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  new_device_id           string     New device's identifier
  device_token            string     New device's long-lived token
  old_device_revoked      boolean    Confirmation old token is dead
  ----------------------- ---------- -------------------------------------------------------

## 14. Recovery                                               [v1.0]

Unplanned device loss recovery via Shamir share reconstruction.

**POST /v1/recovery/initiate**                                  [v1.0]

Begin a recovery ceremony. User must present 2 of 3 Shamir shares to reconstruct the rotation key.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  email                   string     yes            Account email for verification
  share_1                 string     yes            First Shamir share (e.g., from iCloud)
  share_source_1          string     yes            "icloud" | "PDS" | "device" | "paper"
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  recovery_id             string     Recovery session identifier
  shares_needed           integer    Number of additional shares required
  status                  string     "awaiting_shares" | "ready_to_verify"
  ----------------------- ---------- -------------------------------------------------------

**POST /v1/recovery/verify-key**                                [v1.0]

Submit reconstructed key material to prove DID ownership.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  recovery_id             string     yes            Recovery session ID
  share_2                 string     yes            Second Shamir share
  share_source_2          string     yes            Source of the second share
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  status                  string     "verified" | "failed"
  rotation_key            string     Reconstructed rotation public key (for verification)
  ----------------------- ---------- -------------------------------------------------------

**GET /v1/recovery/restore**                                    [v1.0]

Stream the repo and blobs from the PDS to the new device after successful key verification.

**Response:** streaming CAR file + blob manifest

**PUT /v1/keys/shares/:id**                                     [v1.0]

Update the PDS-held Shamir share (Share 2). Used after key rotation to re-split with new shares.

**Request Body**

  ----------------------- ---------- -------------- -------------------------------------------------------
  **Field**               **Type**   **Required**   **Description**
  encrypted_share         string     yes            New encrypted share data
  ----------------------- ---------- -------------- -------------------------------------------------------

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  updated_at              string     ISO 8601
  ----------------------- ---------- -------------------------------------------------------

**GET /v1/keys/rotation-log**                                   [v1.0]

Immutable audit log of all Shamir share rotations and recovery attempts.

**Response (200 OK)**

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  entries                 array      List of rotation/recovery events with timestamps
  ----------------------- ---------- -------------------------------------------------------

## 15. Blob Management                                         [v0.1]

Blob endpoints follow the ATProto spec. See blob-handling-spec.md for storage architecture and lifecycle details.

**POST /v1/blobs/upload**                                       [v0.1]

Alias for com.atproto.repo.uploadBlob. Accepts multipart upload, returns CID reference. Subject to per-account storage quotas.

Note: This is the same endpoint as the XRPC uploadBlob — listed here for completeness. The provisioning API does not add a separate blob upload path.

**GET /v1/accounts/:id/storage**                                [v0.1]

Blob storage metrics for an account. `:id` is the account DID. Operator-only: requires the admin token. Reports on the account regardless of activation state.

**Response (200 OK)** — fields are camelCase, matching the rest of the /v1 API.

  ----------------------- ---------- -------------------------------------------------------
  **Field**               **Type**   **Description**
  blobCount               integer    Total blobs stored for the account
  totalBytes              integer    Total bytes occupied by those blobs
  quotaBytes              integer    Per-account storage quota (`[blobs] max_storage_per_account`). Tiers are not yet differentiated in v0.1, so every account reports the same configured quota.
  quotaUsedPct            number     totalBytes as a percentage of quotaBytes (0 when the quota is 0)
  largestBlob             object     The account\'s largest blob as `{ cid, size }`, or null when it has none
  ----------------------- ---------- -------------------------------------------------------

**Error Responses**

  ------------ -------------- --------------------------------
  **Status**   **Code**       **Description**
  401          UNAUTHORIZED   Missing or invalid admin token
  404          NOT\_FOUND     No account exists for the DID
  ------------ -------------- --------------------------------


Appendix A: Status Codes Reference

  ---------- --------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
  **Code**   **Constants**                                                                                                                                 **Context**
  400        INVALID\_CLAIM, INVALID\_DOCUMENT, INVALID\_PROOF, INVALID\_ENDPOINT, INVALID\_CONFIRMATION                                                   Malformed request or failed validation
  401        UNAUTHORIZED, INVALID\_CREDENTIALS, TOKEN\_EXPIRED                                                                                            Authentication failure
  403        FORBIDDEN, TIER\_RESTRICTED, DIDWEB\_REQUIRES\_DOMAIN, SINGLE\_DEVICE\_TIER                                                                   Insufficient permissions or tier
  404        NOT\_FOUND, DEVICE\_NOT\_FOUND, DID\_NOT\_FOUND, HANDLE\_NOT\_FOUND, NOT\_IN\_GRACE\_PERIOD                                                   Resource doesn't exist
  409        ACCOUNT\_EXISTS, DEVICE\_LIMIT, DID\_EXISTS, HANDLE\_TAKEN, ROTATION\_IN\_PROGRESS, LEASE\_HELD, MIGRATION\_IN\_PROGRESS, ACTIVE\_MIGRATION   Conflict with existing state
  410        ALREADY\_DELETED                                                                                                                              Resource permanently removed
  422        WEAK\_PASSWORD, INVALID\_KEY, INVALID\_HANDLE, KEY\_MISMATCH, DIDWEB\_SELF\_SERVICE                                                           Semantic validation failure
  423        ACCOUNT\_LOCKED                                                                                                                               Temporarily locked due to abuse
  429        RATE\_LIMITED                                                                                                                                 Rate or usage cap exceeded
  503        EXPORT\_IN\_PROGRESS                                                                                                                          Temporary unavailability
  ---------- --------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------

Appendix B: Design Decisions Log

This appendix collects all design decisions made during the specification process, with rationale for future reference.

  ------------------------------------------------ --------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Decision**                                     **Rationale**
  did:plc is the default DID method                Decouples identity from PDS domain. Clean exit path: user signs a PLC operation to repoint service endpoint. No ongoing liability for the PDS operator.
  did:web requires a user-owned custom domain      Eliminates exit liability. If did:web were offered on service subdomains, the PDS would be obligated to host DID documents indefinitely after users leave.
  Primary-device write lease for multi-device      ATProto repos require a linear commit chain. LWW risks lost writes; conflict queues have poor UX. Primary-device matches actual desktop usage patterns.
  Single auth path (web dashboard for all users)   One security model to audit. Self-hosted static\_token bypass can be added later if operators request it.
  No public event API in v1.0                      Iroh channel handles device notifications. Email handles critical alerts. A webhook/SSE surface adds complexity without clear demand.
  PLC mirror starts read-only                      Reduces operational risk. Read-write authority requires consensus participation with the PLC network --- deferred until the product matures.
  Setup wizard handles DID ceremony                Users get a single \"setup complete\" moment. Splitting device binding and DID ceremony into separate sessions creates drop-off risk.
  30-day grace period on account deletion          Prevents accidental data loss. The PDS continues serving the repo during transition, ensuring zero dropped interactions for the user's followers.
  PDS constructs DID document                   Client sends raw key material, not a pre-built DID document. Ensures PDS controls document structure, service endpoints, and signing key binding. Client only needs public keys — no DID assembly logic required. Simplifies mobile clients significantly.
  ------------------------------------------------ --------------------------------------------------------------------------------------------------------------------------------------------------------------
