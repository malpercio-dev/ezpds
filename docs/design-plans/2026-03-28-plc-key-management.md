# PLC Key Management Design

## Summary

This design extends the identity-wallet from a relay-dependent onboarding tool into a standalone AT Protocol key management application. The core capability it adds is "claiming" an existing AT Protocol identity: the user authenticates to their current PDS (e.g., bsky.social) via OAuth, the wallet coordinates with the PDS to produce a signed PLC rotation operation that places the device's Secure Enclave key at the top of the DID's `rotationKeys` hierarchy, verifies that operation locally before submitting it to plc.directory, and then persists the claimed identity in per-DID Keychain storage. After the initial claim the wallet requires no relay or PDS involvement for day-to-day use — it holds the highest-priority rotation key for the DID.

The second major capability is ongoing key custody: a monitoring loop polls plc.directory's audit log for each managed identity, classifies new operations as authorized (signed by the device key) or unauthorized (signed by anything else), and surfaces the latter as time-sensitive alerts because plc.directory gives the holder of a higher-priority key 72 hours to submit a counter-operation. If an unauthorized change is detected, the wallet can build and submit a recovery override operation that re-establishes the user's pre-attack DID state, signed with the device key's root authority. The design is structured across seven implementation phases: extending the crypto crate for non-genesis PLC operations, building per-DID Keychain persistence, wiring PDS discovery and OAuth to arbitrary PDS endpoints, implementing the claim and monitoring backends as Tauri commands, and delivering the corresponding frontend screens.

## Definition of Done
The identity-wallet can operate as a standalone key management tool — independent of the relay — that allows users to (1) claim root rotation key authority over existing AT Protocol identities by authenticating to their current PDS via OAuth, verifying the signed PLC operation locally, and submitting it to plc.directory; (2) manage multiple claimed identities with per-DID Keychain storage; (3) monitor plc.directory for unauthorized PLC operations and alert within the 72-hour recovery window; and (4) sign and submit recovery override operations from the device. The crypto crate is extended to support PLC rotation operations (non-genesis ops with `prev` chaining). The design includes a recovery section covering phone loss/upgrade scenarios and the role of a future SSS-based software recovery key.

## Acceptance Criteria

### plc-key-management.AC1: Crypto crate supports PLC rotation operations
- **plc-key-management.AC1.1 Success:** `build_did_plc_rotation_op` produces a signed PLC operation with `prev` field set to the provided CID and `type: "plc_operation"`
- **plc-key-management.AC1.2 Success:** `verify_plc_operation` accepts a valid rotation op signed by a key in the authorized `rotationKeys` set
- **plc-key-management.AC1.3 Failure:** `verify_plc_operation` rejects an operation with an invalid ECDSA signature
- **plc-key-management.AC1.4 Failure:** `verify_plc_operation` rejects an operation signed by a key not in the authorized `rotationKeys` set
- **plc-key-management.AC1.5 Success:** `compute_cid` produces the same CID as plc.directory for the same signed operation bytes
- **plc-key-management.AC1.6 Success:** `parse_audit_log` correctly parses a real plc.directory audit log JSON response into structured `AuditEntry` values
- **plc-key-management.AC1.7 Success:** `diff_audit_logs` returns empty when cached and current logs are identical
- **plc-key-management.AC1.8 Success:** `diff_audit_logs` returns new operations when current log has entries not in cached log
- **plc-key-management.AC1.9 Success:** `verify_plc_operation` handles both genesis ops (`prev: null`) and rotation ops (`prev: cid`) with the same interface

### plc-key-management.AC2: Multi-identity Keychain persistence
- **plc-key-management.AC2.1 Success:** `add_identity` stores a DID in the `managed-dids` array and generates a per-DID device key
- **plc-key-management.AC2.2 Success:** `list_identities` returns all previously added DIDs
- **plc-key-management.AC2.3 Success:** `remove_identity` removes the DID and all its prefixed Keychain entries
- **plc-key-management.AC2.4 Success:** `get_or_create_device_key` returns the same public key on repeated calls for the same DID
- **plc-key-management.AC2.5 Success:** Different DIDs get different device keys
- **plc-key-management.AC2.6 Success:** `store_did_doc` and `get_did_doc` round-trip a DID document for a specific identity
- **plc-key-management.AC2.7 Success:** `store_plc_log` and `get_plc_log` round-trip an audit log for a specific identity
- **plc-key-management.AC2.8 Edge:** `get_did_doc` returns `None` for an identity with no stored document
- **plc-key-management.AC2.9 Edge:** Operations on a non-existent DID return appropriate errors

### plc-key-management.AC3: PDS discovery and OAuth to arbitrary PDS
- **plc-key-management.AC3.1 Success:** `resolve_handle` resolves a handle to a DID via DNS TXT record
- **plc-key-management.AC3.2 Success:** `resolve_handle` falls back to HTTP `/.well-known/atproto-did` when DNS fails
- **plc-key-management.AC3.3 Failure:** `resolve_handle` returns `HANDLE_NOT_FOUND` when neither DNS nor HTTP resolution succeeds
- **plc-key-management.AC3.4 Success:** `discover_pds` extracts the PDS endpoint from a DID document fetched from plc.directory
- **plc-key-management.AC3.5 Success:** `discover_auth_server` fetches OAuth authorization server metadata from the PDS
- **plc-key-management.AC3.6 Success:** OAuth PKCE+DPoP flow completes against an arbitrary PDS and returns valid tokens
- **plc-key-management.AC3.7 Failure:** `discover_pds` returns `DID_NOT_FOUND` when plc.directory has no record for the DID
- **plc-key-management.AC3.8 Failure:** `discover_pds` returns `PDS_UNREACHABLE` when the PDS endpoint is down

### plc-key-management.AC4: Claim flow executes end-to-end
- **plc-key-management.AC4.1 Success:** `resolve_identity` returns correct `IdentityInfo` including current rotation keys and PDS URL
- **plc-key-management.AC4.2 Success:** `request_claim_verification` calls `requestPlcOperationSignature` on the old PDS
- **plc-key-management.AC4.3 Success:** `sign_and_verify_claim` returns a verified operation with the device key at `rotationKeys[0]`
- **plc-key-management.AC4.4 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when the old PDS returns an operation with a different key at `rotationKeys[0]`
- **plc-key-management.AC4.5 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when `prev` does not chain from the current audit log
- **plc-key-management.AC4.6 Failure:** `sign_and_verify_claim` returns `VERIFICATION_FAILED` when unexpected keys or services are altered
- **plc-key-management.AC4.7 Success:** `sign_and_verify_claim` populates `warnings` for non-blocking concerns (e.g., old PDS added an extra service)
- **plc-key-management.AC4.8 Success:** `submit_claim` POSTs the signed operation to plc.directory and persists the identity to IdentityStore
- **plc-key-management.AC4.9 Failure:** `submit_claim` returns `PLC_DIRECTORY_ERROR` when plc.directory rejects the operation
- **plc-key-management.AC4.10 Failure:** `sign_and_verify_claim` returns `INVALID_TOKEN` when the email verification token is wrong

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.1 Success:** Mode selector on first launch shows "Create new identity" and "I have an identity" options
- **plc-key-management.AC5.2 Success:** App skips mode selector and goes to home when `listIdentities()` returns non-empty
- **plc-key-management.AC5.3 Success:** Identity input screen resolves a handle and displays current PDS + rotation key state
- **plc-key-management.AC5.4 Failure:** Identity input screen shows inline error for unresolvable handle
- **plc-key-management.AC5.5 Success:** PDS auth screen triggers OAuth and proceeds after `auth_ready` event
- **plc-key-management.AC5.6 Success:** Email verification screen sends token and shows verified operation diff
- **plc-key-management.AC5.7 Failure:** Email verification screen shows inline error for invalid token and stays on same screen
- **plc-key-management.AC5.8 Success:** Review operation screen displays added/removed keys and changed services clearly
- **plc-key-management.AC5.9 Success:** Review operation screen blocks submission and shows warning when verification detects suspicious changes
- **plc-key-management.AC5.10 Success:** Claim success screen shows updated DID doc and navigates to home
- **plc-key-management.AC5.11 Success:** Multi-identity home shows all claimed identities as cards with rotation key status badges
- **plc-key-management.AC5.12 Success:** "+" button on home navigates back to mode selector to add another identity
- **plc-key-management.AC5.13 Edge:** Existing onboarding flow (create new identity) remains functional and unchanged

### plc-key-management.AC6: PLC monitoring and alerting
- **plc-key-management.AC6.1 Success:** Monitor detects a new PLC operation signed by the device key and updates cached log without alerting
- **plc-key-management.AC6.2 Success:** Monitor detects a new PLC operation signed by a different key and creates an `UnauthorizedChange` alert
- **plc-key-management.AC6.3 Success:** Alert includes correct recovery deadline (operation timestamp + 72 hours)
- **plc-key-management.AC6.4 Success:** Home screen shows red alert badge on identity cards with `alertCount > 0`
- **plc-key-management.AC6.5 Success:** Alert detail screen shows signing key, timestamp, and recovery deadline countdown
- **plc-key-management.AC6.6 Success:** Monitor runs on app foreground and on a 15-minute timer while app is open
- **plc-key-management.AC6.7 Edge:** Monitor handles plc.directory being unreachable gracefully (logs error, retries next cycle, does not alert)
- **plc-key-management.AC6.8 Edge:** Monitor handles empty audit log (newly created identity, no operations yet)

### plc-key-management.AC7: Recovery override
- **plc-key-management.AC7.1 Success:** `build_recovery_override` produces a signed PLC operation with `prev` pointing to the fork point CID
- **plc-key-management.AC7.2 Success:** Recovery operation restores the pre-unauthorized `rotationKeys`, `services`, and `verificationMethods`
- **plc-key-management.AC7.3 Success:** Recovery operation is signed by the device key (highest authority)
- **plc-key-management.AC7.4 Success:** `submit_recovery_override` POSTs to plc.directory and updates cached log
- **plc-key-management.AC7.5 Failure:** `build_recovery_override` returns `RECOVERY_WINDOW_EXPIRED` when the 72-hour deadline has passed
- **plc-key-management.AC7.6 Success:** Recovery override screen shows the counter-operation diff with confirm/cancel
- **plc-key-management.AC7.7 Edge:** Multiple unauthorized operations in sequence — recovery override targets the earliest fork point

## Glossary

- **AT Protocol (atproto)**: The open, federated social networking protocol developed by Bluesky. Defines the identity, data, and network layers used in this project.
- **DID (Decentralized Identifier)**: A W3C-standard self-sovereign identifier, e.g. `did:plc:abc123`. In AT Protocol, each user account is a DID.
- **did:plc**: The specific DID method used by AT Protocol. DIDs are created and updated by submitting signed operations to plc.directory.
- **plc.directory**: The registry operated by Bluesky that stores and sequences PLC operations for every `did:plc` identity. Acts as the source of truth for DID documents and their audit histories.
- **PLC operation**: A signed, content-addressed record submitted to plc.directory that updates a DID's state — its rotation keys, verification methods, services, and handle aliases. Genesis ops create the DID; rotation ops modify it.
- **rotationKeys**: The ordered list of authorized keys in a DID's PLC state. Lower index means higher authority. `rotationKeys[0]` is the root authority key and can override operations from any lower-priority key within 72 hours.
- **rotation key claim**: The process by which the wallet inserts the device's Secure Enclave key as `rotationKeys[0]` in an existing DID's PLC state, elevating it above the PDS's key.
- **`prev` field / CID chaining**: Each non-genesis PLC operation includes a `prev` field containing the CID (content identifier) of the previous operation. This forms an append-only chain; plc.directory rejects operations whose `prev` does not match the current head.
- **CID (Content Identifier)**: A self-describing, content-addressed hash (using DAG-CBOR encoding + SHA-256 in this context) that uniquely identifies a PLC operation by its content. Used in `prev` chaining.
- **DAG-CBOR**: A deterministic binary encoding of CBOR (Concise Binary Object Representation) used by IPLD. PLC operations are serialized in DAG-CBOR before signing and hashing.
- **72-hour recovery window**: A time-limited override mechanism in plc.directory. When a new PLC operation is submitted, any key that held a higher position (`rotationKeys[i]` with lower `i`) in the previous state retains override authority for 72 hours, allowing it to revert the change. After 72 hours the new state is permanent.
- **PDS (Personal Data Server)**: The server hosting a user's AT Protocol account data and providing the XRPC API. In the claim flow, the wallet contacts the user's current PDS to coordinate signing the new PLC operation.
- **XRPC**: The HTTP-based RPC protocol used within AT Protocol. The claim flow calls three XRPC lexicon methods on the user's PDS: `requestPlcOperationSignature`, `signPlcOperation`, and `getRecommendedDidCredentials`.
- **OAuth PKCE+DPoP**: The authorization flow used to authenticate to an arbitrary PDS. PKCE (Proof Key for Code Exchange) prevents authorization code interception; DPoP (Demonstration of Proof of Possession) binds tokens to the client's key, preventing token theft.
- **Secure Enclave**: Apple's dedicated hardware security subsystem on iPhone and modern Macs. Generates and stores non-extractable P-256 keys; signing happens inside the enclave, so the private key never exists in application memory.
- **IdentityStore**: A new Rust struct in the identity-wallet that manages per-DID Keychain namespacing — storing and retrieving device keys, DID documents, PLC audit logs, and OAuth tokens keyed by DID.
- **PlcMonitor**: A new Rust struct in the identity-wallet that polls plc.directory's audit log for each managed identity and classifies new operations as authorized or unauthorized.
- **audit log**: The complete, ordered history of all PLC operations for a DID, returned by `plc.directory/{did}/log/audit`. The monitor diffs cached and current logs to detect new operations.
- **fork point**: In the recovery override flow, the last legitimate PLC operation before an unauthorized one was inserted. The counter-operation sets `prev` to the fork point's CID to branch the chain from that point.
- **SSS (Shamir Secret Sharing)**: A cryptographic technique for splitting a secret (such as a private key) into N shares, where any K-of-N shares reconstruct the secret. Referenced in the document as a future recovery mechanism.
- **Tauri**: The framework used to build the identity-wallet as a native iOS app with a Rust backend and a SvelteKit/Svelte 5 frontend. IPC between frontend and backend uses typed "commands" via `invoke`.
- **IPC command pattern**: The Tauri mechanism for calling Rust backend functions from the JavaScript frontend. Backend functions annotated with `#[tauri::command]` are registered in `generate_handler![]` and callable via `invoke()`.
- **always-ok pattern**: A design convention in the identity-wallet where a Tauri command returns `Ok(SomeStruct)` even when partial failures occur, encoding errors as fields on the struct rather than as `Err` variants. Prevents the frontend from entering an error state when non-critical data is missing.
- **deep-link OAuth callback**: The mechanism by which Safari returns control to the app after OAuth authorization. The app registers a custom URL scheme (`dev.malpercio.identitywallet:`) and handles the incoming redirect in Rust via `tauri-plugin-deep-link`.
- **per-DID Keychain namespacing**: A new key naming convention introduced by this design. Rather than flat account names like `"did"`, entries use the format `"{did}:device-key"` so multiple identities can coexist in the iOS Keychain without collision.
- **state machine navigation**: The frontend routing pattern used in the identity-wallet. A union type enumerates all screens (`OnboardingStep`); a `goTo()` function transitions between them; child components communicate completion via `onnext`/`onback`/`onsuccess` callbacks.

## Architecture

The identity-wallet gains a second operating mode: **standalone key management**. On first launch, a mode selector replaces the relay config screen as the entry point. "Create new identity" enters the existing relay-dependent onboarding. "I have an identity" enters a relay-free import flow that talks only to the user's current PDS and plc.directory.

After either path, the user lands on a unified home screen showing all managed identities. Each identity card displays: handle, DID, rotation key status (root / non-root), last-checked timestamp, and an alert badge when unauthorized PLC operations are detected.

**Component layers:**

| Layer | New Components | Responsibility |
|-------|----------------|---------------|
| **crypto crate** | `build_did_plc_rotation_op`, `verify_plc_operation`, `compute_cid`, `parse_audit_log` | PLC rotation op building + verification (extends existing genesis support), CID computation for `prev` chaining, audit log parsing |
| **identity-wallet Rust** | `IdentityStore`, `PlcMonitor`, `PdsClient`, new Tauri commands | Per-DID Keychain namespacing, PLC audit log polling + diff detection, XRPC calls to arbitrary PDS via OAuth |
| **identity-wallet frontend** | Import flow screens, identity list home, alert UI | Mode selector, 5-screen import flow, multi-identity home, recovery override confirmation |

**No relay involvement.** The wallet talks directly to three external systems:

- **Old PDS** (e.g., bsky.social) — OAuth authentication + three XRPC endpoints for the initial claim. Not needed after claim succeeds.
- **plc.directory** — PLC operation submission (initial claim + recovery overrides) and audit log polling (monitoring).
- **iOS Keychain** — local persistence of device keys, DID documents, PLC operation logs, and OAuth tokens, all namespaced per DID.

### Claim flow

```
identity_input → pds_auth → email_verification → review_operation → claim_success → home
```

1. **`identity_input`** — User enters handle or DID. Wallet resolves handle via DNS TXT `_atproto.{handle}` or HTTP `/.well-known/atproto-did`, fetches DID doc from plc.directory, extracts current PDS endpoint and rotation key state.

2. **`pds_auth`** — OAuth PKCE+DPoP to the discovered PDS. Reuses existing `OAuthClient` pointed at the old PDS's authorization server (discovered via `/.well-known/oauth-authorization-server`). Safari redirect + deep-link callback.

3. **`email_verification`** — Wallet calls `com.atproto.identity.requestPlcOperationSignature` on old PDS. User receives email with verification token and enters it.

4. **`review_operation`** — Wallet calls `com.atproto.identity.signPlcOperation` with the email token and the user's device key as desired `rotationKeys[0]`. Old PDS returns the signed PLC operation. **Wallet verifies locally**: parses the signed op, checks `rotationKeys[0]` is the device key, checks `prev` chains correctly from the current audit log, checks no unexpected keys or services were altered. Shows a diff to the user.

5. **`claim_success`** — Wallet POSTs the verified operation to `plc.directory`. On success, identity is persisted to `IdentityStore`.

### Monitoring flow

```
app foreground / 15-min timer / iOS background fetch
  → for each managed DID:
    → fetch plc.directory/{did}/log/audit
    → diff against cached log
    → new ops signed by our device key → update cache, no alert
    → new ops signed by other key → UnauthorizedChange alert with 72h countdown
```

Client-side polling for v1. A server-side monitoring service is a future addition for reliable 24/7 coverage (iOS background fetch is OS-throttled and unreliable for time-sensitive alerting).

### Recovery override flow

When an unauthorized change is detected, the user can submit a counter-operation:

1. Wallet builds a new PLC operation with `prev` pointing to the CID of the last legitimate operation (the fork point).
2. The operation restores the previous `rotationKeys`/`services`/`verificationMethods` state.
3. Signed by the device key (`rotationKeys[0]` in the pre-unauthorized state — highest authority).
4. User reviews and confirms. Wallet POSTs to plc.directory.
5. plc.directory accepts because the signing key outranks the key that signed the unauthorized operation.

### IPC contracts

New Tauri commands and their TypeScript wrappers:

```typescript
// Identity resolution
interface IdentityInfo {
  did: string;
  handle: string;
  pdsUrl: string;
  currentRotationKeys: string[];    // did:key URIs
  deviceKeyIsRoot: boolean;         // true if our key is rotationKeys[0]
}
export const resolveIdentity = (handleOrDid: string): Promise<IdentityInfo> =>
  invoke('resolve_identity', { handleOrDid });

// Claim flow
export const startPdsAuth = (pdsUrl: string): Promise<void> =>
  invoke('start_pds_auth', { pdsUrl });

export const requestClaimVerification = (did: string): Promise<void> =>
  invoke('request_claim_verification', { did });

interface VerifiedClaimOp {
  diff: OpDiff;         // human-readable changes
  signedOp: string;     // JSON string of the signed PLC op, ready to submit
  warnings: string[];   // non-blocking concerns (e.g., "old PDS added an extra service")
}
interface OpDiff {
  addedKeys: string[];
  removedKeys: string[];
  changedServices: ServiceChange[];
  prevCid: string;
}
export const signAndVerifyClaim = (did: string, token: string): Promise<VerifiedClaimOp> =>
  invoke('sign_and_verify_claim', { did, token });

interface ClaimResult {
  updatedDidDoc: Record<string, unknown>;
}
export const submitClaim = (did: string): Promise<ClaimResult> =>
  invoke('submit_claim', { did });

// Identity management (always-ok pattern)
interface ManagedIdentity {
  did: string;
  handle: string;
  deviceKeyIsRoot: boolean;
  lastChecked: string | null;       // ISO 8601
  alertCount: number;
}
export const listIdentities = (): Promise<ManagedIdentity[]> =>
  invoke('list_identities');

interface IdentityStatus {
  healthy: boolean;
  alerts: UnauthorizedChange[];
}
interface UnauthorizedChange {
  operationCid: string;
  signedBy: string;                 // did:key of the signing key
  detectedAt: string;               // ISO 8601
  recoveryDeadline: string;         // ISO 8601 (op timestamp + 72h)
  description: string;              // human-readable summary
}
export const checkIdentityStatus = (did: string): Promise<IdentityStatus> =>
  invoke('check_identity_status', { did });

// Recovery override
interface SignedRecoveryOp {
  diff: OpDiff;
  signedOp: string;
}
export const buildRecoveryOverride = (did: string, operationCid: string): Promise<SignedRecoveryOp> =>
  invoke('build_recovery_override', { did, operationCid });

export const submitRecoveryOverride = (did: string): Promise<ClaimResult> =>
  invoke('submit_recovery_override', { did });
```

Error types follow the existing `{ code: "SCREAMING_SNAKE_CASE" }` discriminated union pattern:

```typescript
type ResolveError =
  | { code: 'HANDLE_NOT_FOUND' }
  | { code: 'DID_NOT_FOUND' }
  | { code: 'PDS_UNREACHABLE' }
  | { code: 'NETWORK_ERROR'; message: string };

type ClaimError =
  | { code: 'INVALID_TOKEN' }
  | { code: 'VERIFICATION_FAILED'; message: string }  // details of what's wrong
  | { code: 'PLC_DIRECTORY_ERROR'; message: string }
  | { code: 'UNAUTHORIZED' }
  | { code: 'NETWORK_ERROR'; message: string };

type RecoveryError =
  | { code: 'RECOVERY_WINDOW_EXPIRED' }
  | { code: 'SIGNING_FAILED'; message: string }
  | { code: 'PLC_DIRECTORY_ERROR'; message: string };
```

## Existing Patterns

This design follows established patterns from the identity-wallet and crypto crate:

- **OAuth PKCE+DPoP** — `OAuthClient` in `src-tauri/src/oauth_client.rs` accepts a configurable `base_url` and handles DPoP proof generation, token refresh, and nonce retry. The import flow reuses this pointed at an arbitrary PDS rather than the relay.
- **IPC command pattern** — `#[tauri::command]` async functions return `Result<SuccessType, ErrorType>` with `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]` error serialization. TypeScript wrappers in `src/lib/ipc.ts` expose typed functions.
- **State machine navigation** — `OnboardingStep` union in `src/routes/+page.svelte` with `goTo()` transitions, per-field error rewinding, and child component `onnext`/`onback`/`onsuccess` callbacks.
- **Always-ok pattern** — `load_home_data` always returns `Ok(HomeData)` with partial failures encoded in fields. `listIdentities` and `checkIdentityStatus` follow the same pattern.
- **Keychain abstraction** — `src-tauri/src/keychain.rs` with `store_item`/`get_item`/`delete_item` under service `"ezpds-identity-wallet"`. Extended with per-DID namespacing (new pattern, see Phase 2).
- **Crypto pure functional core** — `crates/crypto/` has zero I/O. All PLC operation building uses DAG-CBOR + ECDSA-SHA256 with low-S normalization. `build_did_plc_rotation_op` follows the same pattern as `build_did_plc_genesis_op_with_external_signer`, adding `prev` field support.
- **Deep-link OAuth callback** — `tauri-plugin-deep-link` with custom scheme `dev.malpercio.identitywallet:` routes callbacks to `handle_deep_link` in `lib.rs`. The import flow reuses this mechanism with the old PDS as the OAuth target.

**New pattern: per-DID Keychain namespacing.** Current Keychain entries use flat account names (`"did"`, `"oauth-access-token"`). Multi-identity requires prefixed accounts: `"{did}:device-key"`, `"{did}:did-doc"`, `"{did}:plc-log"`, `"{did}:oauth-tokens"`. A top-level `"managed-dids"` key stores a JSON array of all managed DID strings. This is a new pattern not present in existing code.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Crypto crate — PLC rotation operations

**Goal:** Extend the crypto crate to support non-genesis PLC operations (rotation ops with `prev` chaining), generalized verification, and audit log parsing.

**Components:**
- `crates/crypto/src/plc.rs` — `build_did_plc_rotation_op(prev_cid, rotation_keys, verification_methods, also_known_as, services, sign_callback) → SignedPlcOp` following the same DAG-CBOR + ECDSA-SHA256 pattern as genesis but with `prev` field; `verify_plc_operation(signed_op_json, authorized_rotation_keys) → VerifiedPlcOp` generalized from `verify_genesis_op` to handle both genesis (`prev: null`) and rotation (`prev: cid`) ops; `compute_cid(signed_op_bytes) → String` for chaining `prev` references
- `crates/crypto/src/plc.rs` — `parse_audit_log(json) → Vec<AuditEntry>` for structured parsing of `plc.directory/{did}/log/audit` responses; `diff_audit_logs(cached, current) → Vec<NewOperation>` for detecting changes
- `crates/crypto/src/lib.rs` — re-export new public types

**Dependencies:** None (pure functional core, no I/O)

**Done when:** Rotation operations can be built and signed with an external signer callback; verification rejects ops with tampered `rotationKeys`, invalid `prev`, or bad signatures; CID computation matches plc.directory's format; audit log parsing handles real plc.directory JSON responses; tests pass covering plc-key-management.AC1
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Identity store — per-DID Keychain namespacing

**Goal:** Multi-identity persistence layer in the iOS Keychain with per-DID namespacing.

**Components:**
- `apps/identity-wallet/src-tauri/src/identity_store.rs` — `IdentityStore` struct wrapping Keychain operations with per-DID prefixed keys; `add_identity(did)`, `remove_identity(did)`, `list_identities() → Vec<String>`, `get_or_create_device_key(did) → PublicKey` (P-256, dispatching to Secure Enclave on real device), `store_did_doc(did, doc)`, `get_did_doc(did)`, `store_plc_log(did, log)`, `get_plc_log(did)`; top-level `"managed-dids"` key maintains JSON array of all managed DIDs
- `apps/identity-wallet/src-tauri/src/keychain.rs` — no structural changes, but `IdentityStore` uses existing `store_item`/`get_item`/`delete_item` with prefixed account names

**Dependencies:** None (Keychain helpers exist)

**Done when:** Multiple identities can be stored and retrieved independently; each identity has its own device key; DID doc and PLC log persistence round-trips correctly; tests pass covering plc-key-management.AC2
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: PDS discovery & OAuth to arbitrary PDS

**Goal:** Resolve AT Protocol handles to PDS endpoints and authenticate via OAuth PKCE+DPoP to any PDS.

**Components:**
- `apps/identity-wallet/src-tauri/src/pds_client.rs` — `PdsClient` struct wrapping `OAuthClient` with discovery methods: `resolve_handle(handle) → DID` (DNS TXT `_atproto.{handle}` with HTTP `/.well-known/atproto-did` fallback), `discover_pds(did) → pds_url` (fetch DID doc from plc.directory, extract `services.atproto_pds`), `discover_auth_server(pds_url) → AuthServerMetadata` (fetch `/.well-known/oauth-authorization-server`); XRPC methods: `request_plc_operation_signature()`, `sign_plc_operation(token, rotation_keys, ...)`, `get_recommended_did_credentials()`
- `apps/identity-wallet/src-tauri/src/lib.rs` — register `PdsClient` in `AppState` (or per-flow transient state)

**Dependencies:** Phase 2 (IdentityStore for persisting resolved identity info)

**Done when:** Handles resolve to DIDs via DNS and HTTP fallback; PDS endpoint is correctly extracted from DID docs; OAuth flow completes against bsky.social's authorization server; XRPC calls return expected responses; tests pass covering plc-key-management.AC3
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Claim flow backend — Tauri commands

**Goal:** Tauri commands orchestrating the complete claim flow from identity resolution through PLC operation submission.

**Components:**
- `apps/identity-wallet/src-tauri/src/claim.rs` — `resolve_identity(handle_or_did) → IdentityInfo`, `start_pds_auth(pds_url) → ()` (triggers OAuth, stores pending auth state), `request_claim_verification(did) → ()` (calls `requestPlcOperationSignature`), `sign_and_verify_claim(did, token) → VerifiedClaimOp` (calls `signPlcOperation` then verifies locally via crypto crate — checks `rotationKeys[0]`, `prev` chain, no unexpected mutations), `submit_claim(did) → ClaimResult` (POSTs to plc.directory, persists to IdentityStore)
- `apps/identity-wallet/src-tauri/src/lib.rs` — register claim commands in `generate_handler![]`
- `apps/identity-wallet/src/lib/ipc.ts` — typed wrappers for all claim commands

**Dependencies:** Phase 1 (crypto verification), Phase 2 (IdentityStore), Phase 3 (PdsClient)

**Done when:** Full claim flow executes end-to-end in integration tests (mocked PDS + mocked plc.directory); local verification catches tampered operations; error codes surface correctly via IPC; tests pass covering plc-key-management.AC4
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Claim flow frontend — import screens and state machine

**Goal:** User-facing import flow with mode selector, 5-screen sequence, and multi-identity home.

**Components:**
- `apps/identity-wallet/src/routes/+page.svelte` — add mode selector as new entry point (`mode_select` step); add import flow steps (`identity_input`, `pds_auth`, `email_verification`, `review_operation`, `claim_success`); wire `onMount` to check `listIdentities()` — if identities exist, skip to home; evolve home screen to show identity list instead of single identity
- `apps/identity-wallet/src/lib/components/import/IdentityInputScreen.svelte` — handle/DID input, calls `resolveIdentity()`, displays current PDS and rotation key state
- `apps/identity-wallet/src/lib/components/import/PdsAuthScreen.svelte` — shows PDS name, triggers `startPdsAuth()`, listens for `auth_ready`
- `apps/identity-wallet/src/lib/components/import/EmailVerificationScreen.svelte` — token input, calls `requestClaimVerification()` then `signAndVerifyClaim()`
- `apps/identity-wallet/src/lib/components/import/ReviewOperationScreen.svelte` — displays `OpDiff` (added/removed keys, changed services), warnings, confirm/cancel
- `apps/identity-wallet/src/lib/components/import/ClaimSuccessScreen.svelte` — confirmation with updated DID doc summary
- `apps/identity-wallet/src/lib/components/home/IdentityListHome.svelte` — replaces single-identity HomeScreen; renders identity cards with status badges; "+" button returns to mode selector

**Dependencies:** Phase 4 (all claim Tauri commands)

**Done when:** Mode selector correctly branches between create and import; import flow navigates through all 5 screens; error rewinding works (bad token → stay on email screen); multi-identity home shows all claimed identities; tests pass covering plc-key-management.AC5
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: PLC monitoring & alerting

**Goal:** Detect unauthorized PLC operations and alert the user within the 72-hour recovery window.

**Components:**
- `apps/identity-wallet/src-tauri/src/plc_monitor.rs` — `PlcMonitor` struct: `check_for_changes(did) → Vec<UnauthorizedChange>` fetches `plc.directory/{did}/log/audit`, diffs against cached log (via crypto crate's `diff_audit_logs`), classifies ops as authorized (signed by our device key) or unauthorized; `check_all() → Vec<(String, Vec<UnauthorizedChange>)>` iterates all managed DIDs; called on app foreground + 15-min timer via `tokio::time::interval`
- `apps/identity-wallet/src-tauri/src/lib.rs` — register `check_identity_status` and `list_identities` commands; start monitoring timer in Tauri setup; register iOS background fetch task (best-effort)
- `apps/identity-wallet/src/lib/components/home/IdentityListHome.svelte` — alert badge (red) on identity cards with `alertCount > 0`; tap navigates to identity detail with alert list
- `apps/identity-wallet/src/lib/components/home/AlertDetailScreen.svelte` — shows unauthorized change details: signing key, timestamp, recovery deadline countdown, "Review & Override" button

**Dependencies:** Phase 1 (audit log parsing), Phase 2 (IdentityStore for cached logs), Phase 5 (home screen)

**Done when:** Monitor detects new operations in the audit log; authorized ops update cache silently; unauthorized ops surface as alerts with correct 72h deadline; home screen shows alert badges; tests pass covering plc-key-management.AC6
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Recovery override

**Goal:** Build and submit counter-operations to override unauthorized PLC changes using the device key's root authority.

**Components:**
- `apps/identity-wallet/src-tauri/src/recovery.rs` — `build_recovery_override(did, unauthorized_op_cid) → SignedRecoveryOp`: fetches full audit log, identifies the fork point (last legitimate op before the unauthorized one), builds a new PLC rotation op with `prev` = fork point CID and the pre-unauthorized `rotationKeys`/`services`/`verificationMethods`, signs with device key via crypto crate's `build_did_plc_rotation_op` with external signer; `submit_recovery_override(did) → ClaimResult`: POSTs the signed op to plc.directory, updates cached log
- `apps/identity-wallet/src-tauri/src/lib.rs` — register recovery commands
- `apps/identity-wallet/src/lib/ipc.ts` — typed wrappers for recovery commands
- `apps/identity-wallet/src/lib/components/home/RecoveryOverrideScreen.svelte` — shows the counter-operation diff, confirm/cancel, deadline countdown

**Dependencies:** Phase 1 (rotation op building + signing), Phase 2 (IdentityStore), Phase 6 (monitoring detects the unauthorized change)

**Done when:** Recovery override builds a valid counter-operation referencing the correct fork point; device key signature is valid; submission to plc.directory succeeds; cached log updates after override; expired recovery windows are rejected with clear error; tests pass covering plc-key-management.AC7
<!-- END_PHASE_7 -->

## Additional Considerations

### Recovery: phone loss and upgrade

The device key lives in the Secure Enclave and is non-extractable. Losing the device means losing the key. Recovery depends on which keys remain in the DID's `rotationKeys`:

**Re-claim via old PDS (always available).** The old PDS's key persists in `rotationKeys` after the initial claim. The user authenticates to the old PDS from a new device and repeats the XRPC claim flow. The old PDS signs a new PLC operation replacing the entire `rotationKeys` array — the lost device key is removed, the new device key takes `rotationKeys[0]`. For 72 hours, the lost device key retains override authority (it was `rotationKeys[0]` in the previous operation), but Secure Enclave non-extractability makes exploitation unlikely. After 72 hours, the new arrangement is permanent.

**Self-sovereign recovery via SSS (future work).** A software-based recovery key is generated alongside the device key, added to `rotationKeys[1]`, and Shamir-split into 2-of-3 shares. If the device is lost, reconstructing 2 shares yields a key that outranks the old PDS key and can sign a new rotation op without PDS cooperation. This is the higher-sovereignty recovery path but requires additional implementation: software key generation, Shamir splitting (crypto crate already supports this), share distribution, and a reconstruction + signing flow on a new device.

**Key ordering after claim:**
- `rotationKeys[0]` — user's device key (root authority, Secure Enclave)
- `rotationKeys[1]` — old PDS key (preserved for re-claim recovery path)
- Future with SSS: `rotationKeys[0]` device, `rotationKeys[1]` software recovery key, `rotationKeys[2]` old PDS key

**The 72-hour recovery window.** A higher-priority key (lower index) does not prevent lower-priority keys from signing new operations. Any rotation key can sign any new operation that replaces the entire `rotationKeys` array. However, plc.directory remembers the old key hierarchy for 72 hours: during this window, a higher-priority key from the previous state can override (revert) operations signed by lower-priority keys. After 72 hours, the override window closes and the new state is permanent. This means recovery is time-sensitive — the user must act within 72 hours of detecting an unauthorized change.

### Server-side monitoring service (future work)

iOS background fetch has a minimum interval of 15 minutes and the OS aggressively throttles apps that aren't in active use. For reliable 72-hour coverage, a server-side monitoring service should poll plc.directory on behalf of registered DIDs and send push notifications to the wallet. This is an optional opt-in service that introduces a server dependency — acceptable as an enhancement to the standalone client-side polling, not a replacement.

### Backward compatibility with existing onboarding

The mode selector is additive — the existing "create new identity" flow is unchanged. Users who have already onboarded via the relay flow see the multi-identity home screen on upgrade, with their existing identity appearing as a managed identity (migrated from flat Keychain keys to per-DID namespaced keys on first launch).
