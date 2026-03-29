# Claim Flow Frontend — Phase 5: IdentityListHome

**Goal:** Replace the single-identity HomeScreen with a multi-identity IdentityListHome that shows all claimed identities with cards, status badges, and a "+" button to add another identity.

**Architecture:** Adds a `get_stored_did_doc` Tauri command to retrieve per-DID document data from Keychain. IdentityListHome calls `listIdentities()` to get all DIDs, then `getStoredDidDoc(did)` for each to extract handle and PDS info for display. The existing HomeScreen/DIDDocumentScreen/RecoveryInfoScreen remain but are reachable by tapping an identity card.

**Tech Stack:** Svelte 5 (runes), TypeScript, Tauri v2 IPC, Rust

**Scope:** 5 of 5 implementation phases

**Codebase verified:** 2026-03-29

---

## Acceptance Criteria Coverage

This phase implements and tests:

### plc-key-management.AC5: Import flow frontend
- **plc-key-management.AC5.11 Success:** Multi-identity home shows all claimed identities as cards with rotation key status badges
- **plc-key-management.AC5.12 Success:** "+" button on home navigates back to mode selector to add another identity
- **plc-key-management.AC5.13 Edge:** Existing onboarding flow (create new identity) remains functional and unchanged

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Add `get_stored_did_doc` Tauri command and IPC wrapper

**Verifies:** plc-key-management.AC5.11 (provides data for identity cards with rotation key status)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/lib.rs` (add command + register in invoke_handler)
- Modify: `apps/identity-wallet/src/lib/ipc.ts` (add wrapper)

**Implementation:**

**Rust side** — add two `#[tauri::command]` wrappers next to the `list_identities` command added in Phase 1. Note: `serde_json` is already a workspace dependency.

**Command 1: `get_stored_did_doc`** — wraps `IdentityStore::get_did_doc()` and returns parsed JSON:

```rust
#[tauri::command]
fn get_stored_did_doc(did: String) -> Result<Option<serde_json::Value>, identity_store::IdentityStoreError> {
    let store = identity_store::IdentityStore;
    match store.get_did_doc(&did)? {
        Some(json_str) => {
            let value: serde_json::Value = serde_json::from_str(&json_str)
                .map_err(|e| identity_store::IdentityStoreError::SerializationError {
                    message: e.to_string(),
                })?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}
```

**Command 2: `get_device_key_id`** — wraps `IdentityStore::get_or_create_device_key()` and returns the `keyId` (did:key URI) for comparing against rotation keys:

```rust
#[tauri::command]
fn get_device_key_id(did: String) -> Result<String, identity_store::IdentityStoreError> {
    let store = identity_store::IdentityStore;
    let device_key = store.get_or_create_device_key(&did)?;
    Ok(device_key.key_id)
}
```

`DevicePublicKey` has a `key_id` field (did:key URI, e.g. `did:key:z...`). This is the same value used by `resolve_identity` to check `deviceKeyIsRoot`.

Register both commands in `tauri::generate_handler![]`.

Register in `tauri::generate_handler![]` alongside `list_identities`.

**TypeScript side** — add to `ipc.ts` in the Identity Store section (after `listIdentities`):

```typescript
export const getStoredDidDoc = (did: string): Promise<Record<string, unknown> | null> =>
  invoke('get_stored_did_doc', { did });

export const getDeviceKeyId = (did: string): Promise<string> =>
  invoke('get_device_key_id', { did });
```

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

**Commit:** `feat(identity-wallet): add get_stored_did_doc Tauri command and IPC wrapper`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Create IdentityListHome component

**Verifies:** plc-key-management.AC5.11, plc-key-management.AC5.12, plc-key-management.AC5.13

**Files:**
- Create: `apps/identity-wallet/src/lib/components/home/IdentityListHome.svelte`

**Implementation:**

Create a multi-identity home screen that loads and displays all claimed identities.

**Props interface:**
```typescript
let {
  onadd,
  onselect,
}: {
  onadd: () => void;
  onselect: (did: string, didDoc: Record<string, unknown>) => void;
} = $props();
```

Import `listIdentities`, `getStoredDidDoc`, `getDeviceKeyId` from `$lib/ipc` and `DIDAvatar` from `./DIDAvatar.svelte`.

**Internal state:**
```typescript
interface IdentityCard {
  did: string;
  handle: string | null;
  pdsUrl: string | null;
  deviceKeyIsRoot: boolean | null;
}

let identities = $state<IdentityCard[]>([]);
let didDocs = $state<Map<string, Record<string, unknown>>>(new Map());
let loading = $state(true);
```

**Behavior:**

1. **On mount:** Load all identities:
   - Call `listIdentities()` to get DIDs
   - For each DID, in parallel:
     - Call `getStoredDidDoc(did)` to get the DID doc
     - Call `getDeviceKeyId(did)` to get the device key's did:key URI
   - Extract handle from `alsoKnownAs` (format: `at://{handle}` — extract after `at://`)
   - Extract PDS from `service` array (find entry where `id === '#atproto_pds'` or `type === 'AtprotoPersonalDataServer'`, get `serviceEndpoint`)
   - Determine `deviceKeyIsRoot`: extract `rotationKeys` array from the DID doc (via `verificationMethod`), check if the device key's did:key URI matches `rotationKeys[0]`. Set `null` if DID doc is missing or rotationKeys is unavailable.
   - Build `IdentityCard[]` and cache `didDocs` map for passing to detail views

2. **Render identity cards:**
   - Each card shows: `DIDAvatar` (reuse existing component), handle (`@{handle}` or "Unknown handle" if null), truncated DID (same truncation as HomeScreen), PDS endpoint
   - **Status badge (per AC5.11):**
     - `deviceKeyIsRoot === true`: green badge "Root Key" — device key is the primary rotation key
     - `deviceKeyIsRoot === false`: amber badge "Not Root" — device key is not the primary rotation key
     - `deviceKeyIsRoot === null`: gray badge "Unknown" — could not determine status
   - Cards are tappable — `onclick={() => onselect(card.did, didDocs.get(card.did)!)}`
   - Use the `.identity-card` styling from HomeScreen as the base pattern, add badge with status-dot pattern from HomeScreen's status indicators

3. **"+" button** (floating or at bottom of list):
   - "Add Identity" button → calls `onadd()`
   - Navigates to mode selector to start a new onboarding or import flow

4. **Empty state:** If `identities.length === 0`, show a friendly message ("No identities yet") with the "Add Identity" button

5. **Header:** "Identity Wallet" title with refresh button (same pattern as HomeScreen)

6. **Refresh:** `loadData()` function that re-fetches all identities, callable from refresh button

**Styling:** Follow HomeScreen patterns:
- `.screen` container with padding, column layout, gap
- `.header` with title + refresh button
- `.identity-card` cards (background: `#f9fafb`, border: `1px solid #d1d5db`, `12px` radius)
- Cards should be stacked vertically with `0.75rem` gap
- "+" button: `#007aff` primary style, full width at bottom

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): add IdentityListHome component`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->
<!-- START_TASK_3 -->
### Task 3: Wire IdentityListHome into +page.svelte

**Verifies:** plc-key-management.AC5.11, plc-key-management.AC5.12, plc-key-management.AC5.13

**Files:**
- Modify: `apps/identity-wallet/src/routes/+page.svelte`

**Implementation:**

**Step 1: Import IdentityListHome**
```typescript
import IdentityListHome from '$lib/components/home/IdentityListHome.svelte';
```

**Step 2: Replace the HomeScreen rendering** for the `home` step

Currently the `home` step renders `HomeScreen`. Update it to render `IdentityListHome` instead when the user has multiple identities, or keep `HomeScreen` as a detail view when an identity is selected:

Replace the existing `{:else if step === 'home'}` block. The new `home` step shows `IdentityListHome`:

```svelte
{:else if step === 'home'}
  <IdentityListHome
    onadd={() => goTo('mode_select')}
    onselect={(did, didDoc) => {
      selectedDid = did;
      selectedDidDoc = didDoc;
      goTo('identity_detail');
    }}
  />
```

**Step 3: Add `identity_detail` step** (new step for viewing a selected identity)

Add `'identity_detail'` to the `OnboardingStep` type union.

Add state variables for the selected identity:
```typescript
let selectedDid = $state<string | null>(null);
let selectedDidDoc = $state<Record<string, unknown> | null>(null);
```

Add the rendering block — reuse `DIDDocumentScreen` for the detail view:
```svelte
{:else if step === 'identity_detail'}
  <DIDDocumentScreen
    didDoc={selectedDidDoc ?? {}}
    onback={() => goTo('home')}
  />
```

**Step 4: Update ClaimSuccessScreen navigation**

In the `claim_success` rendering block, change `ondone` to navigate to `home` (which now shows IdentityListHome):
```svelte
ondone={() => goTo('home')}
```
(This should already be correct from Phase 4.)

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

**Commit:** `feat(identity-wallet): wire IdentityListHome as home screen with identity detail navigation`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Final build and flow verification

**Files:**
- No file changes — verification only

**Verification:**
Run: `cd apps/identity-wallet && pnpm check`
Expected: No type errors

Run: `cargo build -p identity-wallet --lib`
Expected: Compiles without errors

Run: `cargo test -p identity-wallet`
Expected: All existing Rust tests pass

Verify the complete flow compiles:
1. mode_select → relay_config → (existing onboarding) → home (IdentityListHome)
2. mode_select → identity_input → pds_auth → email_verification → review_operation → claim_success → home (IdentityListHome)
3. home → identity_detail (DIDDocumentScreen) → home
4. home → "+" → mode_select

**Commit:** No commit — verification only
<!-- END_TASK_4 -->
<!-- END_SUBCOMPONENT_B -->
