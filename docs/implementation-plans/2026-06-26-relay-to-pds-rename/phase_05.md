# Phase 05 — Frontend lockstep (identity-wallet / Obsign app)

**Goal:** Update the iOS app (SvelteKit frontend + Tauri Rust backend) to the new `pds` wire API and to internal `pds` naming, so it stays in sync with Phase 04. Lands in the same branch/PR.

**Architecture:** Three coupled surfaces: (1) the Tauri Rust HTTP client that calls the server's renamed routes/fields, (2) the `#[tauri::command]` IPC command names, and (3) the Svelte frontend that invokes those commands, renders status, and shows config UI. All three must rename together or the app breaks at runtime.

**Scope:** Phase 5 of 6.

**Codebase verified:** 2026-06-26 (exact Tauri-Rust symbol names to be confirmed by grep in Task 1 — the investigator located the Svelte/TS side precisely; the matching Rust `#[tauri::command]` definitions live in `apps/identity-wallet/src-tauri/`).

**Verifies:** None (refactor — verified by typecheck/app build).

> The relay CI gate excludes identity-wallet, so this phase is NOT covered by `just ci-pds`. Verify with the app's own build/typecheck (`pnpm` + `cargo build -p identity-wallet` / `cargo tauri` as the project does).

---

## ⚠️ UX-copy decision (user-facing strings)

Several UI strings say "relay" to the *user* (e.g. "Connect to a relay", "Held by the relay", "The relay hasn't been configured yet"). "PDS" is jargon for the mainstream half of the audience (see PRODUCT.md). **Recommendation:** user-facing copy should NOT say "PDS" or "relay" — use plain language ("your server", "Custos") consistent with the Obsign/Custos brand. This is a design-voice choice, not a mechanical rename.

**Default applied in this phase:** replace user-facing "relay" with **"Custos"** where a proper noun reads well ("Connect to Custos"), and **"server"** in sentence body ("Your wallet connects to a server to create your identity"). Flag the screen for a follow-up `/impeccable` copy pass. If the reviewer prefers different wording, adjust in Task 4.

---

<!-- START_TASK_1 -->
### Task 1: Inventory the three app surfaces

```bash
# Svelte/TS frontend
grep -rn -i 'relay' apps/identity-wallet/src/
# Tauri Rust backend (commands + HTTP client)
grep -rn -i 'relay' apps/identity-wallet/src-tauri/src/
```

Categorize:
- **IPC command names** (must match on both sides): `get_relay_url`, `save_relay_url` → `get_pds_url`, `save_pds_url`. Find the `#[tauri::command]` fn definitions in `src-tauri/` AND every `invoke('get_relay_url')`/`invoke('save_relay_url')` call in TS.
- **HTTP client** (`src-tauri/`): the code that calls `/v1/devices/:id/relay` (or `/v1/relay/keys`) and deserializes `relay_url`. Update paths → `/pds`, field → `pds_url` to match Phase 04.
- **Component / state / types:** `RelayConfigScreen.svelte`, `DEFAULT_RELAY_URL`, `RelayConfigError`, `relayHealthy`, route state `'relay_config'`.
- **User-facing copy:** the UX strings (handled per the decision above).

**Verification:** categorized list in scratchpad; IPC command pairs identified on both sides.
<!-- END_TASK_1 -->

<!-- START_SUBCOMPONENT_A (tasks 2-3) -->
<!-- START_TASK_2 -->
### Task 2: Rename the Tauri Rust backend (commands, client, types)

The iOS Rust backend (`apps/identity-wallet/src-tauri/src/`) carries ~250 Sense-A `relay` hits across 7 files. Rename per the tables below. **Confirm exact line numbers with the Task 1 grep before editing** (line numbers drift), but the *symbol* renames are fixed.

**`http.rs` — the client for OUR server:**

| Old | New |
|---|---|
| `struct RelayClient` (and all impls/refs) | `struct CustosClient` |
| `const RELAY_BASE_URL` | `const CUSTOS_BASE_URL` |
| `fn default_relay_url()` | `fn default_pds_url()` |
| doc-comment "All relay API calls go through `RelayClient`" | "All PDS API calls go through `CustosClient`" |
| request path `/v1/devices/:id/relay`, field `relay_url` | `/v1/devices/:id/pds`, `pds_url` (match Phase 04 canonical) |

> ⚠️ Rename `RelayClient` → **`CustosClient`**, NOT `PdsClient` — a *different* `PdsClient` already exists in `pds_client.rs` (generic handle/DID resolution). See overview constraint 6. Leave that `PdsClient` alone.

**`lib.rs`:**

| Old | New |
|---|---|
| `struct RelaySigningKey` | `struct PdsSigningKey` |
| `struct RelayErrorEnvelope`, `struct RelayErrorBody` | `PdsErrorEnvelope`, `PdsErrorBody` |
| `struct CreateHandleRelayResponse` | `CreateHandlePdsResponse` |
| `enum RelayConfigError` + variants `NoRelaySigningKey`, `RelayKeyFetchFailed` | `PdsConfigError` + `NoPdsSigningKey`, `PdsKeyFetchFailed` |
| `fn normalize_relay_url` | `fn normalize_pds_url` |
| `fn relay_client()` accessor | `fn custos_client()` |
| `#[tauri::command] get_relay_url` / `save_relay_url` | `get_pds_url` / `save_pds_url` (+ update `invoke_handler![...]`) |

**`home.rs`:**

| Old | New | Note |
|---|---|---|
| field `relay_healthy` | `pds_healthy` | `#[serde(rename_all="camelCase")]` ⇒ IPC field becomes `pdsHealthy`; TS side (Task 3) must change in lockstep |
| `fn ping_relay_health` | `ping_pds_health` | |
| `RelayClient` param/usages | `CustosClient` | |

**`oauth.rs`, `claim.rs`, `recovery.rs`:** rename Sense-A `relay`-named locals/fns/usages (incl. any `RelayClient` references → `CustosClient`). Use the Task 1 grep list; same Sense-A/B rule.

**`pds_client.rs` — leave the struct, rename ONLY the one Sense-A fn:**

| Old | New |
|---|---|
| `fn client_id_for_relay` | `fn client_id_for_pds` (it builds the OAuth client_id for *our* server) |

(Everything else in `pds_client.rs` is generic-PDS resolution — already correctly named; do not touch.)

**`keychain.rs` — rename fns, KEEP the storage-key string (overview constraint 7):**

| Old | New | Note |
|---|---|---|
| `fn store_relay_url` / `fn load_relay_url` | `store_pds_url` / `load_pds_url` | |
| `const RELAY_URL_ACCOUNT` (~line 81) | `const PDS_URL_ACCOUNT` | rename the *const name*; its *value* stays `"relay-base-url"` (below) |
| `fn delete_relay_url_test_only` (~line 181) | `delete_pds_url_test_only` | |
| keychain account string value `"relay-base-url"` | **KEEP `"relay-base-url"`** | renaming strands the configured URL for in-place upgraders |

Add a `// Keychain account string kept as "relay-base-url" for upgrade compatibility (see rename plan).` comment at the kept literal.

**Verification:** `cargo build -p identity-wallet` (or the project's Tauri build) compiles; `grep -rn 'Relay\|relay' src-tauri/src/ | grep -v 'relay-base-url'` → only Sense-B (none expected in src-tauri) and the kept keychain comment remain. IPC command + return-field names match the TS side after Task 3.
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Rename the Svelte/TS frontend

**Files (confirm via Task 1 grep):**
- Rename: `apps/identity-wallet/src/lib/components/onboarding/RelayConfigScreen.svelte` → `PdsConfigScreen.svelte` (or `ServerConfigScreen.svelte` — match the chosen user-facing noun; pick one and use it consistently). Update every import of it.
- `src/lib/ipc.ts` — `invoke('get_relay_url')`/`invoke('save_relay_url')` → `get_pds_url`/`save_pds_url`; `relayHealthy` → `pdsHealthy`; doc-comments.
- `src/lib/components/home/HomeScreen.svelte` — `homeData?.relayHealthy` → `pdsHealthy`.
- `src/routes/+page.svelte` — route-state union value `'relay_config'` → `'pds_config'`; update the comments referencing relay (Sense-A).
- `DEFAULT_RELAY_URL` → `DEFAULT_PDS_URL`; `RelayConfigError` → `PdsConfigError` (and its `code` checks).

**Implementation:** Use `git mv` for the component file; rename the TS identifiers; keep all behavior. Ensure the IPC command strings exactly match the Rust `#[tauri::command]` names from Task 2.

**Verification:** `pnpm check` / `pnpm svelte-check` (project's typecheck) passes; no unresolved imports of the old component path.
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_4 -->
### Task 4: Apply the user-facing copy decision, build, commit

**Files (UX strings):**
- `RecoveryInfoScreen.svelte` — "Held by the relay — stored during account setup" → "Held by Custos — stored during account setup" (or chosen wording).
- `DIDCeremonyScreen.svelte` — "The relay hasn't been configured yet. …" → "Custos hasn't been configured yet. …".
- `HandleRegistrationScreen.svelte` — "The relay has no handle domains configured. …" → "Custos has no handle domains configured. …".
- `PdsConfigScreen.svelte` — title "Connect to a relay" → "Connect to Custos"; subtitle "Your wallet connects to a relay to create your identity." → "Your wallet connects to a server to create your identity."; placeholder unchanged unless the default host changes.

**Step 1: Build/typecheck the app**
```bash
# from repo root, per project conventions:
pnpm --dir apps/identity-wallet check
cargo build -p identity-wallet
```
Expected: green. (Full `cargo tauri ios build` is a heavier macOS-only check — run if convenient, but typecheck + cargo build are sufficient for the rename gate.)

**Step 2: Commit**
```bash
git add -A
git commit -m "refactor(app)!: move identity-wallet to pds wire API + naming

Tauri commands get_pds_url/save_pds_url, HTTP client targets /pds and
reads pds_url, PdsConfigScreen, pdsHealthy, pds_config route state.
User-facing copy uses Custos/server (flagged for /impeccable copy pass).
Storage keys kept where renaming would strand upgrading users.

Lands with the server wire-API rename (phase 04)."
```

> After this phase, both Phase 04 and Phase 05 are committed on the branch and the app speaks the new API. The deprecated server aliases (Phase 04) can be removed in a later release once no old app build is in the field.
<!-- END_TASK_4 -->
