# Wallet Outbound Migration — Phase 2: Migration XRPC client surface

**Goal:** Provide a client function for every migration XRPC leg — public unauthenticated fetches on `PdsClient` and authenticated module-level helpers taking `&OAuthClient` — each issuing the correct method/path/auth and parsing its response, individually tested against a mock server.

**Architecture:** Follows the established `pds_client.rs` convention: module-level `async fn helper(client: &OAuthClient, ...) -> Result<T, PdsClientError>` that calls `client.get/post/post_bytes`, checks `status.is_success()`, and parses JSON (mirroring the existing `get_recommended_did_credentials` / `sign_plc_operation` / `request_plc_operation_signature`). Public reads that require no auth (`getRepo`, `getBlob`, `reserveSigningKey`) are methods on the stateless `PdsClient`.

**Tech Stack:** Rust, `reqwest`, `serde` (camelCase), `urlencoding` (already a dependency, used by `build_pds_authorize_url`), `httpmock` 0.8, `tokio` test runtime.

**Scope:** Phase 2 of 7.

**Codebase verified:** 2026-07-05.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### wallet-outbound-migration.AC7: The migration XRPC client surface exists
- **wallet-outbound-migration.AC7.1 Success:** Each new client function (`get_service_auth`, `create_account_migration`, `import_repo`, `upload_blob`, `list_missing_blobs`, `get_preferences`, `put_preferences`, `check_account_status`, `activate_account`, `deactivate_account`, `fetch_repo_car`, `fetch_blob`) issues the correct method, path, and auth, and parses its response.
- **wallet-outbound-migration.AC7.2 Success:** `get_service_auth` requests a token with `aud = dest_did` and `lxm = com.atproto.server.createAccount`.
- **wallet-outbound-migration.AC7.3 Success:** `fetch_repo_car`/`fetch_blob` use the unauthenticated `PdsClient` (the endpoints are `auth: none`).

---

## Verified server contracts (match these EXACTLY)

All handlers live in `crates/pds/src/routes/`. Field names below are the wire (JSON) names.

| XRPC | Method / Path | Auth | Request | Response (exact JSON keys) |
|---|---|---|---|---|
| getServiceAuth | `GET /xrpc/com.atproto.server.getServiceAuth?aud=&exp=&lxm=` | Bearer/DPoP (source access) | query: `aud` (req), `exp` (opt), `lxm` (opt) | `{ "token": "<JWT>" }` |
| reserveSigningKey | `POST /xrpc/com.atproto.server.reserveSigningKey` | **none** | `{ "did": "..." }` | `{ "signingKey": "did:key:z..." }` |
| createAccount (migration) | `POST /xrpc/com.atproto.server.createAccount` | Bearer (service-auth JWT) | `{ handle, email, did, inviteCode? }` | `{ accessJwt, refreshJwt, handle, did, didDoc? }` |
| importRepo | `POST /xrpc/com.atproto.repo.importRepo` | Bearer | CAR bytes, `Content-Type: application/vnd.ipld.car` | 200 empty |
| listMissingBlobs | `GET /xrpc/com.atproto.repo.listMissingBlobs?limit=&cursor=` | Bearer | query: `limit` (opt, def 500), `cursor` (opt) | `{ blobs: [{cid, recordUri}], cursor? }` |
| uploadBlob | `POST /xrpc/com.atproto.repo.uploadBlob` | Bearer | raw bytes, `Content-Type: <mime>` | `{ blob: { $type, ref: {$link}, mimeType, size } }` |
| getPreferences | `GET /xrpc/app.bsky.actor.getPreferences` | Bearer | — | `{ preferences: [ ... ] }` |
| putPreferences | `POST /xrpc/app.bsky.actor.putPreferences` | Bearer | `{ preferences: [ ... ] }` | 200 empty |
| checkAccountStatus | `GET /xrpc/com.atproto.server.checkAccountStatus` | Bearer | — | `{ activated, validDid, repoCommit?, repoRev?, storedBlocks, indexedRecords, privateStateValues, expectedBlobs, importedBlobs }` |
| activateAccount | `POST /xrpc/com.atproto.server.activateAccount` | Bearer | empty body (non-empty → 400) | 200 empty |
| deactivateAccount | `POST /xrpc/com.atproto.server.deactivateAccount` | Bearer | `{ deleteAfter? }` (RFC 3339) or empty | 200 empty |
| getRepo | `GET /xrpc/com.atproto.sync.getRepo?did=` | **none** | query: `did` (req), `since` (opt) | CAR bytes |
| getBlob | `GET /xrpc/com.atproto.sync.getBlob?did=&cid=` | **none** | query: `did`, `cid` | raw blob bytes |

**Two divergences from the canonical ATProto lexicon — match the ezpds server, not the spec:**
- `checkAccountStatus` returns **`storedBlocks`**, not the canonical `repoBlocks`. Type the field accordingly.
- `getServiceAuth` is a **GET with query params** here (the canonical lexicon marks it a query too, but some docs describe it as a POST — the ezpds handler reads query params).

**On the migration `createAccount` account model:** the ezpds handler creates a **deactivated, repo-less** account, requires `did` + `handle` + `email`, requires a **previously reserved signing key** (`get_reserved_repo_key_by_did` → else `InvalidClaim "no reserved signing key for this DID; call reserveSigningKey first"`), and stores a **NULL password** when none is supplied (OAuth-only migration). A DID that already has an account returns **HTTP 409 `DidAlreadyExists`** ("account already exists"). `inviteCode` is only required when the server has `inviteCodeRequired`.

## Verified codebase facts

File `apps/identity-wallet/src-tauri/src/pds_client.rs`:
- `PdsClient { client: Client (30s timeout), plc_directory_url: String }`; `new()`, `#[cfg(test)] new_for_test(plc_directory_url)`. Public POST example: `post_plc_operation(did, op)` posts JSON to `{plc_directory_url}/{did}`.
- Module-level helper template (`get_recommended_did_credentials`, lines 885–917; `sign_plc_operation`, 855–882; `request_plc_operation_signature`, 824–852): `client.get/post` → `if !status.is_success() { read body, return NetworkError }` → `resp.json::<T>().await.map_err(...)`.
- Request/response structs use `#[serde(rename_all = "camelCase")]`. Existing examples: `SignPlcOperationResponse { operation: Value }`, `RecommendedCredentials { rotation_keys, also_known_as, verification_methods, services }`.
- `PdsClientError` (lines 34–65): `#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`; variants `HandleNotFound`, `DidNotFound`, `PdsUnreachable { #[serde(skip)] reason }`, `NetworkError { message }`, `InvalidResponse { message }`, `OauthFailed { message }`.
- Tests use `httpmock::MockServer::start()` inline (not `#[ignore]`d for the bulk of them), FIFO mock registration, `.mock(|when, then| { ... })`.
- `OAuthClient::post_bytes(path, content_type, body)` and `OAuthClient::new_bearer(...)` land in Phase 1 and are used here.

## Design refinements folded into this phase (from verification)

1. **New `PdsClient::reserve_signing_key(pds_url, did)`** — the server hard-requires a reserved signing key before migration `createAccount`. Added to the client surface even though the design's AC7.1 list predates this finding.
2. **New `PdsClientError::DidAlreadyExists` variant** — so `create_account_migration` can surface a 409 that the orchestrator (Phase 3) tolerates for resume (AC5.1). Serializes to `{ "code": "DID_ALREADY_EXISTS" }`.
3. **`AccountStatus.stored_blocks`** (serde `storedBlocks`), not `repoBlocks`.
4. **`get_service_auth` builds a query string** with `urlencoding::encode` for `aud` and `lxm`, and calls `client.get(...)`.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Request/response types + `DidAlreadyExists` error variant

**Verifies:** wallet-outbound-migration.AC7.1 (types are the contract the helpers parse)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (add types near the existing struct block ~lines 171–239; add the error variant in `PdsClientError` at 34–65)

**Implementation:** Add these types (all `#[serde(rename_all = "camelCase")]` unless noted). Types don't need their own tests — the compiler checks them; the helper tests in Tasks 4–5 exercise their parsing.
```rust
#[derive(Debug, Deserialize)]
pub struct ServiceAuthToken { pub token: String }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountMigrationRequest {
    pub handle: String,
    pub email: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
    #[serde(default)]
    pub did_doc: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingBlob { pub cid: String, pub record_uri: String }

#[derive(Debug, Deserialize)]
pub struct MissingBlobs {
    pub blobs: Vec<MissingBlob>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub activated: bool,
    pub valid_did: bool,
    #[serde(default)]
    pub repo_commit: Option<String>,
    #[serde(default)]
    pub repo_rev: Option<String>,
    pub stored_blocks: i64,      // ezpds returns "storedBlocks" (NOT canonical "repoBlocks")
    pub indexed_records: u64,
    pub private_state_values: u64,
    pub expected_blobs: u64,
    pub imported_blobs: u64,
}

#[derive(Debug, Deserialize)]
pub struct UploadBlobResponse { pub blob: serde_json::Value }
```
Add to `PdsClientError`:
```rust
#[error("did already exists")]
DidAlreadyExists,     // {"code":"DID_ALREADY_EXISTS"}
```

**Testing:** None (types; compiler-verified). Parsing is proven by Tasks 4–5.

**Verification:**
```
cargo build -p identity-wallet
```
Expected: compiles.

**Commit:** `feat(wallet): migration XRPC request/response types + DidAlreadyExists`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Unauthenticated `PdsClient` fetches — repo CAR, blob, reserveSigningKey

**Verifies:** wallet-outbound-migration.AC7.1, wallet-outbound-migration.AC7.3

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (add methods on `impl PdsClient`)

**Implementation:** These endpoints are `auth: none`, so they use `PdsClient`'s own reqwest `client` (not an `OAuthClient`). Take the destination/source `pds_url` explicitly (the `PdsClient` is not bound to a base URL for XRPC calls).
```rust
/// GET com.atproto.sync.getRepo (auth: none) → full repo CAR bytes.
pub async fn fetch_repo_car(&self, pds_url: &str, did: &str) -> Result<Vec<u8>, PdsClientError> {
    // GET {pds_url}/xrpc/com.atproto.sync.getRepo?did={urlencoded did}
    // on !success -> NetworkError; else resp.bytes().await -> Vec<u8>
}

/// GET com.atproto.sync.getBlob (auth: none) → raw blob bytes.
pub async fn fetch_blob(&self, pds_url: &str, did: &str, cid: &str) -> Result<Vec<u8>, PdsClientError> {
    // GET {pds_url}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}
}

/// POST com.atproto.server.reserveSigningKey (auth: none, idempotent by DID) → reserved key id.
pub async fn reserve_signing_key(&self, pds_url: &str, did: &str) -> Result<String, PdsClientError> {
    // POST {pds_url}/xrpc/com.atproto.server.reserveSigningKey  body {"did": did}
    // parse { signingKey } (camelCase) -> String
}
```
Use `urlencoding::encode` for `did`/`cid` in query strings. Map non-2xx to `PdsClientError::NetworkError { message }` with the status + body (mirroring the existing helpers).

**Testing (inline `httpmock`, matching `pds_client.rs` style — not `#[ignore]`):**
Tests must verify:
- AC7.3: `fetch_repo_car` issues `GET .../xrpc/com.atproto.sync.getRepo?did=...` **with no Authorization header** and returns the exact CAR bytes the mock served.
- AC7.3: `fetch_blob` issues `GET .../xrpc/com.atproto.sync.getBlob?did=...&cid=...` with no auth and returns the exact blob bytes.
- AC7.1: `reserve_signing_key` POSTs `{"did":...}` to `.../reserveSigningKey` and parses `signingKey` from `{"signingKey":"did:key:z..."}`.

**Verification:**
```
cargo test -p identity-wallet --lib pds_client
```
Expected: three new tests pass.

**Commit:** `feat(wallet): PdsClient fetch_repo_car/fetch_blob/reserve_signing_key`
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-5) -->

<!-- START_TASK_3 -->
### Task 3: Auth setup helpers — `get_service_auth`, `create_account_migration`

**Verifies:** wallet-outbound-migration.AC7.1, wallet-outbound-migration.AC7.2

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (module-level helpers)

**Implementation:**
```rust
/// GET com.atproto.server.getServiceAuth on the SOURCE PDS. For migration, `aud` is the
/// destination server DID and `lxm` is "com.atproto.server.createAccount".
pub async fn get_service_auth(
    client: &crate::oauth_client::OAuthClient,
    aud: &str,
    lxm: &str,
) -> Result<ServiceAuthToken, PdsClientError> {
    let path = format!(
        "/xrpc/com.atproto.server.getServiceAuth?aud={}&lxm={}",
        urlencoding::encode(aud),
        urlencoding::encode(lxm),
    );
    // client.get(&path) -> check status -> resp.json::<ServiceAuthToken>()
}

/// POST com.atproto.server.createAccount in migration mode. `client` is a Bearer client
/// carrying the SOURCE-minted service-auth JWT (built by the orchestrator). Returns the
/// destination session tokens. A 409 maps to PdsClientError::DidAlreadyExists.
pub async fn create_account_migration(
    client: &crate::oauth_client::OAuthClient,
    req: &CreateAccountMigrationRequest,
) -> Result<CreateAccountResponse, PdsClientError> {
    let resp = client.post("/xrpc/com.atproto.server.createAccount", req).await
        .map_err(|e| PdsClientError::NetworkError { message: format!("createAccount failed: {e}") })?;
    let status = resp.status();
    if status.as_u16() == 409 {
        return Err(PdsClientError::DidAlreadyExists);
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(PdsClientError::NetworkError { message: format!("createAccount {status}: {body}") });
    }
    resp.json::<CreateAccountResponse>().await
        .map_err(|e| PdsClientError::NetworkError { message: format!("parse createAccount: {e}") })
}
```
(Confirmed: `create_account_xrpc.rs` maps the DID UNIQUE-violation to `ErrorCode::DidAlreadyExists`, and `common/src/error.rs:124` maps `ErrorCode::DidAlreadyExists` → **HTTP 409**. So keying on `status.as_u16() == 409` is correct — no body-code inspection is needed.)

**Testing (inline `httpmock`):**
- AC7.2: `get_service_auth(client, "did:web:dest", "com.atproto.server.createAccount")` issues a GET whose path/query contains `aud=did%3Aweb%3Adest` (url-encoded) and `lxm=com.atproto.server.createAccount`, and parses `token`.
- AC7.1: `create_account_migration` POSTs the camelCase body `{handle,email,did,inviteCode?}` and parses `{accessJwt,refreshJwt,handle,did}`.
- AC7.1 (resume seam): when the mock returns 409, `create_account_migration` returns `Err(PdsClientError::DidAlreadyExists)`.
- Build the `&OAuthClient` for these tests with a Bearer test client pointed at the mock `base_url` (see Phase 1's Bearer test helper). Assert the `Authorization` header is `Bearer ...`.

**Verification:**
```
cargo test -p identity-wallet --lib pds_client
```
Expected: getServiceAuth + createAccount tests pass.

**Commit:** `feat(wallet): get_service_auth + create_account_migration helpers`
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Data-transfer helpers — `import_repo`, `upload_blob`, `list_missing_blobs`, `get_preferences`, `put_preferences`

**Verifies:** wallet-outbound-migration.AC7.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (module-level helpers)

**Implementation:**
```rust
/// POST com.atproto.repo.importRepo — CAR bytes, Content-Type application/vnd.ipld.car.
pub async fn import_repo(client: &OAuthClient, car: Vec<u8>) -> Result<(), PdsClientError> {
    // client.post_bytes("/xrpc/com.atproto.repo.importRepo", "application/vnd.ipld.car", car)
    // -> check status.is_success() -> Ok(()) / NetworkError
}

/// POST com.atproto.repo.uploadBlob — raw bytes with the blob's MIME type.
pub async fn upload_blob(client: &OAuthClient, mime: &str, bytes: Vec<u8>) -> Result<UploadBlobResponse, PdsClientError> {
    // client.post_bytes("/xrpc/com.atproto.repo.uploadBlob", mime, bytes) -> json::<UploadBlobResponse>
}

/// GET com.atproto.repo.listMissingBlobs — one cursor page.
pub async fn list_missing_blobs(client: &OAuthClient, cursor: Option<&str>) -> Result<MissingBlobs, PdsClientError> {
    // path = "/xrpc/com.atproto.repo.listMissingBlobs" + optional "?cursor={urlencoded}"
    // client.get(&path) -> json::<MissingBlobs>
}

/// GET app.bsky.actor.getPreferences.
pub async fn get_preferences(client: &OAuthClient) -> Result<serde_json::Value, PdsClientError> {
    // client.get("/xrpc/app.bsky.actor.getPreferences") -> resp.json::<serde_json::Value>()
    // (return the full { preferences: [...] } object so put_preferences can echo it back)
}

/// POST app.bsky.actor.putPreferences — body is the { preferences: [...] } object.
pub async fn put_preferences(client: &OAuthClient, prefs: &serde_json::Value) -> Result<(), PdsClientError> {
    // client.post("/xrpc/app.bsky.actor.putPreferences", prefs) -> check status
}
```
`import_repo`/`upload_blob` depend on Phase 1's `post_bytes`. `list_missing_blobs` builds the `?cursor=` query only when `cursor.is_some()`.

**Testing (inline `httpmock`):**
- `import_repo` sends `Content-Type: application/vnd.ipld.car` and the exact CAR bytes (assert body + header); 200 → `Ok(())`.
- `upload_blob` sends the given `mime` as `Content-Type` and the exact bytes; parses `{blob:...}`.
- `list_missing_blobs(None)` issues the base path; `list_missing_blobs(Some("cur1"))` includes `cursor=cur1`; both parse `{blobs:[{cid,recordUri}],cursor?}`.
- `get_preferences` parses `{preferences:[...]}`; `put_preferences` posts the same object back and treats 200 as success.
- Use a Bearer test client for `client`; assert `Authorization: Bearer`.

**Verification:**
```
cargo test -p identity-wallet --lib pds_client
```
Expected: five helper tests pass.

**Commit:** `feat(wallet): importRepo/uploadBlob/listMissingBlobs/get+putPreferences helpers`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Lifecycle helpers — `check_account_status`, `activate_account`, `deactivate_account`

**Verifies:** wallet-outbound-migration.AC7.1

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/pds_client.rs` (module-level helpers)

**Implementation:**
```rust
/// GET com.atproto.server.checkAccountStatus.
pub async fn check_account_status(client: &OAuthClient) -> Result<AccountStatus, PdsClientError> {
    // client.get("/xrpc/com.atproto.server.checkAccountStatus") -> json::<AccountStatus>
}

/// POST com.atproto.server.activateAccount (empty body). Idempotent server-side.
pub async fn activate_account(client: &OAuthClient) -> Result<(), PdsClientError> {
    // client.post("/xrpc/com.atproto.server.activateAccount", &serde_json::json!({})) -> check status
    // NOTE: server rejects a NON-empty body with 400. serde_json::json!({}) serializes to "{}",
    // which the handler accepts as empty/whitespace-tolerant — verify against activate_account.rs;
    // if it requires a truly empty body, send no body via a dedicated post-with-empty-body path.
}

/// POST com.atproto.server.deactivateAccount, optional deleteAfter (RFC 3339).
pub async fn deactivate_account(client: &OAuthClient, delete_after: Option<&str>) -> Result<(), PdsClientError> {
    // body = match delete_after { Some(t) => json!({"deleteAfter": t}), None => json!({}) }
    // client.post("/xrpc/com.atproto.server.deactivateAccount", &body) -> check status
}
```
**Important:** verify `activateAccount`'s empty-body handling against `crates/pds/src/routes/activate_account.rs` (it returns 400 for a non-empty payload). The handler treats empty/whitespace bodies as valid; confirm that a `Content-Type: application/json` request with body `{}` is accepted, or send a genuinely empty body. Do the same check for `deactivateAccount` (`{}` vs empty).

**Testing (inline `httpmock`):**
- `check_account_status` parses all fields including `storedBlocks` (assert a value round-trips into `stored_blocks`), `validDid`, `expectedBlobs`, `importedBlobs`.
- `activate_account` / `deactivate_account` issue POSTs to the right paths and treat 200 as success. `deactivate_account(Some("2026-07-08T00:00:00.000Z"))` includes `deleteAfter` in the body; `deactivate_account(None)` omits it.

**Verification:**
```
cargo test -p identity-wallet --lib pds_client
```
Expected: status/activate/deactivate tests pass.

**Commit:** `feat(wallet): checkAccountStatus/activate/deactivate helpers`
<!-- END_TASK_5 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase 2 done when

- Every helper in AC7.1 (plus `reserve_signing_key`) exists with a mock-server test asserting method, path, auth header, and response parsing.
- `get_service_auth` sends `aud`/`lxm` as verified (AC7.2); `fetch_repo_car`/`fetch_blob` send no auth (AC7.3).
- `AccountStatus` deserializes `storedBlocks`; `create_account_migration` maps 409 → `DidAlreadyExists`.
- `cargo test -p identity-wallet --lib pds_client` passes.
- Covers wallet-outbound-migration.AC7.1–AC7.3.

(See Phase 1's "How to run tests" for the sandbox socket-binding note.)
