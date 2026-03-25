# MM-149 OAuth PKCE Client Implementation Plan

**Goal:** Implement PKCE generation utilities and the PAR HTTP call that kicks off the authorization flow.

**Architecture:** PKCE is pure crypto: 32 OS-random bytes → base64url (verifier), then SHA-256 → base64url (challenge). The state parameter is 16 OS-random bytes → base64url. The PAR call is a new `par()` method on `RelayClient` that POSTs form-urlencoded data and returns a `request_uri`. This is the first outbound call in the OAuth round-trip.

**Tech Stack:** `rand_core = "0.6"` (OsRng), `sha2 = "0.10"`, `base64 = "0.21"`, `reqwest 0.12` (+ `form` feature)

**Scope:** 7 phases from original design (phase 4 of 7)

**Codebase verified:** 2026-03-23

---

## Acceptance Criteria Coverage

This phase implements and tests:

### MM-149.AC1: PAR flow completes successfully
- **MM-149.AC1.1 Success:** `start_oauth_flow` posts to `/oauth/par` with a valid DPoP proof and receives a `request_uri` (201 response)
- **MM-149.AC1.3 Failure:** PAR request with unknown `client_id` returns a client error (relay rejects it)
- **MM-149.AC1.4 Failure:** PAR request missing `code_challenge` returns a client error

> AC1.2 (Authorization URL opened in Safari) is verified in Phase 5 with the full `start_oauth_flow` command. AC1.1 is tested here as an integration test against a running relay.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->
### Task 1: Add rand_core and reqwest form feature

**Verifies:** None (infrastructure)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/Cargo.toml`

Two changes:
1. `rand_core` workspace dep is needed for PKCE random bytes (`OsRng.fill_bytes()`). The workspace dep already has `features = ["getrandom"]`.
2. `reqwest`'s `.form()` method requires the `form` cargo feature — without it, `.form()` does not exist on the request builder.

**Step 1: Add rand_core and update reqwest features**

In `apps/identity-wallet/src-tauri/Cargo.toml`, add `rand_core = { workspace = true }` and update reqwest's features:

Before:
```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

After:
```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "form"] }
rand_core = { workspace = true }
```

**Step 2: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Implement PKCE utilities in oauth.rs

**Verifies:** Part of MM-149.AC1.1 (pkce verifier/challenge used in PAR call); tested directly in Task 4

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs`

PKCE is defined by RFC 7636. The code_verifier is 43-128 URL-safe characters (32 OS-random bytes → base64url gives exactly 43 unreserved chars). The code_challenge is the S256 transform: `base64url(sha256(ascii(verifier)))`.

**Step 1: Add imports**

Add at the top of oauth.rs, after the existing `use` statements:

```rust
use rand_core::{OsRng, RngCore};
```

**Step 2: Add the pkce module**

Add inside `oauth.rs` (after the `DPoPKeypair` impl, before `#[cfg(test)]`):

```rust
// ── PKCE utilities ────────────────────────────────────────────────────────────

pub mod pkce {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};

    /// Generate a PKCE code_verifier and code_challenge pair.
    ///
    /// - `verifier`: 32 OS-random bytes base64url-encoded (43 chars, all unreserved per RFC 7636 §4.1)
    /// - `challenge`: `base64url(SHA-256(verifier))` (S256 method per RFC 7636 §4.2)
    ///
    /// Returns `(verifier, challenge)`.
    pub fn generate() -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        (verifier, challenge)
    }
}

/// Generate a CSRF state parameter: 16 OS-random bytes base64url-encoded (22 chars).
pub fn generate_state_param() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
```

**Step 3: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors.

<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->
### Task 3: Add PAR call to RelayClient in http.rs

**Verifies:** MM-149.AC1.1 (PAR returns 201 with request_uri)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/http.rs`

The relay's PAR endpoint (`POST /oauth/par`) accepts `application/x-www-form-urlencoded`. The `DPoP` header is sent per RFC 9449 §6 (the relay currently ignores it at PAR, but it's spec-correct to include it). The function returns a typed `ParResponse` on 201, and `OAuthError::ParFailed` on any other status.

**Step 1: Read the full current `http.rs`**

Open `apps/identity-wallet/src-tauri/src/http.rs` to see the full current content (approximately 80 lines). Note the imports and the `RelayClient` struct definition.

**Step 2: Add imports and ParResponse at the top of http.rs**

Add at the top (after the existing `use` statements):

```rust
use crate::oauth::OAuthError;
```

Add the `ParResponse` type after the existing struct definitions but before the `impl RelayClient` block:

```rust
/// Successful response from `POST /oauth/par` (RFC 9126 §2.2).
#[derive(Debug, serde::Deserialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u32,
}
```

**Step 3: Add the `par()` method to `impl RelayClient`**

Add after the existing `post_with_bearer()` method:

```rust
/// POST `/oauth/par` — push the authorization request parameters to the relay.
///
/// Sends the required PKCE and OAuth parameters as `application/x-www-form-urlencoded`.
/// Includes a `DPoP` proof header per RFC 9449 §6.
///
/// `dpop_jkt` is the JWK thumbprint of the DPoP key; included as a form field for
/// servers that support PAR-level DPoP key binding (the relay currently ignores it,
/// but it is spec-correct to send it).
pub async fn par(
    &self,
    code_challenge: &str,
    state_param: &str,
    dpop_proof: &str,
    dpop_jkt: &str,
    login_hint: Option<&str>,
) -> Result<ParResponse, OAuthError> {
    let url = format!("{}/oauth/par", self.base_url);

    let mut fields = vec![
        ("client_id", "dev.malpercio.identitywallet"),
        ("redirect_uri", "dev.malpercio.identitywallet:/oauth/callback"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("state", state_param),
        ("response_type", "code"),
        ("scope", "atproto"),
        ("dpop_jkt", dpop_jkt),
    ];

    let hint_owned;
    if let Some(hint) = login_hint {
        hint_owned = hint.to_string();
        fields.push(("login_hint", &hint_owned));
    }

    let resp = self
        .client
        .post(&url)
        .header("DPoP", dpop_proof)
        .form(&fields)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "PAR request network error");
            OAuthError::ParFailed
        })?;

    let status = resp.status();
    if status.as_u16() != 201 {
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, body = %body, "PAR request failed");
        return Err(OAuthError::ParFailed);
    }

    resp.json::<ParResponse>().await.map_err(|e| {
        tracing::error!(error = %e, "PAR response deserialization failed");
        OAuthError::ParFailed
    })
}
```

**Step 4: Build to verify**

```bash
cargo build -p identity-wallet
```

Expected: builds without errors. If you get a lifetime error on `hint_owned`, move the `hint_owned` variable declaration before `fields` is defined (before the `let mut fields = ...` line).

<!-- END_TASK_3 -->

<!-- START_TASK_4 -->
### Task 4: Write PKCE unit tests and PAR integration test

**Verifies:** MM-149.AC1.1, MM-149.AC1.3 (relay rejects unknown client), MM-149.AC1.4 (PAR without code_challenge returns 4xx)

**Files:**
- Modify: `apps/identity-wallet/src-tauri/src/oauth.rs` (add tests to existing `#[cfg(test)]` module)

**Step 1: Add PKCE unit tests to the existing `#[cfg(test)]` mod in oauth.rs**

Inside the existing `#[cfg(test)]` module (from Phase 3), add:

```rust
    // PKCE tests
    #[test]
    fn pkce_verifier_is_43_unreserved_chars() {
        let (verifier, _) = pkce::generate();
        assert_eq!(verifier.len(), 43, "base64url of 32 bytes must be 43 chars");
        // RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assert!(
            verifier.chars().all(|c| c.is_alphanumeric() || "-._~".contains(c)),
            "verifier must consist only of unreserved chars: got {verifier}"
        );
    }

    #[test]
    fn pkce_challenge_equals_sha256_base64url_of_verifier() {
        use sha2::{Digest, Sha256};
        let (verifier, challenge) = pkce::generate();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected, "challenge must be base64url(sha256(verifier))");
    }

    #[test]
    fn state_param_is_22_chars() {
        let state = generate_state_param();
        assert_eq!(state.len(), 22, "base64url of 16 bytes must be 22 chars");
    }

    #[test]
    fn pkce_verifiers_are_unique() {
        let (v1, _) = pkce::generate();
        let (v2, _) = pkce::generate();
        assert_ne!(v1, v2, "each generate() call must produce a different verifier");
    }
```

**Step 2: Add a PAR integration test (requires running relay)**

Integration tests that need external services should be marked `#[ignore]` so they don't run in CI. They can be run explicitly with `cargo test -- --include-ignored` when the relay is available.

Add to the same test module:

```rust
    /// Integration test: PAR call against a running relay.
    ///
    /// Requires the relay to be running at http://localhost:8080 with the V013
    /// migration applied (identity-wallet client registered).
    ///
    /// Run with: cargo test -p identity-wallet par_integration -- --include-ignored --nocapture
    #[tokio::test]
    #[ignore = "requires running relay at localhost:8080"]
    async fn par_integration_returns_201_with_request_uri() {
        let relay = crate::http::RelayClient::new();
        let keypair = DPoPKeypair::get_or_create().expect("keypair must generate");
        // `htu` is embedded in the DPoP proof JWT claims (the `htu` claim per RFC 9449 §4.2),
        // not used for the HTTP request itself — `relay.par()` constructs the URL internally.
        let htu = format!("{}/oauth/par", crate::http::RelayClient::base_url());
        let dpop_proof = keypair.make_proof("POST", &htu, None, None)
            .expect("DPoP proof must build");
        let dpop_jkt = keypair.public_jwk_thumbprint();
        let (_, challenge) = pkce::generate();
        let state = generate_state_param();

        let resp = relay.par(&challenge, &state, &dpop_proof, &dpop_jkt, None)
            .await
            .expect("PAR must succeed");

        assert!(
            resp.request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
            "request_uri must use OAuth PAR URN scheme, got: {}",
            resp.request_uri
        );
        assert_eq!(resp.expires_in, 60);
    }
```

**Step 2b: Add a negative integration test for AC1.4 (PAR without code_challenge)**

Add to the same test module, immediately after `par_integration_returns_201_with_request_uri`:

```rust
    /// Integration test: PAR call missing code_challenge is rejected by relay.
    ///
    /// Verifies MM-149.AC1.4: the relay returns a client error (400) when
    /// code_challenge is absent from the PAR request.
    ///
    /// Run with: cargo test -p identity-wallet par_missing_challenge -- --include-ignored --nocapture
    #[tokio::test]
    #[ignore = "requires running relay at localhost:8080"]
    async fn par_missing_code_challenge_returns_client_error() {
        // Build a minimal PAR form body with no code_challenge field.
        let base_url = crate::http::RelayClient::base_url();
        let url = format!("{base_url}/oauth/par");
        let keypair = DPoPKeypair::get_or_create().expect("keypair must generate");
        let dpop_proof = keypair
            .make_proof("POST", &url, None, None)
            .expect("DPoP proof must build");

        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("DPoP", dpop_proof)
            .form(&[
                ("client_id", "dev.malpercio.identitywallet"),
                ("redirect_uri", "dev.malpercio.identitywallet:/oauth/callback"),
                ("code_challenge_method", "S256"),
                ("state", "somestate"),
                ("response_type", "code"),
                ("scope", "atproto"),
                // code_challenge intentionally omitted
            ])
            .send()
            .await
            .expect("request must reach relay");

        assert!(
            resp.status().is_client_error(),
            "relay must reject PAR without code_challenge with 4xx, got: {}",
            resp.status()
        );
    }
```

Note: this test requires `reqwest` in `[dev-dependencies]`. The build-dependency already exists in `[dependencies]` (from Task 1), so the test can use it directly with `reqwest::Client::new()` — no additional Cargo.toml change needed.

**Step 3: Run PKCE unit tests**

```bash
cargo test -p identity-wallet pkce
```

Expected: 4 tests pass (pkce_verifier, pkce_challenge, state_param, pkce_verifiers_unique).

**Step 4: Run all identity-wallet tests**

```bash
cargo test -p identity-wallet
```

Expected: all tests pass (the PAR integration tests are skipped due to `#[ignore]`).

**Step 5: (Optional, requires running relay) Run the PAR integration tests**

Start the relay in another terminal, then:

```bash
cargo test -p identity-wallet par_ -- --include-ignored --nocapture
```

Expected:
- `par_integration_returns_201_with_request_uri` passes (AC1.1)
- `par_missing_code_challenge_returns_client_error` passes with 400 (AC1.4)

**Step 6: Commit**

```bash
git add apps/identity-wallet/src-tauri/Cargo.toml
git add apps/identity-wallet/src-tauri/src/http.rs
git add apps/identity-wallet/src-tauri/src/oauth.rs
git commit -m "feat(identity-wallet): PKCE generation and PAR HTTP call (MM-149 phase 4)"
```

<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->
