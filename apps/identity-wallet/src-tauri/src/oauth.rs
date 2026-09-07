// pattern: Mixed (unavoidable)

//! `AppState` (the app-wide Tauri-managed state) plus the wallet's OAuth DPoP client
//! machinery. The types (`AppState`, `OAuthSession`) are Functional Core.
//!
//! **`AppState` slots.** `oauth_session` (`std::sync::Mutex<Option<_>>`, cleanly empty
//! outside a flow — restored from Keychain-persisted tokens on startup; the create-flow login
//! that used to populate it live was retired, see below); `custos_client` (`OnceLock`, set
//! once from the Keychain URL or first-launch config, compile-time default otherwise);
//! `pds_client` (eager — cheap and stateless; exposed via [`AppState::pds_client`] for the
//! claim-flow commands); and the per-flow `tokio::sync::Mutex<Option<_>>` slots
//! (`claim_state`, `recovery_state`, `rotation_state`, `migration_state`,
//! `orchestration_state`, `share_recovery_state`) — tokio mutexes because those commands hold
//! the lock across `.await` points. Neither source login (claim, outbound migration) parks
//! OAuth state here: both are password `createSession` (`claim::authenticate_source_pds`,
//! `migration_orchestrator::authenticate_migration_source`).
//!
//! **The create-flow OAuth login has no live caller.** It used to be `prepare_oauth_flow`
//! (DPoP keygen + PKCE + PAR → authorize URL) and `complete_oauth_flow` (callback validation +
//! DPoP-bound token exchange into `oauth_session` and the Keychain), split around the in-app
//! `ASWebAuthenticationSession`; both were removed once the create flow started ending at
//! `home` with no OAuth round trip. The final authorize step was unreachable for a
//! passwordless account (a password form with no password to enter, and a wallet hand-off
//! pointing at the very app hosting the browser), and the evidence said it proved nothing —
//! `POST /v1/dids` already returns `status: "active"` plus a session token, `oauth_session`
//! had writers but zero readers, and `OAuthClient`'s DPoP mode has no production caller
//! (Bearer construction does not touch the shared [`DpopKeypair`] at all — a Bearer client's
//! `dpop` field is `None`, so it never generates or persists a key) because every
//! authenticated operation resolves a per-DID session
//! via `SessionProvider::full_access_client` (minted by `sovereign_login`/`password_unlock`
//! against the device key the genesis op pinned at `rotationKeys[0]`). [`DpopKeypair`], the
//! global `oauth-*` Keychain items, the `auth_ready` startup emit, and the vendored
//! `tauri-plugin-auth-session` remain — `OAuthClient`'s DPoP mode and the claim/migration
//! password logins still depend on them.
//!
//! Also here: [`DpopKeypair`] (P-256, persisted in Keychain and reused across flows so a
//! server can `jkt`-bind tokens to it) — the type itself, its Keychain wiring, and the
//! `custos_client::OAuthClient` adapters (diagnostics, token persistence) live in
//! `custos-client` and this module respectively; see the crate's own module docs for the
//! DPoP/XRPC machinery. [`OAuthError`] serializes as `{ code: "SCREAMING_SNAKE_CASE" }`; its
//! TypeScript union must match.

use std::sync::{Mutex, OnceLock};

pub use custos_client::{DpopKeypair, OAuthError, OAuthSession};

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide OAuth state registered via `.manage()` in lib.rs.
///
/// Option-wrapped so the state is cleanly empty before any OAuth flow starts and after a
/// flow completes.
pub struct AppState {
    /// The active authenticated session after a successful token exchange.
    /// Restored from the Keychain on startup; read by `OAuthClient` for every request.
    pub oauth_session: Mutex<Option<OAuthSession>>,
    /// Runtime custos client. Populated from Keychain on startup or by
    /// `save_pds_url` on first launch. Falls back to the compile-time default if unset.
    custos_client: OnceLock<crate::http::CustosClient>,
    /// PDS client for discovery and XRPC operations against arbitrary PDS endpoints.
    /// Stateless and cheap to construct; available to Tauri commands.
    pds_client: crate::pds_client::PdsClient,
    /// Claim flow state persisted across multi-step claim commands.
    /// Set by `resolve_identity`; used by subsequent `authenticate_source_pds`,
    /// `request_claim_verification`, `sign_and_verify_claim`, `submit_claim`.
    /// Uses tokio::sync::Mutex because claim commands hold the lock across .await points.
    pub claim_state: tokio::sync::Mutex<Option<crate::claim::ClaimState>>,
    /// Recovery override state persisted between build and submit.
    /// Set by `build_recovery_override` after signing; used by `submit_recovery_override`.
    /// Uses tokio::sync::Mutex because recovery commands hold the lock across .await points.
    pub recovery_state: tokio::sync::Mutex<Option<crate::recovery::RecoveryState>>,
    /// Repo signing-key rotation state persisted between build and submit.
    /// Set by `build_repo_key_rotation_cmd` after signing; used (and cleared on
    /// success) by `submit_repo_key_rotation_cmd`.
    /// Uses tokio::sync::Mutex because rotation commands hold the lock across .await points.
    pub rotation_state: tokio::sync::Mutex<Option<crate::rotate_repo_key::RotationState>>,
    /// Migration state persisted between build and submit of the self-signed identity leg.
    /// The authenticated destination-PDS client is populated by the migration orchestrator;
    /// `build_migration_op_cmd` reads it, `submit_migration_op_cmd` consumes the signed op.
    /// Uses tokio::sync::Mutex because migration commands hold the lock across .await points.
    pub migration_state: tokio::sync::Mutex<Option<crate::migrate::MigrationState>>,
    /// Outbound-migration orchestration state (in-memory only; an app kill restarts from
    /// `prepare_migration`). Tracks the DID, source/dest PDS URLs, OAuth clients, and phase
    /// across multiple outbound migration commands.
    /// Uses tokio::sync::Mutex because migration orchestrator commands hold the lock across .await points.
    pub orchestration_state:
        tokio::sync::Mutex<Option<crate::migration_orchestrator::OutboundMigrationState>>,
    /// Share-recovery ceremony state (collection → verify → re-anchor). In-memory by
    /// design: the pre-anchor phase is restartable from the entry screen, and the
    /// rotation epilogue persists its own durable Keychain record.
    /// Uses tokio::sync::Mutex because recovery commands hold the lock across .await points.
    pub share_recovery_state: tokio::sync::Mutex<Option<crate::share_recovery::ShareRecoveryState>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            oauth_session: Mutex::new(None),
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::PdsClient::new(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
            rotation_state: tokio::sync::Mutex::new(None),
            migration_state: tokio::sync::Mutex::new(None),
            orchestration_state: tokio::sync::Mutex::new(None),
            share_recovery_state: tokio::sync::Mutex::new(None),
        }
    }

    /// Returns the configured custos client, or initializes with the compile-time
    /// default URL if none has been set yet.
    pub fn custos_client(&self) -> &crate::http::CustosClient {
        self.custos_client
            .get_or_init(crate::http::CustosClient::new)
    }

    /// Set the custos client from a runtime URL. Silently ignored if already set
    /// (OnceLock::set semantics — this is only called once on first launch).
    pub fn set_custos_client(&self, url: String) {
        if self
            .custos_client
            .set(crate::http::CustosClient::new_with_url(url.clone()))
            .is_err()
        {
            tracing::warn!(url = %url, "set_custos_client: custos_client already initialized; ignoring");
        }
    }

    /// Returns the PDS client for discovery and XRPC operations.
    pub fn pds_client(&self) -> &crate::pds_client::PdsClient {
        &self.pds_client
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── DPoP keypair Keychain wiring ─────────────────────────────────────────────
//
// `DpopKeypair` itself (proof construction/signing) lives in `custos_client::dpop` — this is
// only the wallet's Keychain wiring for it, mirroring `device_key.rs`'s pattern.

/// Load or create the wallet's DPoP keypair via its real Keychain, at the same account this
/// module used before the `custos-client` extraction. `OAuthClient::new` (DPoP mode) has no
/// production caller today — see this module's doc — so this is currently reachable only from
/// tests; kept as the one production-shaped entry point a revived create-flow OAuth login would
/// call.
#[cfg(test)]
pub(crate) fn test_dpop_keypair() -> Result<DpopKeypair, custos_client::DpopError> {
    DpopKeypair::get_or_create::<crate::device_key::WalletKeychain>(
        crate::keychain::DPOP_KEY_PRIV_ACCOUNT,
    )
}

// ── custos_client adapters ───────────────────────────────────────────────────
//
// `OAuthClient` is Tauri-free; it takes its diagnostics and token-persistence seams as
// trait objects rather than calling `crate::diagnostics`/`crate::keychain` directly.

/// Records `OAuthClient` transport/server breadcrumbs into the wallet's exportable
/// diagnostics log.
pub(crate) struct WalletTransportObserver;

impl custos_client::TransportObserver for WalletTransportObserver {
    fn record_transport(&self, op: &str, url: Option<&str>, error: &reqwest::Error) {
        crate::diagnostics::record_reqwest_transport(op, url, error);
    }

    fn record_server(&self, op: &str, host: Option<&str>, status: u16, error_code: Option<&str>) {
        crate::diagnostics::record_server(op, host, status, error_code);
    }
}

/// Persists a DPoP-mode refreshed token pair to the wallet's legacy global OAuth-client
/// Keychain item (see `keychain.rs`'s module doc). `#[cfg(test)]`: only `OAuthClient::new`
/// (DPoP mode) would call this, and that constructor has no production caller today.
#[cfg(test)]
pub(crate) struct WalletTokenPersister;

#[cfg(test)]
impl custos_client::TokenPersister for WalletTokenPersister {
    fn store_tokens(&self, access_token: &str, refresh_token: &str) -> Result<(), String> {
        crate::keychain::store_oauth_tokens(access_token, refresh_token).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use custos_client::OAuthClient;
    use httpmock::prelude::*;
    use std::sync::{Arc, Mutex};

    /// End-to-end check of the wallet's own adapters (not `custos_client`'s internals, which
    /// the crate's own test suite covers): a DPoP-mode `OAuthClient` built with
    /// `device_key::WalletKeychain`, `WalletTransportObserver`, and `WalletTokenPersister`
    /// refreshes a token and the new pair lands in the wallet's real (test-mode in-memory)
    /// Keychain via `keychain::load_oauth_tokens`.
    #[tokio::test]
    async fn refresh_persists_tokens_through_wallet_keychain_adapter() {
        crate::keychain::clear_for_test();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST).path("/oauth/token");
            then.status(200).json_body(serde_json::json!({
                "access_token": "wallet-new-access",
                "token_type": "DPoP",
                "expires_in": 300,
                "refresh_token": "wallet-new-refresh",
                "scope": "atproto"
            }));
        });

        let keypair = test_dpop_keypair().expect("keypair must exist");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = Arc::new(Mutex::new(OAuthSession {
            access_token: "wallet-old-access".to_string(),
            refresh_token: "wallet-old-refresh".to_string(),
            expires_at: now, // already due for refresh
            dpop_nonce: None,
        }));
        let client = OAuthClient::new(
            keypair,
            "test-client-id".to_string(),
            session,
            server.base_url(),
            Arc::new(WalletTransportObserver),
            Arc::new(WalletTokenPersister),
        );

        client.refresh_token().await.expect("refresh must succeed");

        let (access, refresh) =
            crate::keychain::load_oauth_tokens().expect("tokens must be persisted");
        assert_eq!(access, "wallet-new-access");
        assert_eq!(refresh, "wallet-new-refresh");
    }

    /// End-to-end check of the redaction pipeline through the wallet's real
    /// `WalletTransportObserver` and `crate::diagnostics::export_diagnostics()`: a lazy-refresh
    /// transport failure must record exactly one breadcrumb, and the exported report must never
    /// contain the access/refresh tokens or any request-path detail (e.g. a DID query param).
    /// Uniquely-named markers, not a before/after count, since the diagnostics sink is a
    /// process-global shared across tests running in parallel.
    #[tokio::test]
    async fn lazy_refresh_transport_failure_records_a_redacted_breadcrumb() {
        // A bound-then-dropped listener: a real, briefly-valid port that is guaranteed closed
        // by the time the client connects, so the transport failure is deterministic across
        // platforms (unlike a fixed low port number, which may be filtered rather than refused).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let keypair = test_dpop_keypair().expect("keypair must exist");
        let session = Arc::new(Mutex::new(OAuthSession {
            access_token: "private-access-token-oauthrs-test".to_string(),
            refresh_token: "private-refresh-token-oauthrs-test".to_string(),
            expires_at: 0, // already due for refresh
            dpop_nonce: None,
        }));
        let client = OAuthClient::new(
            keypair,
            "test-client-id".to_string(),
            session,
            base_url,
            Arc::new(WalletTransportObserver),
            Arc::new(WalletTokenPersister),
        );

        let error = client
            .get("/resource?did=did:plc:private-identity-oauthrs-test")
            .await
            .unwrap_err();
        assert!(matches!(error, OAuthError::TokenRefreshFailed));

        let report = crate::diagnostics::export_diagnostics();
        assert!(
            report.contains("oauthRefresh"),
            "the transport failure must be recorded"
        );
        for secret in [
            "private-access-token-oauthrs-test",
            "private-refresh-token-oauthrs-test",
            "private-identity-oauthrs-test",
        ] {
            assert!(
                !report.contains(secret),
                "secret leaked into diagnostics report: {secret}"
            );
        }
    }
}
