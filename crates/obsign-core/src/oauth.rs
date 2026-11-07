// pattern: Mixed (unavoidable)

//! `Core` (the app-wide Tauri-managed state): the flow-state slots and both clients.
//!
//! **`Core` slots.** `custos_client` (`OnceLock`, set once from the Keychain URL or
//! first-launch config, compile-time default otherwise); `pds_client` (eager — cheap and
//! stateless; exposed via [`Core::pds_client`] for the claim-flow commands); and the per-flow
//! `tokio::sync::Mutex<Option<_>>` slots (`claim_state`, `recovery_state`, `rotation_state`,
//! `migration_state`, `orchestration_state`, `share_recovery_state`) — tokio mutexes because
//! those commands hold the lock across `.await` points. Neither source login (claim, outbound
//! migration) parks OAuth state here: both are password `createSession`
//! (`claim::authenticate_source_pds`, `migration_orchestrator::authenticate_migration_source`),
//! and every other authenticated operation resolves a per-DID session via
//! `SessionProvider::full_access_client` (minted by `sovereign_login`/`password_unlock`
//! against the device key the genesis op pinned at `rotationKeys[0]`).
//!
//! There is no global OAuth session and no DPoP key: the create flow ends at `home` with no
//! OAuth round trip. [`OAuthError`] serializes as `{ code: "SCREAMING_SNAKE_CASE" }`; its
//! TypeScript union must match.

use std::sync::OnceLock;

pub use custos_client::OAuthError;

// ── Shared state ──────────────────────────────────────────────────────────────

/// App-wide state registered via `.manage()` in lib.rs.
///
/// Flow slots are Option-wrapped so they are cleanly empty before a flow starts and after it
/// completes.
pub struct Core {
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
    /// The running app's bundle identifier (the APNs topic), set once by the shell at startup.
    app_identifier: OnceLock<String>,
}

impl Core {
    pub fn new() -> Self {
        Self {
            custos_client: OnceLock::new(),
            pds_client: crate::pds_client::new_with_diagnostics(),
            claim_state: tokio::sync::Mutex::new(None),
            recovery_state: tokio::sync::Mutex::new(None),
            rotation_state: tokio::sync::Mutex::new(None),
            migration_state: tokio::sync::Mutex::new(None),
            orchestration_state: tokio::sync::Mutex::new(None),
            share_recovery_state: tokio::sync::Mutex::new(None),
            app_identifier: OnceLock::new(),
        }
    }

    /// Returns the configured custos client, or initializes with the compile-time
    /// default URL if none has been set yet.
    pub fn custos_client(&self) -> &crate::http::CustosClient {
        self.custos_client
            .get_or_init(|| crate::http::new_configured(crate::http::default_pds_url().to_string()))
    }

    /// Set the custos client from a runtime URL. Silently ignored if already set
    /// (OnceLock::set semantics — this is only called once on first launch).
    pub fn set_custos_client(&self, url: String) {
        if self
            .custos_client
            .set(crate::http::new_configured(url.clone()))
            .is_err()
        {
            tracing::warn!(url = %url, "set_custos_client: custos_client already initialized; ignoring");
        }
    }

    /// Record the running app's bundle identifier. Ignored after the first call.
    pub fn set_app_identifier(&self, identifier: String) {
        let _ = self.app_identifier.set(identifier);
    }

    /// The running app's bundle identifier, read from its configuration rather than restated
    /// as a constant (see `notifications::register_for_notifications`). Empty until the shell
    /// sets it, which only tests skip.
    pub fn app_identifier(&self) -> &str {
        self.app_identifier.get().map(String::as_str).unwrap_or("")
    }

    /// Returns the PDS client for discovery and XRPC operations.
    pub fn pds_client(&self) -> &crate::pds_client::PdsClient {
        &self.pds_client
    }
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}
