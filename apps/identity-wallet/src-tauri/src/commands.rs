//! The IPC command table. Every `#[tauri::command]` the wallet registers is generated here
//! from one line naming its function, so the registered set and the functions behind it
//! cannot drift apart: a renamed function or a changed argument list is a compile error
//! here, and a command is registered exactly when it has a line.
//!
//! Each line is `[kind] ipc_name = path::to::function(ipc args) -> Ret;`. The kind says
//! whether the command is `async` or `sync`, and whether its function takes the app's
//! [`Core`](crate::oauth::Core) (`state`) ahead of its IPC arguments. The wrapper keeps the IPC name, argument names and types, and return type,
//! so the frontend's `invoke()` calls and `{ code }` error unions are unchanged.

macro_rules! commands {
    ($( [$($kind:ident)+] $name:ident = $($seg:ident)::+ ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty ; )*) => {
        $( commands!(@one [$($kind)+] $name = $($seg)::+ ($($arg : $ty),*) -> $ret); )*

        /// The invoke handler `run()` installs: every command above, and nothing else.
        pub(crate) fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
            tauri::generate_handler![$($name),*]
        }
    };
    (@one [async state] $name:ident = $($seg:ident)::+ ($($arg:ident : $ty:ty),*) -> $ret:ty) => {
        #[tauri::command]
        #[allow(clippy::too_many_arguments)]
        pub async fn $name(state: tauri::State<'_, crate::oauth::Core>, $($arg: $ty),*) -> $ret {
            $($seg)::+(&state, $($arg),*).await
        }
    };
    (@one [async] $name:ident = $($seg:ident)::+ ($($arg:ident : $ty:ty),*) -> $ret:ty) => {
        #[tauri::command]
        #[allow(clippy::too_many_arguments)]
        pub async fn $name($($arg: $ty),*) -> $ret {
            $($seg)::+($($arg),*).await
        }
    };
    (@one [sync] $name:ident = $($seg:ident)::+ ($($arg:ident : $ty:ty),*) -> $ret:ty) => {
        #[tauri::command]
        #[allow(clippy::too_many_arguments)]
        pub fn $name($($arg: $ty),*) -> $ret {
            $($seg)::+($($arg),*)
        }
    };
}

commands! {
    [async state] create_account = obsign_core::create_flow::create_account(claim_code: String, email: String, handle: String) -> Result<obsign_core::create_flow::CreateAccountResult, obsign_core::create_flow::CreateAccountError>;
    [async state] perform_did_ceremony = obsign_core::create_flow::perform_did_ceremony(handle: String, password: Option<String>) -> Result<obsign_core::create_flow::DIDCeremonyResult, obsign_core::create_flow::DIDCeremonyError>;
    [sync] confirm_share_backup = obsign_core::create_flow::confirm_share_backup(did: String) -> Result<(), obsign_core::share_recovery::ShareBackupError>;
    [async state] prepare_did_web_ceremony = obsign_core::create_flow::prepare_did_web_ceremony() -> Result<obsign_core::create_flow::DidWebPreparation, obsign_core::create_flow::DIDCeremonyError>;
    [async state] complete_did_web_ceremony = obsign_core::create_flow::complete_did_web_ceremony(document_text: String, password: Option<String>, enable_managed_hosting: bool) -> Result<obsign_core::create_flow::DIDCeremonyResult, obsign_core::create_flow::DIDCeremonyError>;
    [async state] register_handle = obsign_core::create_flow::register_handle(handle: String) -> Result<obsign_core::create_flow::RegisterHandleResult, obsign_core::create_flow::RegisterHandleError>;
    [async state] register_created_identity = obsign_core::create_flow::register_created_identity(did: String, handle: String) -> Result<(), obsign_core::create_flow::RegisterIdentityError>;
    [async state] import_did_web_identity = obsign_core::import_did_web::import_did_web_identity(input: String) -> Result<obsign_core::import_did_web::ImportedDidWebIdentity, obsign_core::import_did_web::ImportDidWebError>;
    [async state] check_handle_resolution = obsign_core::create_flow::check_handle_resolution(handle: String, expected_did: String) -> Result<bool, String>;
    [async state] get_available_user_domains = obsign_core::create_flow::get_available_user_domains() -> Result<Vec<String>, obsign_core::create_flow::AvailableDomainsError>;
    [sync] list_identities = obsign_core::identity_store::list_identities() -> Result<Vec<String>, obsign_core::identity_store::IdentityStoreError>;
    [sync] get_stored_did_doc = obsign_core::identity_store::get_stored_did_doc(did: String) -> Result<Option<serde_json::Value>, obsign_core::identity_store::IdentityStoreError>;
    [async state] refresh_did_doc = obsign_core::identity_store::refresh_did_doc(did: String) -> Result<serde_json::Value, obsign_core::identity_store::RefreshDidDocError>;
    [sync] get_device_key_id = obsign_core::identity_store::get_device_key_id(did: String) -> Result<String, obsign_core::identity_store::IdentityStoreError>;
    [sync] get_pds_url = obsign_core::pds_config::get_pds_url() -> Option<String>;
    [async state] save_pds_url = obsign_core::pds_config::save_pds_url(url: String) -> Result<(), obsign_core::pds_config::PdsConfigError>;
    [async state] get_pds_capabilities = obsign_core::pds_config::get_pds_capabilities(pds_url: Option<String>) -> Result<obsign_core::pds_capabilities::ServerCapabilities, obsign_core::pds_config::PdsConfigError>;
    [sync] get_appearance_preference = obsign_core::preferences::get_appearance_preference() -> Option<String>;
    [sync] set_appearance_preference = obsign_core::preferences::set_appearance_preference(preference: String) -> Result<(), obsign_core::preferences::AppearanceError>;
    [sync] export_diagnostics = crate::diagnostics::export_diagnostics() -> String;
    [async state] resolve_identity = crate::claim::resolve_identity(handle_or_did: String) -> Result<crate::claim::IdentityInfo, crate::claim::ResolveError>;
    [async state] authenticate_source_pds = crate::claim::authenticate_source_pds(did: String, identifier: String, password: String, auth_factor_token: Option<String>) -> Result<(), crate::claim::ClaimError>;
    [async state] request_claim_verification = crate::claim::request_claim_verification(did: String) -> Result<(), crate::claim::ClaimError>;
    [async state] sign_and_verify_claim = crate::claim::sign_and_verify_claim(did: String, token: String) -> Result<crate::claim::VerifiedClaimOp, crate::claim::ClaimError>;
    [async state] submit_claim = crate::claim::submit_claim(did: String) -> Result<crate::claim::ClaimResult, crate::claim::ClaimError>;
    [async state] list_agents = crate::agents::list_agents(did: String) -> Result<Vec<crate::agents::AgentSummary>, crate::agents::AgentsError>;
    [async state] revoke_agent = crate::agents::revoke_agent(did: String, registration_id: String) -> Result<(), crate::agents::AgentsError>;
    [async state] get_agent_audit = crate::agents::get_agent_audit(did: String, registration_id: String, cursor: Option<String>) -> Result<crate::agents::AgentAuditPage, crate::agents::AgentsError>;
    [async state] preview_agent_claim = crate::agents::preview_agent_claim(did: String, user_code: String) -> Result<crate::agents::AgentClaimPreview, crate::agents::AgentsError>;
    [async state] confirm_agent_claim = crate::agents::confirm_agent_claim(did: String, user_code: String) -> Result<crate::agents::AgentClaimConfirmation, crate::agents::AgentsError>;
    [sync] agent_accounts_provisioned = crate::agents::agent_accounts_provisioned(did: String) -> bool;
    [async state] mint_child_from_claim = crate::agents::mint_child_from_claim(did: String, user_code: String, handle: String) -> Result<crate::agents::MintedChild, crate::agents::AgentsError>;
    [async state] list_children = crate::agents::list_children(did: String) -> Result<Vec<crate::agents::ChildSummary>, crate::agents::AgentsError>;
    [async state] revoke_child = crate::agents::revoke_child(did: String, child_did: String) -> Result<(), crate::agents::AgentsError>;
    [async state] delete_child = crate::agents::delete_child(did: String, child_did: String) -> Result<crate::agents::ChildDeletion, crate::agents::AgentsError>;
    [async state] remint_child_assertion = crate::agents::remint_child_assertion(did: String, child_did: String) -> Result<crate::agents::ChildAssertion, crate::agents::AgentsError>;
    [async state] reconcile_children = crate::agents::reconcile_children(did: String) -> Result<crate::agents::ChildReconciliation, crate::agents::AgentsError>;
    [async state] preview_oauth_consent = crate::oauth_consent::preview_oauth_consent(did: String, user_code: String) -> Result<crate::oauth_consent::ConsentPreview, crate::oauth_consent::ConsentError>;
    [async state] preview_oauth_consent_by_request_id = crate::oauth_consent::preview_oauth_consent_by_request_id(did: String, request_id: String) -> Result<crate::oauth_consent::ConsentPreview, crate::oauth_consent::ConsentError>;
    [async state] confirm_oauth_consent = crate::oauth_consent::confirm_oauth_consent(did: String, request_id: String, client_id: String, decision: String, granted_scope: String, match_code: Option<String>) -> Result<crate::oauth_consent::ConsentDecision, crate::oauth_consent::ConsentError>;
    [async state] create_app_password = crate::app_passwords::create_app_password(did: String, name: String, privileged: bool, personal_details: bool) -> Result<crate::pds_client::AppPasswordCreated, crate::app_passwords::AppPasswordsError>;
    [async state] list_app_passwords = crate::app_passwords::list_app_passwords(did: String) -> Result<Vec<crate::pds_client::AppPasswordEntry>, crate::app_passwords::AppPasswordsError>;
    [async state] revoke_app_password = crate::app_passwords::revoke_app_password(did: String, name: String) -> Result<(), crate::app_passwords::AppPasswordsError>;
    [async] get_blob_backup_status = crate::blob_backup::get_blob_backup_status(did: String) -> Result<crate::blob_backup::BlobBackupStatus, crate::blob_backup::BlobBackupError>;
    [async] set_blob_backup_enabled = crate::blob_backup::set_blob_backup_enabled(did: String, enabled: bool) -> Result<crate::blob_backup::BlobBackupStatus, crate::blob_backup::BlobBackupError>;
    [async state] run_blob_backup = crate::blob_backup::run_blob_backup(did: String) -> Result<crate::blob_backup::BlobBackupRunReport, crate::blob_backup::BlobBackupError>;
    [async state] restore_blob_backup = crate::blob_backup::restore_blob_backup(did: String) -> Result<crate::blob_backup::BlobRestoreReport, crate::blob_backup::BlobBackupError>;
    [async] get_repo_backup_status = crate::repo_backup::get_repo_backup_status(did: String) -> Result<crate::repo_backup::RepoBackupStatus, crate::repo_backup::RepoBackupError>;
    [async] set_repo_backup_enabled = crate::repo_backup::set_repo_backup_enabled(did: String, enabled: bool) -> Result<crate::repo_backup::RepoBackupStatus, crate::repo_backup::RepoBackupError>;
    [async state] run_repo_backup = crate::repo_backup::run_repo_backup(did: String) -> Result<crate::repo_backup::RepoBackupRunReport, crate::repo_backup::RepoBackupError>;
    [sync] get_background_backup_settings = crate::bg_backup::get_background_backup_settings() -> crate::bg_backup::BackgroundBackupSettings;
    [sync] set_background_backup_settings = crate::bg_backup::set_background_backup_settings(settings: crate::bg_backup::BackgroundBackupSettings) -> Result<crate::bg_backup::BackgroundBackupSettings, crate::bg_backup::BackgroundBackupError>;
    [async state] register_for_notifications = crate::notifications::register_for_notifications(did: String) -> Result<crate::notifications::RegistrationOutcome, crate::notifications::NotificationsError>;
    [sync] get_notification_diagnostics = crate::notifications::get_notification_diagnostics() -> crate::notifications::NotificationDiagnostics;
    [sync] clear_notification_failures = crate::notifications::clear_notification_failures() -> ();
    [sync] take_pending_notification_route = crate::notification_routes::take_pending_notification_route() -> Option<crate::notification_routes::PendingNotificationRoute>;
    [async state] check_identity_status = crate::plc_monitor::check_identity_status() -> Result<Vec<crate::plc_monitor::IdentityStatus>, crate::plc_monitor::MonitorError>;
    [sync] get_monitor_history = crate::plc_monitor::get_monitor_history() -> crate::plc_monitor::MonitorHistory;
    [async state] build_recovery_override_cmd = crate::recovery::build_recovery_override_cmd(did: String, operation_cid: String) -> Result<crate::recovery::SignedRecoveryOp, crate::recovery::RecoveryError>;
    [async state] build_repo_key_rotation_cmd = crate::rotate_repo_key::build_repo_key_rotation_cmd(did: String) -> Result<crate::rotate_repo_key::SignedRotationOp, crate::rotate_repo_key::RotationError>;
    [async state] submit_repo_key_rotation_cmd = crate::rotate_repo_key::submit_repo_key_rotation_cmd(did: String) -> Result<crate::claim::ClaimResult, crate::rotate_repo_key::RotationError>;
    [async state] build_rekey_cmd = crate::rekey::build_rekey_cmd(did: String) -> Result<crate::rekey::RekeyPreview, crate::rekey::RekeyError>;
    [async state] submit_rekey_cmd = crate::rekey::submit_rekey_cmd(did: String) -> Result<crate::rekey::RekeyResult, crate::rekey::RekeyError>;
    [sync] confirm_rekey_cmd = crate::rekey::confirm_rekey_cmd(did: String) -> Result<(), crate::rekey::RekeyError>;
    [sync] rekey_in_progress_cmd = crate::rekey::rekey_in_progress_cmd(did: String) -> bool;
    [async state] build_self_held_kit_cmd = crate::self_held_kit::build_self_held_kit_cmd(did: String) -> Result<crate::self_held_kit::SelfHeldKitPreview, crate::self_held_kit::SelfHeldKitError>;
    [async state] submit_self_held_kit_cmd = crate::self_held_kit::submit_self_held_kit_cmd(did: String) -> Result<crate::self_held_kit::SelfHeldKitResult, crate::self_held_kit::SelfHeldKitError>;
    [sync] confirm_self_held_kit_cmd = crate::self_held_kit::confirm_self_held_kit_cmd(did: String) -> Result<(), crate::self_held_kit::SelfHeldKitError>;
    [sync] self_held_kit_in_progress_cmd = crate::self_held_kit::self_held_kit_in_progress_cmd(did: String) -> bool;
    [async state] submit_recovery_override_cmd = crate::recovery::submit_recovery_override_cmd(did: String) -> Result<crate::claim::ClaimResult, crate::recovery::RecoveryError>;
    [async state] get_identity_removal_route = crate::identity_removal::get_identity_removal_route(did: String) -> Result<crate::identity_removal::RemovalRoute, crate::identity_removal::RemovalError>;
    [async state] request_identity_removal = crate::identity_removal::request_identity_removal(did: String) -> Result<(), crate::identity_removal::RemovalError>;
    [async state] confirm_identity_removal = crate::identity_removal::confirm_identity_removal(did: String, password: Option<String>, token: String) -> Result<crate::identity_removal::RemovalOutcome, crate::identity_removal::RemovalError>;
    [async state] tombstone_identity = crate::identity_removal::tombstone_identity(did: String) -> Result<crate::identity_removal::RemovalOutcome, crate::identity_removal::RemovalError>;
    [sync] list_pending_removals = crate::identity_removal::list_pending_removals() -> Vec<String>;
    [sync] forget_identity_locally = crate::identity_removal::forget_identity_locally(did: String) -> Result<bool, crate::identity_removal::RemovalError>;
    [async state] detect_migration_path_cmd = crate::migrate::detect_migration_path_cmd(did: String) -> Result<crate::migrate::MigrationPathDecision, crate::migrate::MigrateError>;
    [async state] build_migration_op_cmd = crate::migrate::build_migration_op_cmd(did: String) -> Result<crate::migrate::SignedMigrationOp, crate::migrate::MigrateError>;
    [async state] submit_migration_op_cmd = crate::migrate::submit_migration_op_cmd(did: String) -> Result<crate::claim::ClaimResult, crate::migrate::MigrateError>;
    [async state] build_did_web_migration_document_cmd = crate::migrate::build_did_web_migration_document_cmd(did: String) -> Result<crate::migrate::DidWebMigrationDocument, crate::migrate::MigrateError>;
    [async state] submit_did_web_migration_document_cmd = crate::migrate::submit_did_web_migration_document_cmd(did: String, document_text: String, enable_managed_hosting: bool) -> Result<crate::claim::ClaimResult, crate::migrate::MigrateError>;
    [async state] prepare_migration = crate::migration_orchestrator::prepare_migration(did: String, dest_pds_url: String) -> Result<crate::migration_orchestrator::PreparedMigration, crate::migration_orchestrator::MigrationError>;
    [async state] authenticate_migration_source = crate::migration_orchestrator::authenticate_migration_source(did: String, identifier: String, password: String, auth_factor_token: Option<String>) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] create_destination_account = crate::migration_orchestrator::create_destination_account(did: String, email: String, invite_code: Option<String>) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] transfer_repo = crate::migration_orchestrator::transfer_repo(did: String) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] transfer_blobs = crate::migration_orchestrator::transfer_blobs(did: String, accept_loss: bool) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] transfer_preferences = crate::migration_orchestrator::transfer_preferences(did: String) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] verify_import = crate::migration_orchestrator::verify_import(did: String) -> Result<crate::pds_client::AccountStatus, crate::migration_orchestrator::MigrationError>;
    [async state] arm_identity_leg = crate::migration_orchestrator::arm_identity_leg(did: String) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] finalize_migration = crate::migration_orchestrator::finalize_migration(did: String) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] prepare_disaster_recovery = crate::disaster_recovery::prepare_disaster_recovery(did: String, dest_pds_url: String, handle_override: Option<String>) -> Result<crate::disaster_recovery::PreparedRecovery, crate::disaster_recovery::DisasterRecoveryError>;
    [async state] enroll_recovery_signing_key = crate::disaster_recovery::enroll_recovery_signing_key(did: String) -> Result<crate::disaster_recovery::RecoveryEnrollment, crate::disaster_recovery::DisasterRecoveryError>;
    [async state] await_recovery_key_visibility = crate::disaster_recovery::await_recovery_key_visibility(did: String) -> Result<crate::disaster_recovery::RecoveryKeyStatus, crate::disaster_recovery::DisasterRecoveryError>;
    [async state] create_recovery_destination_account = crate::disaster_recovery::create_recovery_destination_account(did: String, email: String, invite_code: Option<String>) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] recovery_transfer_repo = crate::disaster_recovery::recovery_transfer_repo(did: String) -> Result<(), crate::migration_orchestrator::MigrationError>;
    [async state] sovereign_login = crate::sovereign_session::sovereign_login(did: String) -> Result<crate::sovereign_session::SovereignLoginResult, crate::sovereign_session::SovereignLoginError>;
    [async state] ensure_identity_session = crate::session_provider::ensure_identity_session(did: String) -> Result<crate::session_provider::SessionReady, crate::session_provider::SessionError>;
    [async state] get_identity_unlock_route = crate::password_unlock::get_identity_unlock_route(did: String) -> Result<crate::password_unlock::UnlockRoute, crate::password_unlock::UnlockError>;
    [async state] unlock_identity_with_password = crate::password_unlock::unlock_identity_with_password(did: String, identifier: String, password: String, auth_factor_token: Option<String>) -> Result<crate::session_provider::SessionReady, crate::password_unlock::UnlockError>;
    [async state] change_handle_cmd = crate::handle_change::change_handle_cmd(did: String, handle: String) -> Result<crate::claim::ClaimResult, crate::handle_change::HandleChangeError>;
    [async state] get_identity_handle_domains = crate::handle_change::get_identity_handle_domains(did: String) -> Result<Vec<String>, crate::handle_change::HandleChangeError>;
    [async state] check_custom_handle_dns = crate::handle_change::check_custom_handle_dns(did: String, handle: String) -> Result<crate::handle_change::CustomHandleDnsCheck, crate::handle_change::HandleChangeError>;
    [async state] repair_hosting_endpoint = crate::endpoint_repair::repair_hosting_endpoint(did: String, new_endpoint: String) -> Result<crate::endpoint_repair::EndpointRepairResult, crate::endpoint_repair::EndpointRepairError>;
    [async state] start_share_recovery = crate::share_recovery::start_share_recovery(identifier: String) -> Result<crate::share_recovery::RecoveryTarget, crate::share_recovery::ShareRecoveryError>;
    [async state] add_recovery_share = crate::share_recovery::add_recovery_share(share: String) -> Result<crate::share_recovery::CollectedShare, crate::share_recovery::ShareRecoveryError>;
    [async state] initiate_escrow_release = crate::share_recovery::initiate_escrow_release() -> Result<(), crate::share_recovery::ShareRecoveryError>;
    [async state] request_escrow_release = crate::share_recovery::request_escrow_release(otp: Option<String>) -> Result<crate::share_recovery::EscrowReleaseStatus, crate::share_recovery::ShareRecoveryError>;
    [async state] verify_recovery_shares = crate::share_recovery::verify_recovery_shares() -> Result<crate::share_recovery::RecoveredIdentity, crate::share_recovery::ShareRecoveryError>;
    [async state] recover_identity = crate::share_recovery::recover_identity() -> Result<crate::share_recovery::RecoveryAnchor, crate::share_recovery::ShareRecoveryError>;
    [async state] run_recovery_epilogue = crate::share_recovery::run_recovery_epilogue(skip_escrow: Option<bool>) -> Result<crate::share_recovery::EpilogueResult, crate::share_recovery::ShareRecoveryError>;
    [sync] get_pending_recovery_epilogue = crate::share_recovery::get_pending_recovery_epilogue() -> Result<Option<crate::share_recovery::PendingEpilogue>, crate::share_recovery::ShareRecoveryError>;
    [async state] confirm_recovery_backup = crate::share_recovery::confirm_recovery_backup() -> Result<(), crate::share_recovery::ShareBackupError>;
}
