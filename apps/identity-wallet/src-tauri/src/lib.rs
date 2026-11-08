//! Obsign wallet shell: the Tauri wiring around `obsign_core`. Every ceremony, client, and
//! `Core` itself live in that crate, re-exported here under each module's old name so
//! `crate::claim::…` still resolves; the IPC table is `commands.rs`. What lives *here*:
//!
//! - `run()` — the iOS/Android entry point (`#[cfg_attr(mobile, tauri::mobile_entry_point)]`;
//!   `main.rs` calls it on desktop). Its `setup` builds the platform adapters into the managed
//!   `Core`, restores the configured PDS URL, runs `obsign_core::startup_reconcile`, deletes the
//!   retired OAuth Keychain items, spawns the PLC monitoring loop, and on iOS
//!   registers the background jobs and the APNs bridge.
//! - `TauriEvents`, the `EventSink` adapter, and the `BGTaskScheduler` identifiers.

pub use obsign_core::agents;
/// The iOS APNs device-token bridge. iOS-only because it is nothing *but* platform plumbing:
/// every part with logic worth testing lives in [`notifications`].
#[cfg(target_os = "ios")]
pub mod apns;
pub use obsign_core::app_passwords;
/// The background-backup policy, under the name its Tauri commands and Keychain accounts have
/// always had.
pub use obsign_core::backup_policy as bg_backup;
pub use obsign_core::blob_backup;
pub use obsign_core::claim;
mod commands;
pub use obsign_core::device_key;
pub mod diagnostics;
pub use obsign_core::disaster_recovery;
pub use obsign_core::endpoint_repair;
pub use obsign_core::handle_change;
pub use obsign_core::http;
pub use obsign_core::identity_removal;
pub use obsign_core::identity_store;
pub mod keychain;
pub use obsign_core::migrate;
pub use obsign_core::migration_orchestrator;
pub use obsign_core::notification_routes;
pub use obsign_core::notifications;
pub use obsign_core::oauth;
pub use obsign_core::oauth_client;
pub use obsign_core::oauth_consent;
pub use obsign_core::password_unlock;
pub use obsign_core::pds_capabilities;
pub use obsign_core::pds_client;
pub use obsign_core::plc_monitor;
pub use obsign_core::recovery;
pub use obsign_core::rekey;
pub use obsign_core::repo_backup;
pub use obsign_core::rotate_repo_key;
pub use obsign_core::self_held_kit;
pub use obsign_core::session_provider;
pub use obsign_core::share_ceremony;
pub use obsign_core::share_recovery;
pub use obsign_core::source_login;
pub use obsign_core::sovereign_session;

use std::sync::Arc;

use tauri::{Emitter, Manager};

/// The `BGTaskScheduler` identifier for the background backup job. MUST match the entry in
/// `Info.ios.plist`'s `BGTaskSchedulerPermittedIdentifiers` (iOS refuses to register or submit an
/// identifier the plist doesn't permit), and is bundle-id-prefixed by Apple convention.
#[cfg(target_os = "ios")]
const BACKUP_TASK_IDENTIFIER: &str = "dev.malpercio.identitywallet.blob-backup";

/// The `BGTaskScheduler` identifier for the background PLC sweep, an app-refresh task (short,
/// and run through the day rather than overnight). Same plist rule as the backup identifier.
#[cfg(target_os = "ios")]
const PLC_CHECK_TASK_IDENTIFIER: &str = "dev.malpercio.identitywallet.plc-check";

/// The UI end of `obsign_core::events`: each event goes to the webview as a Tauri event.
struct TauriEvents(tauri::AppHandle);

impl obsign_core::events::EventSink for TauriEvents {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        if let Err(e) = self.0.emit(event, payload) {
            tracing::warn!(event, error = %e, "failed to emit event");
        }
    }
}

/// The PLC monitor's foreground timer: one sweep every `MONITOR_INTERVAL_SECS`, after letting
/// the app finish initializing. Missed ticks are delayed, not burst-fired, after iOS suspension.
async fn run_monitoring_loop(app: tauri::AppHandle) {
    use tokio::time::{interval, Duration, MissedTickBehavior};
    let mut interval = interval(Duration::from_secs(plc_monitor::MONITOR_INTERVAL_SECS));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        interval.tick().await;
        plc_monitor::run_monitoring_cycle_and_alert(&app.state::<oauth::Core>()).await;
    }
}

/// iOS only: register the background jobs with BGTaskScheduler (before app launch completes,
/// which `setup` does) and hand the scheduler to the `Core`. Off-device there is none and
/// background requests are dropped (scheduling is a device concern; the harness is untouched).
#[cfg(target_os = "ios")]
fn background_scheduler(
    app: &tauri::AppHandle,
) -> Option<Arc<dyn obsign_core::scheduler::Scheduler>> {
    use obsign_core::scheduler::BackgroundJob;
    use obsign_platform_ios::scheduler::{IosScheduler, TaskKind};
    let app_handle = app.clone();
    let scheduler = IosScheduler::new(
        vec![
            (
                BackgroundJob::BackupMirror,
                BACKUP_TASK_IDENTIFIER,
                TaskKind::Processing,
            ),
            (
                BackgroundJob::PlcCheck,
                PLC_CHECK_TASK_IDENTIFIER,
                TaskKind::AppRefresh,
            ),
        ],
        Arc::new(move |job, on_done| {
            let app = app_handle.clone();
            let worker = tauri::async_runtime::spawn(async move {
                obsign_core::scheduler::run(job, &app.state::<oauth::Core>()).await;
                on_done();
            });
            Box::new(move || worker.abort())
        }),
    );
    scheduler.register();
    Some(Arc::new(scheduler))
}

#[cfg(not(target_os = "ios"))]
fn background_scheduler(
    _app: &tauri::AppHandle,
) -> Option<Arc<dyn obsign_core::scheduler::Scheduler>> {
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[allow(
    clippy::expect_used,
    reason = "Tauri's run only fails when the app cannot start, which is fatal"
)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Debug)
                .build(),
        )
        // In-app OAuth session (ASWebAuthenticationSession on iOS/macOS). Invoked from the
        // frontend as `plugin:auth-session|start`; drives both the create-flow and claim-flow
        // PDS logins. (Replaced the deep-link + opener plugins, which depended on Safari
        // auto-launching the app from a custom-scheme redirect — which iOS blocks.)
        .plugin(tauri_plugin_auth_session::init());

    // Mobile-only plugins: biometric (Face ID / Touch ID) gate on signing actions, the iOS Share
    // Pane, and camera QR scanning for the OAuth consent scan path. Registering them behind
    // `#[cfg(mobile)]` keeps the macOS host build and its test suite free of dependencies they
    // cannot compile.
    #[cfg(mobile)]
    let builder = builder
        .plugin(tauri_plugin_biometric::init())
        .plugin(tauri_plugin_sharesheet::init())
        .plugin(tauri_plugin_barcode_scanner::init());

    builder
        .setup(|app| {
            // The platform adapters, owned by the `Core` every command reaches. Built here
            // because the event sink and the backup location need the app handle; commands
            // cannot run before `setup` returns.
            let keys: Arc<dyn obsign_core::keystore::KeyStore> = Arc::new(
                obsign_platform_ios::keychain::AppleKeychain::new(keychain::SERVICE),
            );
            // Every device key (each identity's, and the global one the create flow signs
            // with): the Secure Enclave on a real device, software elsewhere.
            #[cfg(all(target_os = "ios", not(target_env = "sim")))]
            let signer: Arc<dyn obsign_core::signer::Signer> = Arc::new(
                obsign_platform_ios::enclave_signer::EnclaveSigner::new(keys.clone()),
            );
            #[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
            let signer: Arc<dyn obsign_core::signer::Signer> =
                Arc::new(obsign_core::signer::SoftwareSigner::new(keys.clone()));
            let backup = Arc::new(obsign_platform_ios::icloud::ICloudBackupStore::new(
                app.path()
                    .app_data_dir()
                    .ok()
                    .map(|dir| dir.join("blob-backup")),
            ));
            app.manage(oauth::Core::new(obsign_core::platform::Platform {
                keys,
                signer,
                events: Arc::new(TauriEvents(app.handle().clone())),
                backup,
                scheduler: background_scheduler(app.handle()),
                clock: Arc::new(obsign_core::platform::SystemClock),
            }));
            let core = app.state::<oauth::Core>();
            core.set_app_identifier(app.config().identifier.clone());

            // Restore PDS URL from Keychain if previously configured.
            if let Some(url) = obsign_core::pds_config::configured_pds_url(&core) {
                core.set_custos_client(url);
            }

            // Best-effort, idempotent, order-sensitive: the Share 1 launch hops, then the
            // created-identity re-registration. Must follow the `Core` construction above.
            obsign_core::startup_reconcile::run(&core);

            // Delete the Keychain items the retired create-flow OAuth login left behind.
            keychain::retire_legacy_oauth_items(&core);

            // Start the PLC monitor's foreground timer (15-minute interval). It runs alongside
            // the background PLC job requested below, which covers the app being closed.
            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(run_monitoring_loop(monitor_handle));

            // Submit the backup request the settings ask for and the PLC sweep request.
            obsign_core::backup_policy::apply_schedule(&core);
            obsign_core::plc_monitor::schedule_background_check(&core);

            // iOS only: install the APNs device-token callbacks and ask for notification
            // permission. Must run in `setup` — the delegate methods have to exist before iOS
            // delivers the token, which it does shortly after launch. Off-device this is absent
            // entirely, and every caller treats a token-less device as an ordinary state.
            #[cfg(target_os = "ios")]
            apns::register_for_remote_notifications(app.handle());

            Ok(())
        })
        .invoke_handler(commands::handler())
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        .run(|app, event| {
            // The Camera-app half of the consent QR. tao runs the UIScene lifecycle on iOS,
            // so a URL opened from outside the app arrives as `scene:openURLContexts:` and
            // surfaces here as `RunEvent::Opened` — never through an application-delegate
            // `openURL` method (adding one is dead code under scenes). Routed through the
            // same pending-route slot + event a tapped notification uses, so cold-start
            // drain and warm-foreground listener both already handle it.
            if let tauri::RunEvent::Opened { urls } = event {
                use tauri::Emitter;
                for url in urls {
                    if let Some(route) = notification_routes::route_from_handoff_url(url.as_str()) {
                        notification_routes::store_pending_route(route.clone());
                        let _ = app.emit("notification_route", route);
                    }
                }
            }
        });
}
