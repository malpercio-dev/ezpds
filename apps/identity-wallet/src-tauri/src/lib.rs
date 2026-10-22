//! Obsign wallet shell: the Tauri wiring around `obsign_core`. Every ceremony, client, and
//! `Core` itself live in that crate, re-exported here under each module's old name so
//! `crate::claim::…` still resolves; the IPC table is `commands.rs`. What lives *here*:
//!
//! - `run()` — the iOS/Android entry point (`#[cfg_attr(mobile, tauri::mobile_entry_point)]`;
//!   `main.rs` calls it on desktop). Its `setup` installs the platform adapters, restores the
//!   configured PDS URL, runs `obsign_core::startup_reconcile`, restores the legacy OAuth
//!   session (`expires_at = 0` forces an immediate refresh; `auth_ready` emitted after a 300 ms
//!   delay so SvelteKit can register its listener), spawns the PLC monitoring loop, and on iOS
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
#[allow(
    clippy::expect_used,
    reason = "Tauri's run only fails when the app cannot start, which is fatal"
)]
pub fn run() {
    // First, before anything touches storage. A second `run()` in one process would be refused
    // and keep the store already installed, which is the same Keychain.
    let _ = obsign_core::keystore::install(Box::new(
        obsign_platform_ios::keychain::AppleKeychain::new(keychain::SERVICE),
    ));
    // Each identity's device key: the Secure Enclave on a real device, software elsewhere.
    #[cfg(all(target_os = "ios", not(target_env = "sim")))]
    let _ =
        obsign_core::signer::install(Box::new(obsign_platform_ios::enclave_signer::EnclaveSigner));
    #[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
    let _ = obsign_core::signer::install(Box::new(obsign_core::signer::SoftwareSigner));

    let builder = tauri::Builder::default()
        .manage(oauth::Core::new())
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
            // The platform seams that need the app handle: events to the UI, the backup
            // location, and the bundle identifier push registration uses as its topic.
            let _ = obsign_core::events::install(Box::new(TauriEvents(app.handle().clone())));
            let _ = obsign_core::backup_store::install(Box::new(
                obsign_platform_ios::icloud::ICloudBackupStore::new(
                    app.path()
                        .app_data_dir()
                        .ok()
                        .map(|dir| dir.join("blob-backup")),
                ),
            ));
            app.state::<oauth::Core>()
                .set_app_identifier(app.config().identifier.clone());

            // Restore PDS URL from Keychain if previously configured.
            if let Some(url) = obsign_core::pds_config::configured_pds_url() {
                app.state::<oauth::Core>().set_custos_client(url);
            }

            // Best-effort, idempotent, order-sensitive: the Share 1 launch hops, then the
            // created-identity re-registration. Must follow the adapter installs above.
            obsign_core::startup_reconcile::run();

            // On relaunch: restore persisted session from Keychain and notify frontend.
            // The 300 ms delay lets the SvelteKit app boot and register its event listener
            // before the event fires — emitting synchronously here would be dropped.
            if let Some((access, refresh)) = keychain::load_oauth_tokens() {
                {
                    let state = app.state::<oauth::Core>();
                    *state
                        .oauth_session
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(oauth::OAuthSession {
                            access_token: access,
                            refresh_token: refresh,
                            // expires_at = 0 ensures OAuthClient refreshes immediately on first use.
                            expires_at: 0,
                            dpop_nonce: None,
                        });
                }
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    handle.emit("auth_ready", ()).ok();
                });
            }

            // Start the PLC monitor's foreground timer (15-minute interval). It runs alongside
            // the background PLC job requested below, which covers the app being closed.
            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(run_monitoring_loop(monitor_handle));

            // iOS only: register the background jobs with BGTaskScheduler (before app launch
            // completes, which `setup` does) and install the scheduler. Off-device nothing is
            // installed and background requests are dropped (scheduling is a device concern;
            // the harness is untouched). Then submit the backup request the settings ask for and
            // the PLC sweep request.
            #[cfg(target_os = "ios")]
            {
                use obsign_core::scheduler::BackgroundJob;
                use obsign_platform_ios::scheduler::{IosScheduler, TaskKind};
                let app_handle = app.handle().clone();
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
                    std::sync::Arc::new(move |job, on_done| {
                        let app = app_handle.clone();
                        let worker = tauri::async_runtime::spawn(async move {
                            obsign_core::scheduler::run(job, &app.state::<oauth::Core>()).await;
                            on_done();
                        });
                        Box::new(move || worker.abort())
                    }),
                );
                scheduler.register();
                let _ = obsign_core::scheduler::install(Box::new(scheduler));
            }
            obsign_core::backup_policy::apply_schedule();
            obsign_core::plc_monitor::schedule_background_check();

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
