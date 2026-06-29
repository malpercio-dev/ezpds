//! Tauri v2 plugin for in-app OAuth authentication on Apple and Android platforms.
//!
//! - **macOS / iOS:** ASWebAuthenticationSession (in-app auth sheet)
//! - **Android:** Chrome Custom Tabs (in-app browser tab)
//! - **Windows / Linux:** Returns an error (use a desktop OAuth plugin instead)
//!
//! # Usage
//!
//! ```rust,no_run
//! tauri::Builder::default()
//!     .plugin(tauri_plugin_auth_session::init())
//!     .run(tauri::generate_context!())
//!     .expect("error while running tauri application");
//! ```

use tauri::{
    plugin::{Builder, TauriPlugin},
    Runtime,
};

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.tauri.auth_session";

#[cfg(target_os = "android")]
use tauri::{AppHandle, Manager};

/// Holds the mobile plugin handle for Android IPC.
#[cfg(target_os = "android")]
struct MobilePluginHandle<R: Runtime>(tauri::plugin::PluginHandle<R>);

/// Initialize the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("auth-session")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            {
                let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "AuthSessionPlugin")?;
                app.manage(MobilePluginHandle(handle));
            }
            #[cfg(not(target_os = "android"))]
            {
                let _ = (app, api);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![start])
        .build()
}

// ---------------------------------------------------------------------------
// Apple implementation (macOS + iOS)
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tauri::command]
async fn start(
    auth_url: String,
    callback_url_scheme: String,
    ephemeral: Option<bool>,
) -> Result<String, String> {
    apple::start_session(auth_url, callback_url_scheme, ephemeral.unwrap_or(false)).await
}

// ---------------------------------------------------------------------------
// Android implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
#[tauri::command]
async fn start<R: Runtime>(
    app: AppHandle<R>,
    auth_url: String,
    callback_url_scheme: String,
    _ephemeral: Option<bool>,
) -> Result<String, String> {
    let handle = app.state::<MobilePluginHandle<R>>();
    android::start_session(&handle.0, auth_url, callback_url_scheme).await
}

// ---------------------------------------------------------------------------
// Stub (Windows / Linux)
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
#[tauri::command]
async fn start(
    _auth_url: String,
    _callback_url_scheme: String,
    _ephemeral: Option<bool>,
) -> Result<String, String> {
    Err("In-app auth sessions are only available on Apple and Android platforms".to_string())
}
