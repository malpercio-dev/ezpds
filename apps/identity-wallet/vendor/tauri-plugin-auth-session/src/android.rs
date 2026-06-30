//! Android implementation — bridges to Kotlin via Tauri's mobile plugin IPC.

use serde::{Deserialize, Serialize};
use tauri::{plugin::PluginHandle, Runtime};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartArgs {
    auth_url: String,
    callback_url_scheme: String,
}

#[derive(Deserialize)]
struct StartResponse {
    url: String,
}

pub async fn start_session<R: Runtime>(
    handle: &PluginHandle<R>,
    auth_url: String,
    callback_url_scheme: String,
) -> Result<String, String> {
    let args = StartArgs {
        auth_url,
        callback_url_scheme,
    };

    let response: StartResponse = handle
        .run_mobile_plugin("start", args)
        .map_err(|e| e.to_string())?;

    Ok(response.url)
}
