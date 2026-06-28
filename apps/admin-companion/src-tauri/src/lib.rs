//! admin-companion — Tauri backend entry point.
//!
//! Phase 6 scaffold: the app's only wired capability so far is its per-device
//! admin key (Secure Enclave on a real device, software key on the simulator/
//! macOS). Pairing, request signing, and the operator screens land in Phases
//! 7–8. The two commands below let the frontend prove the key round-trips
//! end-to-end through the IPC bridge.

mod device_key;
mod keychain;

/// Get-or-create the device's admin P-256 key and return its public form.
/// Idempotent: returns the same key on every call for a given install.
#[tauri::command]
fn get_or_create_device_key() -> Result<device_key::DevicePublicKey, device_key::DeviceKeyError> {
    device_key::get_or_create()
}

/// Sign arbitrary bytes with the device's admin key, returning a raw 64-byte
/// (r‖s, low-S) P-256 signature. The canonical request envelope that feeds this
/// in production is built in Phase 7.
#[tauri::command]
fn sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, device_key::DeviceKeyError> {
    device_key::sign(&data)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            get_or_create_device_key,
            sign_with_device_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running admin-companion");
}
