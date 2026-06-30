//! admin-companion — Tauri backend entry point.
//!
//! Phase 7 wires the operator console's two capabilities on top of the Phase 6 device
//! key: **pairing** (claim a QR pairing code → register this device's public key) and
//! **signed admin requests** (every call carries the canonical `X-Admin-*` envelope the
//! relay verifies). The demo action is `generate_claim_code`. The terminal-native
//! operator screens that assemble these land in Phase 8.

mod device_key;
mod keychain;
mod relay_client;
mod signing;

/// Get-or-create the device's admin P-256 key and return its public form.
/// Idempotent: returns the same key on every call for a given install.
#[tauri::command]
fn get_or_create_device_key() -> Result<device_key::DevicePublicKey, device_key::DeviceKeyError> {
    device_key::get_or_create()
}

/// Sign arbitrary bytes with the device's admin key, returning a raw 64-byte
/// (r‖s, low-S) P-256 signature. Used by the signing client; also exposed for
/// diagnostics and the Phase 6 round-trip check.
#[tauri::command]
fn sign_with_device_key(data: Vec<u8>) -> Result<Vec<u8>, device_key::DeviceKeyError> {
    device_key::sign(&data)
}

/// Pair this device with a relay by claiming a pairing code (typed manually or scanned
/// from the operator's QR). Registers the device's public key and persists the
/// relay-assigned `device_id` + relay URL; returns the `device_id`.
#[tauri::command]
async fn pair_device(
    relay_url: String,
    pairing_code: String,
    label: String,
) -> Result<String, relay_client::RelayClientError> {
    relay_client::pair(&relay_url, &pairing_code, &label).await
}

/// The device's current pairing (`{ deviceId, relayUrl }`) or `null` if unpaired —
/// lets the home screen choose between the Pair screen and the operator console.
#[tauri::command]
fn pairing_state() -> Result<Option<keychain::Pairing>, relay_client::RelayClientError> {
    relay_client::current_pairing()
}

/// Mint a single account claim code via a signed request to the paired relay. The
/// companion app's demo-lifesaver action.
#[tauri::command]
async fn generate_claim_code() -> Result<String, relay_client::RelayClientError> {
    relay_client::generate_claim_code().await
}

/// Forget the current pairing locally (unpair). Server-side self-revoke arrives with
/// the Settings screen in Phase 8.
#[tauri::command]
fn unpair() -> Result<(), relay_client::RelayClientError> {
    relay_client::unpair()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default().plugin(tauri_plugin_log::Builder::new().build());

    // The barcode-scanner plugin is mobile-only (iOS/Android camera). Registering it
    // behind `#[cfg(mobile)]` keeps the macOS host build — and the test suite that
    // proves the signing contract — free of a dependency it cannot compile.
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());

    builder
        .invoke_handler(tauri::generate_handler![
            get_or_create_device_key,
            sign_with_device_key,
            pair_device,
            pairing_state,
            generate_claim_code,
            unpair
        ])
        .run(tauri::generate_context!())
        .expect("error while running admin-companion");
}
