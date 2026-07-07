//! admin-companion — Tauri backend entry point.
//!
//! The operator console's capabilities, layered on the device admin key: **multi-relay
//! pairing** (a versioned document of relays this device is paired to, with local id-based
//! selection), **claim a QR pairing code** (→ register this device's public key with a new
//! relay, append and activate), **signed admin requests** (every call carries the canonical
//! `X-Admin-*` envelope the relay verifies — the demo action is `generate_claim_code`),
//! **self-revoke** (a signed request sent to a specific relay's revoke endpoint), and the
//! **biometric-gate preference** that backs the Settings screen. The terminal-native operator
//! screens consume these commands over IPC.

mod device_key;
mod keychain;
mod pairings;
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
/// from the operator's QR). Registers the device's public key, appends the pairing to
/// the document, and makes it the active selection; returns the relay-assigned
/// `device_id`. `nickname` is the operator's local display name for this relay — it is
/// stored on-device only and never sent to the relay.
#[tauri::command]
async fn pair_device(
    relay_url: String,
    pairing_code: String,
    label: String,
    nickname: String,
) -> Result<String, relay_client::RelayClientError> {
    relay_client::pair(&relay_url, &pairing_code, &label, &nickname).await
}

/// Every stored pairing plus the active selection — the state behind the Home switcher
/// and the Settings server list. Local keychain read; no network.
#[tauri::command]
fn list_pairings() -> Result<pairings::PairingsState, relay_client::RelayClientError> {
    relay_client::list_pairings()
}

/// Select the pairing that unqualified actions (claim-code mint) target.
#[tauri::command]
fn set_active_pairing(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::set_active_pairing(&id)
}

/// Rename a pairing's operator-chosen nickname. Local-only; no relay is contacted.
#[tauri::command]
fn rename_pairing(id: String, nickname: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::rename_pairing(&id, &nickname)
}

/// Mint a single account claim code via a signed request to the paired relay. The
/// companion app's demo-lifesaver action.
#[tauri::command]
async fn generate_claim_code() -> Result<String, relay_client::RelayClientError> {
    relay_client::generate_claim_code().await
}

/// Revoke the given pairing's admin credential on its relay (signed self-revoke), then
/// remove the entry locally. Removal only after the relay confirms.
#[tauri::command]
async fn revoke_self(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::revoke_self(&id).await
}

/// Forget the given pairing locally without contacting its relay — the fallback when a
/// server-side self-revoke can't reach it.
#[tauri::command]
fn unpair(id: String) -> Result<(), relay_client::RelayClientError> {
    relay_client::unpair(&id)
}

/// Whether the biometric (user-presence) gate on signing actions is enabled. Defaults to
/// `true` on a fresh install — signing is gated until the operator opts out in Settings.
/// Errors serialize through `RelayClientError::Keychain` (the app's one Serialize error).
#[tauri::command]
fn biometric_enabled() -> Result<bool, relay_client::RelayClientError> {
    Ok(keychain::get_biometric_enabled()?)
}

/// Persist the biometric-gate preference (the Settings toggle).
#[tauri::command]
fn set_biometric_enabled(enabled: bool) -> Result<(), relay_client::RelayClientError> {
    keychain::set_biometric_enabled(enabled)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default().plugin(tauri_plugin_log::Builder::new().build());

    // The barcode-scanner (camera QR), biometric (Face ID / Touch ID user-presence gate),
    // and sharesheet (iOS Share Pane) plugins are all mobile-only. Registering them behind
    // `#[cfg(mobile)]` keeps the macOS host build — and the test suite that proves the
    // signing contract — free of dependencies it cannot compile.
    #[cfg(mobile)]
    let builder = builder
        .plugin(tauri_plugin_barcode_scanner::init())
        .plugin(tauri_plugin_biometric::init())
        .plugin(tauri_plugin_sharesheet::init());

    builder
        .invoke_handler(tauri::generate_handler![
            get_or_create_device_key,
            sign_with_device_key,
            pair_device,
            list_pairings,
            set_active_pairing,
            rename_pairing,
            generate_claim_code,
            revoke_self,
            unpair,
            biometric_enabled,
            set_biometric_enabled
        ])
        .run(tauri::generate_context!())
        .expect("error while running admin-companion");
}
