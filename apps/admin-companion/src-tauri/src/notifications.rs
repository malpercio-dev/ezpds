// pattern: Imperative Shell
//
//! The console half of the E2E-encrypted notification relay: key material, the APNs token,
//! and the pin store the Notification Service Extension reads.
//!
//! ONE notification P-256 keypair per device, shared across every pairing — the admin key
//! model, mirroring `device_key.rs` — registered per relay through the signed
//! `POST /v1/admin/notifications/register` (`relay_client::register_notifications`). The
//! pinned sender keys live in two places on purpose:
//!
//! * **Per pairing, in the pairing document** (`Pairing::notification_sender_keys`) — the
//!   operator-facing truth, refreshed on contact via `relay_client::refresh_sender_keys`.
//! * **Mirrored into the NSE pin store** (`notification-sender-keys`, the same
//!   `{version, hosts}` JSON shape the wallet writes) — the extension is a separate bundle
//!   that reads one keychain item while the device is locked; it cannot parse the pairing
//!   document, and the wallet's Swift decoder already exists. [`write_nse_pins`] rebuilds
//!   the whole mirror from the document after every pin refresh, so the two can never
//!   drift for longer than one refresh.
//!
//! Wire/storage discipline is the wallet's `notifications.rs`, copied by value (the two
//! apps share no crate): every keychain write of notification material is
//! `AccessibleAfterFirstUnlock` and read back before success is reported, because a key the
//! app believes it stored but the extension cannot find renders every future alert as the
//! unverified notice with nothing anywhere saying why.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::keychain;
use crate::pairings::{PairingDoc, SenderKey};
use crate::relay_client::RelayClientError;

/// Keychain account for the device's notification private key (raw 32-byte P-256 scalar).
/// The name is shared with the NSE's Swift constant by spelling, not by import.
pub const NOTIFICATION_KEY_ACCOUNT: &str = "notification-key-priv";

/// Keychain account for the NSE pin mirror (JSON [`PinnedSenderKeys`]).
pub const PINNED_SENDER_KEYS_ACCOUNT: &str = "notification-sender-keys";

/// Keychain account for the APNs device token (lowercase hex).
pub const APNS_TOKEN_ACCOUNT: &str = "notification-apns-token";

/// Version pinned into the NSE pin mirror. Must match the Swift decoder's
/// `PinnedSenderKeys.supportedVersion` (and the wallet's `PIN_DOCUMENT_VERSION`).
pub const PIN_DOCUMENT_VERSION: u8 = 1;

/// The NSE pin mirror: hosting server → that server's published sender-key set. The same
/// JSON shape the wallet stores, so the shared extension decodes both apps' pins with one
/// decoder.
#[derive(Debug, Default, Serialize, Deserialize)]
struct PinnedSenderKeys {
    version: u8,
    hosts: BTreeMap<String, Vec<SenderKey>>,
}

/// Normalize a relay base URL into a pin-store host key (the wallet's `host_key` rule).
fn host_key(relay_url: &str) -> String {
    relay_url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Rebuild the NSE pin mirror from the pairing document and store it where the extension
/// reads. Two pairings naming the same relay URL are the same instance, so the later entry's
/// set wins.
pub fn write_nse_pins(doc: &PairingDoc) -> Result<(), RelayClientError> {
    let mut hosts: BTreeMap<String, Vec<SenderKey>> = BTreeMap::new();
    for pairing in doc.pairings() {
        if !pairing.notification_sender_keys.is_empty() {
            hosts.insert(
                host_key(&pairing.relay_url),
                pairing.notification_sender_keys.clone(),
            );
        }
    }
    let pins = PinnedSenderKeys {
        version: PIN_DOCUMENT_VERSION,
        hosts,
    };
    let bytes = serde_json::to_vec(&pins).map_err(|e| RelayClientError::Keychain {
        message: format!("could not serialize the NSE pin mirror: {e}"),
    })?;
    keychain::store_item_after_first_unlock(PINNED_SENDER_KEYS_ACCOUNT, &bytes)
        .map_err(RelayClientError::from)
}

/// Load — or, on first use, generate — the device's notification keypair, returning its
/// `did:key`. Stored `AccessibleAfterFirstUnlock` and read back before being reported; an
/// unreadable or invalid stored scalar is replaced rather than wedging registration forever
/// (the only loss is payloads sealed to a key nobody can reconstruct anyway).
pub fn notification_public_key() -> Result<String, RelayClientError> {
    if let Some(scalar) = stored_notification_scalar()? {
        match crypto::p256_keypair_from_secret(&scalar) {
            Ok(keypair) => return Ok(keypair.key_id.0),
            Err(e) => tracing::warn!(
                error = %e,
                "stored notification key is unusable; minting a replacement"
            ),
        }
    }

    let keypair = crypto::generate_p256_keypair().map_err(|e| RelayClientError::Keychain {
        message: format!("could not generate a notification key: {e}"),
    })?;
    keychain::store_item_after_first_unlock(
        NOTIFICATION_KEY_ACCOUNT,
        keypair.private_key_bytes.as_ref(),
    )?;

    match stored_notification_scalar()? {
        Some(read_back) if read_back.as_ref() == keypair.private_key_bytes.as_ref() => {
            Ok(keypair.key_id.0)
        }
        _ => Err(RelayClientError::Keychain {
            message: "the notification key did not read back after storing".to_string(),
        }),
    }
}

/// The stored notification private scalar, or `None` when absent or the wrong length
/// (unreconstructable either way — the caller mints a fresh key).
fn stored_notification_scalar() -> Result<Option<Zeroizing<[u8; 32]>>, RelayClientError> {
    match keychain::get_item(NOTIFICATION_KEY_ACCOUNT) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&bytes);
            Ok(Some(Zeroizing::new(scalar)))
        }
        Ok(_) => {
            tracing::warn!("notification key has an unexpected length; treating it as absent");
            Ok(None)
        }
        Err(e) if keychain::is_not_found(&e) => Ok(None),
        Err(e) => Err(RelayClientError::from(e)),
    }
}

// ── APNs token ───────────────────────────────────────────────────────────────

/// Record the APNs device token iOS handed us, reporting whether it actually changed
/// (iOS re-delivers on every launch; an unchanged token must not re-register every pairing).
#[cfg(any(target_os = "ios", test))]
pub(crate) fn record_apns_token(token: &str) -> Result<bool, RelayClientError> {
    let token = token.to_ascii_lowercase();
    if stored_apns_token() == Some(token.clone()) {
        return Ok(false);
    }
    keychain::store_item(APNS_TOKEN_ACCOUNT, token.as_bytes())?;
    Ok(true)
}

/// The stored APNs device token, if this device has one. `None` is an ordinary state
/// (pre-permission, simulator) that registration reports as `AWAITING_APNS_TOKEN`.
pub(crate) fn stored_apns_token() -> Option<String> {
    match keychain::get_item(APNS_TOKEN_ACCOUNT) {
        Ok(bytes) => String::from_utf8(bytes)
            .ok()
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty()),
        Err(e) if keychain::is_not_found(&e) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not read the stored APNs token");
            None
        }
    }
}

/// Render a raw APNs device token into the lowercase hex the relay validates.
#[cfg(any(target_os = "ios", test))]
pub(crate) fn hex_encode_apns_token(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Register every pairing with its relay after an APNs token change, stepping over
/// per-pairing failures — one unreachable relay must not cost the others their registration.
#[cfg(target_os = "ios")]
pub(crate) async fn re_register_every_pairing(apns_topic: &str) {
    let pairings = match keychain::load_pairings() {
        Ok(doc) => doc.pairings().to_vec(),
        Err(e) => {
            tracing::error!(error = %e, "could not load pairings to re-register notifications");
            return;
        }
    };
    for pairing in pairings {
        if let Err(e) = crate::relay_client::register_notifications(&pairing.id, apns_topic).await {
            tracing::warn!(
                pairing = %pairing.id,
                error = %e,
                "notification re-registration failed for one pairing"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairings::Pairing;

    #[test]
    fn hex_encoding_is_lowercase_and_zero_padded() {
        assert_eq!(hex_encode_apns_token(&[0x00, 0x0f, 0xab]), "000fab");
    }

    #[test]
    fn apns_token_change_detection_round_trips() {
        keychain::clear_for_test();
        assert_eq!(stored_apns_token(), None);
        assert!(
            record_apns_token("ABCDEF01").unwrap(),
            "first token is a change"
        );
        assert_eq!(stored_apns_token().as_deref(), Some("abcdef01"));
        assert!(
            !record_apns_token("abcdef01").unwrap(),
            "the same token re-delivered on launch is not a change"
        );
        assert!(record_apns_token("ffff").unwrap());
    }

    #[test]
    fn the_notification_key_is_minted_once_and_stable() {
        keychain::clear_for_test();
        let first = notification_public_key().expect("mint");
        assert!(first.starts_with("did:key:"));
        let second = notification_public_key().expect("load");
        assert_eq!(first, second, "the keypair is device-global and stable");
    }

    #[test]
    fn nse_pins_mirror_the_pairing_document_per_host() {
        keychain::clear_for_test();
        let mut doc = PairingDoc::empty();
        doc.append(Pairing::new(
            "id-a",
            "Staging",
            "https://Staging.example/",
            "d-a",
            "L",
        ));
        doc.append(Pairing::new(
            "id-b",
            "Prod",
            "https://prod.example",
            "d-b",
            "L",
        ));
        doc.set_notification_sender_keys(
            "id-a",
            vec![SenderKey {
                kid: 1,
                public_key: "did:key:zStaging".to_string(),
            }],
        )
        .unwrap();
        // id-b has nothing pinned yet: it must not appear in the mirror at all.

        write_nse_pins(&doc).expect("write");
        let stored = keychain::get_item(PINNED_SENDER_KEYS_ACCOUNT).expect("stored");
        let parsed: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(parsed["version"], 1);
        // The host key is normalized (trimmed slash, lowercased) so the Swift lookup by
        // flattening across hosts stays consistent with the wallet's convention.
        assert_eq!(
            parsed["hosts"]["https://staging.example"][0],
            serde_json::json!({"kid": 1, "publicKey": "did:key:zStaging"})
        );
        assert!(parsed["hosts"].get("https://prod.example").is_none());
    }
}
