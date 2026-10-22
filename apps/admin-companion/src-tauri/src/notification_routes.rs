// pattern: Functional Core

//! The pending notification route: where a tapped operator alert wants the console to go.
//! The portable, host-tested half of notification-tap routing (`apns.rs` is the iOS half);
//! the console copy of the wallet's `obsign_core::notification_routes`, by value — the two
//! apps share no notification crate, and the route shapes differ.
//!
//! A tap can arrive before the frontend exists (cold start — iOS launches the app *because
//! of* the tap) or while it is running (warm foreground). One mechanism serves both: the iOS
//! tap handler stores the route here (`store_pending_route`) and emits a `notification_route`
//! Tauri event; the frontend drains the slot via the `take_pending_notification_route`
//! command on mount (cold start) and on the event (warm), and `take` clears it so the two
//! paths can never double-navigate on one tap.
//!
//! The route's fields come from the delivered notification's `ezpdsRoute` block, which the
//! Notification Service Extension writes ONLY after the sealed payload verified under HPKE
//! Auth mode — so a stored route is instance-authenticated by construction. It is still a
//! pointer, never a claim: `server` only selects which *existing* pairing to open (by relay
//! URL — a server this device is not paired with routes nowhere), `screen` is matched
//! against the frontend's own allowlist, and everything the screen then shows is fetched
//! through that pairing's signed requests as usual.
//!
//! A single newest-wins slot, not a queue: an alert is a prompt to go look, and the
//! Accounts screen shows every current flag regardless of how many taps led there.

use std::sync::{Mutex, OnceLock};

use serde::Serialize;

/// A routing instruction extracted from a tapped, NSE-verified operator alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingNotificationRoute {
    /// The payload `type` the console dispatches on (`accounts_flagged`,
    /// `storage_cap_approaching`). Unknown kinds are stored anyway and ignored by the
    /// frontend — the extension versions independently.
    pub kind: String,
    /// The sealing instance's public URL — which pairing the alert belongs to.
    pub server: String,
    /// The console screen the alert points at (`accounts`).
    pub screen: Option<String>,
    /// The account the alert concerns, when it concerns exactly one.
    pub did: Option<String>,
}

fn slot() -> &'static Mutex<Option<PendingNotificationRoute>> {
    static SLOT: OnceLock<Mutex<Option<PendingNotificationRoute>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Build a route from the delivered notification's extracted fields. `None` when there is
/// nothing to route on: without `server` the console cannot know which pairing to open.
///
/// Only the iOS tap handler fills the slot (the two `cfg`s below), so a host build sees
/// these as unused; the host test suite is what exercises them.
#[cfg(any(target_os = "ios", test))]
pub fn route_from_fields(
    kind: Option<String>,
    server: Option<String>,
    screen: Option<String>,
    did: Option<String>,
) -> Option<PendingNotificationRoute> {
    Some(PendingNotificationRoute {
        kind: kind?,
        server: server.filter(|s| !s.trim().is_empty())?,
        screen,
        did,
    })
}

/// Park a route for the frontend. The newest tap wins; a route the frontend never drained is
/// replaced, not queued.
#[cfg(any(target_os = "ios", test))]
pub fn store_pending_route(route: PendingNotificationRoute) {
    *slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(route);
}

/// Take (and clear) the pending route. Clearing is what keeps the cold-start drain and the
/// warm-event handler from both navigating on one tap.
pub fn take_pending_notification_route() -> Option<PendingNotificationRoute> {
    slot().lock().unwrap_or_else(|e| e.into_inner()).take()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flagged(server: &str) -> PendingNotificationRoute {
        PendingNotificationRoute {
            kind: "accounts_flagged".into(),
            server: server.into(),
            screen: Some("accounts".into()),
            did: None,
        }
    }

    // The slot is process-global, so the two slot tests run under one lock to keep their
    // stores from interleaving (the test binary runs tests in parallel threads).
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn take_drains_the_slot_exactly_once() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        store_pending_route(flagged("https://one.example"));
        assert_eq!(
            take_pending_notification_route(),
            Some(flagged("https://one.example"))
        );
        assert_eq!(
            take_pending_notification_route(),
            None,
            "a second drain (the warm-event handler after a cold-start drain) must find nothing"
        );
    }

    #[test]
    fn the_newest_tap_wins() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        store_pending_route(flagged("https://old.example"));
        store_pending_route(flagged("https://new.example"));
        assert_eq!(
            take_pending_notification_route(),
            Some(flagged("https://new.example"))
        );
    }

    #[test]
    fn a_route_needs_a_server_not_just_a_kind() {
        assert_eq!(
            route_from_fields(Some("accounts_flagged".into()), None, None, None),
            None
        );
        assert_eq!(
            route_from_fields(
                Some("accounts_flagged".into()),
                Some("  ".into()),
                None,
                None
            ),
            None
        );
        assert_eq!(
            route_from_fields(None, Some("https://pds.example".into()), None, None),
            None
        );
        let route = route_from_fields(
            Some("storage_cap_approaching".into()),
            Some("https://pds.example".into()),
            Some("accounts".into()),
            Some("did:plc:abc".into()),
        )
        .unwrap();
        assert_eq!(route.kind, "storage_cap_approaching");
        assert_eq!(route.did.as_deref(), Some("did:plc:abc"));
    }

    #[test]
    fn route_serializes_camel_case_for_the_frontend() {
        let json = serde_json::to_value(flagged("https://pds.example")).unwrap();
        assert_eq!(json["kind"], "accounts_flagged");
        assert_eq!(json["server"], "https://pds.example");
        assert_eq!(json["screen"], "accounts");
        assert_eq!(json["did"], serde_json::Value::Null);
    }
}
