// pattern: Functional Core
//
// The pending notification route: where a tapped push wants the app to go.
//
// A tap can arrive before the frontend exists (cold start — iOS launches the app *because of*
// the tap) or while it is running (warm foreground). One mechanism serves both: the iOS tap
// handler (`apns.rs`) stores the route here and emits a `notification_route` Tauri event; the
// frontend drains this slot on mount (cold start) and on the event (warm), and `take` clears
// it so the two paths can never double-navigate.
//
// The route's fields come from the delivered notification's `ezpdsRoute` block, which the
// Notification Service Extension writes ONLY after the sealed payload verified under HPKE
// Auth mode — so a stored route is instance-authenticated by construction. The wallet still
// treats it as a pointer, not a claim: everything it displays is re-fetched from the server
// by `request_id` (the QR-path discipline), and the `did` must name an identity this wallet
// actually manages before anything navigates.
//
// A single slot, not a queue: routes are stale the moment a newer tap happens, and a consent
// prompt is ~5-minutes perishable anyway. The newest tap wins.

use std::sync::{Mutex, OnceLock};

use serde::Serialize;

/// A routing instruction extracted from a tapped, NSE-verified notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingNotificationRoute {
    /// The payload `type` the app dispatches on (e.g. `login-approval`). Unknown kinds are
    /// stored anyway and ignored by the frontend — the extension versions independently.
    pub kind: String,
    /// A pending OAuth consent `request_id` (`login-approval`).
    pub request_id: Option<String>,
    /// The account DID the notification concerns, so a multi-identity wallet opens the right one.
    pub did: Option<String>,
}

fn slot() -> &'static Mutex<Option<PendingNotificationRoute>> {
    static SLOT: OnceLock<Mutex<Option<PendingNotificationRoute>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Build a route from the delivered notification's extracted fields. `None` when there is
/// nothing to route on — a `type` alone opens nothing.
pub fn route_from_fields(
    kind: Option<String>,
    request_id: Option<String>,
    did: Option<String>,
) -> Option<PendingNotificationRoute> {
    let kind = kind?;
    if request_id.is_none() && did.is_none() {
        return None;
    }
    Some(PendingNotificationRoute {
        kind,
        request_id,
        did,
    })
}

/// Park a route for the frontend. The newest tap wins; a route the frontend never drained is
/// replaced, not queued (it pointed at a prompt that is stale now).
pub fn store_pending_route(route: PendingNotificationRoute) {
    *slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(route);
}

/// Take (and clear) the pending route. Clearing is what keeps the cold-start drain and the
/// warm-event handler from both navigating on one tap.
#[tauri::command]
pub fn take_pending_notification_route() -> Option<PendingNotificationRoute> {
    slot().lock().unwrap_or_else(|e| e.into_inner()).take()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_route(request_id: &str) -> PendingNotificationRoute {
        PendingNotificationRoute {
            kind: "login-approval".into(),
            request_id: Some(request_id.into()),
            did: Some("did:plc:abc".into()),
        }
    }

    #[test]
    fn take_drains_the_slot_exactly_once() {
        store_pending_route(login_route("poauth_one"));
        assert_eq!(
            take_pending_notification_route(),
            Some(login_route("poauth_one"))
        );
        assert_eq!(
            take_pending_notification_route(),
            None,
            "a second drain (the warm-event handler after a cold-start drain) must find nothing"
        );
    }

    #[test]
    fn the_newest_tap_wins() {
        store_pending_route(login_route("poauth_old"));
        store_pending_route(login_route("poauth_new"));
        assert_eq!(
            take_pending_notification_route(),
            Some(login_route("poauth_new"))
        );
    }

    #[test]
    fn a_route_needs_an_identifier_not_just_a_kind() {
        assert_eq!(
            route_from_fields(Some("login-approval".into()), None, None),
            None
        );
        assert_eq!(route_from_fields(None, Some("poauth_x".into()), None), None);
        let route = route_from_fields(
            Some("login-approval".into()),
            Some("poauth_x".into()),
            Some("did:plc:abc".into()),
        )
        .unwrap();
        assert_eq!(route.kind, "login-approval");
        assert_eq!(route.request_id.as_deref(), Some("poauth_x"));
    }

    #[test]
    fn route_serializes_camel_case_for_the_frontend() {
        let json = serde_json::to_value(login_route("poauth_x")).unwrap();
        assert_eq!(json["kind"], "login-approval");
        assert_eq!(json["requestId"], "poauth_x");
        assert_eq!(json["did"], "did:plc:abc");
    }
}
