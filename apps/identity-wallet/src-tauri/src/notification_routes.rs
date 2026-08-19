// pattern: Functional Core

//! The pending notification route: where a tapped push wants the app to go. The portable,
//! host-tested half of notification-tap routing (`apns.rs` is the iOS half).
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
//! Auth mode — so a stored route is instance-authenticated by construction. The wallet still
//! treats it as a pointer, never a claim: everything the consent screen displays is
//! re-fetched from the server by `request_id` (the QR-path discipline), and the frontend
//! router navigates only for a DID this wallet actually manages (or the sole identity), and
//! only from an interruptible surface.
//!
//! A single newest-wins slot, not a queue: routes are stale the moment a newer tap happens,
//! and a consent prompt is ~5-minutes perishable anyway.

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

/// The custom schemes iOS launches the wallet on for a consent handoff, both registered in
/// `Info.ios.plist`. `obsign` is what the Custos consent page emits today — the product name,
/// because the iOS Camera chip displays the raw scheme string ("Open in obsign"). The old
/// reverse-FQDN spelling stays accepted for QR codes from not-yet-updated Custos instances.
const HANDOFF_SCHEMES: [&str; 2] = ["obsign", "org.obsign.identitywallet"];

/// Parse a wallet handoff URL into a route, or `None` for any URL this module does not own.
///
/// This is the Camera-app half of the consent QR: the same QR the in-app scanner reads is a
/// plain URL to iOS, and scanning it from outside Obsign launches the app through
/// `application:openURL:` with nothing but this string. Only the `/consent` path routes —
/// every other URL on the scheme (the ASWebAuthenticationSession OAuth callback, anything a
/// future feature claims) reads as `None` so the caller can decline it untouched.
///
/// The URL is attacker-suppliable by construction (anyone can print a QR), which is why the
/// result is a pointer and nothing more: the same `request_id`-only discipline as the in-app
/// scan path, with everything displayed re-fetched from the server and approval still behind
/// the number-match + biometric-signed envelope.
///
/// Both `scheme:/consent` (the server's spelling) and `scheme://consent` (a scanner that
/// normalizes an authority slot into the URL) are accepted; they are the same instruction.
pub fn route_from_handoff_url(raw: &str) -> Option<PendingNotificationRoute> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if !HANDOFF_SCHEMES
        .iter()
        .any(|scheme| url.scheme().eq_ignore_ascii_case(scheme))
    {
        return None;
    }
    let names_consent = |segment: Option<&str>| segment == Some("consent");
    let path = url.path().trim_matches('/');
    let is_consent = if path.is_empty() {
        names_consent(url.host_str())
    } else {
        names_consent(Some(path)) && url.host_str().is_none()
    };
    if !is_consent {
        return None;
    }

    let request_id = url
        .query_pairs()
        .find(|(name, _)| name == "request_id")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())?;

    // No `did`: the QR names a pending request, not an identity. The frontend resolves which
    // managed identity can answer it (sole identity, or by probing the request's preview).
    Some(PendingNotificationRoute {
        kind: "login-approval".to_string(),
        request_id: Some(request_id),
        did: None,
    })
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

    // ── the Camera-app handoff URL ──

    /// The exact string the Custos consent page renders into its QR
    /// (`oauth_templates::wallet_handoff_uri`), origin rider included — and the old
    /// reverse-FQDN spelling still emitted by not-yet-updated Custos instances.
    #[test]
    fn the_servers_handoff_url_routes_to_the_consent_request() {
        for scheme in ["obsign", "org.obsign.identitywallet"] {
            let route = route_from_handoff_url(&format!(
                "{scheme}:/consent?request_id=poauth_abc123&origin=https%3A%2F%2Fapp.example.com",
            ))
            .unwrap();
            assert_eq!(route.kind, "login-approval");
            assert_eq!(route.request_id.as_deref(), Some("poauth_abc123"));
            assert_eq!(
                route.did, None,
                "the QR names a request, not an identity — resolution is the frontend's job"
            );
        }
    }

    /// A scanner that rewrites `scheme:/x` into `scheme://x` has not changed the instruction.
    #[test]
    fn an_authority_spelled_consent_url_routes_identically() {
        let route = route_from_handoff_url("obsign://consent?request_id=poauth_abc").unwrap();
        assert_eq!(route.request_id.as_deref(), Some("poauth_abc"));
    }

    /// Everything on the scheme that is not the consent handoff must read as "not ours":
    /// returning `None` is what lets the openURL handler decline a URL without consuming it.
    #[test]
    fn other_urls_on_the_scheme_are_declined_untouched() {
        for raw in [
            // The ASWebAuthenticationSession OAuth callback — same scheme, different owner.
            "org.obsign.identitywallet:/oauth/callback?code=xyz",
            // A consent path with nothing to route on.
            "org.obsign.identitywallet:/consent",
            "org.obsign.identitywallet:/consent?request_id=",
            // A hostile spelling that puts `consent` where it doesn't belong.
            "org.obsign.identitywallet://evil.example/consent?request_id=poauth_x",
            // Someone else's scheme entirely.
            "https://pds.example.com/consent?request_id=poauth_x",
            "not a url at all",
        ] {
            assert_eq!(route_from_handoff_url(raw), None, "must decline: {raw}");
        }
    }

    /// The request id round-trips percent-decoding, since the server percent-encodes it.
    #[test]
    fn the_request_id_is_percent_decoded() {
        let route = route_from_handoff_url("obsign:/consent?request_id=poauth_a%2Db%5Fc").unwrap();
        assert_eq!(route.request_id.as_deref(), Some("poauth_a-b_c"));
    }
}
