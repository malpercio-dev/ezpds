// pattern: Imperative Shell (iOS-only Objective-C runtime bridge)

//! How the APNs device token reaches `notifications.rs`. iOS delivers it exactly once per
//! launch, to two methods on the **application delegate** — there is no polling API, no
//! `UIApplication.deviceToken` property, and no Tauri plugin for it. So this module installs
//! those two methods on Tauri's live delegate class, wired once from `lib.rs`'s `setup`,
//! before asking iOS to register. On a **changed** token the callback re-registers every
//! managed identity; an unchanged one (iOS re-delivers on every launch) does nothing — a
//! round trip per identity per launch would only rewrite rows that already say this.
//!
//! The same add-only mechanism carries the third callback: a notification **tap**
//! (`userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:`) is only
//! ever delivered to `UNUserNotificationCenter`'s delegate, which Tauri never sets — so the
//! method is added to the application delegate's class and the center's delegate pointed at
//! it. The tap handler reads the `ezpdsRoute` block the Notification Service Extension writes
//! only on the *verified* (HPKE-authenticated) path, parks it in `notification_routes` (the
//! portable, host-tested half), and emits the `notification_route` event — the deep-link path
//! for push-to-approve.
//!
//! A fourth add-only method, `application:openURL:options:`, is the **Camera-app half of the
//! consent QR**: the QR the consent page renders is a plain `org.obsign.identitywallet:` URL,
//! and scanning it outside Obsign launches the app through this callback (the scheme is
//! registered in Info.ios.plist; nothing consumed the URL after the deep-link plugin was
//! retired with the Safari OAuth flow). The `/consent` handoff parses via the host-tested
//! `notification_routes::route_from_handoff_url` into the same pending-route slot and event
//! the tap path uses; every other URL on the scheme is declined untouched.
//!
//! Everything here is compiled only for iOS (`lib.rs` gates the whole module), which also
//! means it is compiled only by the `aarch64-apple-ios` cross-compile in the PR lane and
//! exercised only on a device. Both consequences shape the code: the logic that *can* be
//! tested lives in `notifications.rs` (hex encoding, change detection, the registration
//! sequence), and what stays here is the smallest possible amount of runtime plumbing.
//!
//! # Why add methods rather than swizzle
//!
//! `class_addMethod` fails if the class already implements the selector, and that failure
//! mode is the one we want: Tauri's delegate does not implement either method today, and if a
//! future version starts to, silently replacing its implementation would be a far worse
//! outcome than declining and logging. Nothing here ever calls `method_setImplementation` or
//! `method_exchangeImplementations`, so no existing behaviour can be displaced.
//!
//! # Why a process-global handle
//!
//! An IMP is a bare C function pointer with no capture. The callbacks therefore read the
//! `AppHandle` from a `OnceLock` written during `setup` — the unit-of-global shape
//! `IdentityStore` and `pds_capabilities` already use — rather than threading state they
//! structurally cannot carry.

use std::sync::OnceLock;

use block2::{Block, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, ProtocolObject, Sel};
use objc2::{sel, MainThreadMarker};
use objc2_foundation::{NSData, NSDictionary, NSError, NSString, NSURL};
use objc2_ui_kit::UIApplication;
use objc2_user_notifications::{
    UNAuthorizationOptions, UNNotificationResponse, UNUserNotificationCenter,
    UNUserNotificationCenterDelegate,
};
use tauri::{AppHandle, Emitter, Manager};

/// The app handle the delegate callbacks resolve state through. Written once during `setup`.
static APP: OnceLock<AppHandle> = OnceLock::new();

/// Ask the user for notification permission and, if granted, ask iOS for a device token.
///
/// Called from `setup`. Fire-and-forget by nature: the system prompt is answered whenever the
/// user answers it, the token arrives asynchronously afterwards, and the app is fully usable
/// throughout. Everything downstream treats "no token" as an ordinary state
/// (`AWAITING_APNS_TOKEN`), so a denied prompt costs banners and nothing else.
pub fn register_for_remote_notifications(app: &AppHandle) {
    if APP.set(app.clone()).is_err() {
        // `setup` runs once; a second call would mean the startup path grew a duplicate.
        tracing::warn!("APNs registration was requested twice; ignoring the second call");
        return;
    }

    let Some(mtm) = MainThreadMarker::new() else {
        tracing::error!("APNs registration must run on the main thread; skipping");
        return;
    };

    if !install_delegate_methods(mtm) {
        // Without the callbacks the token would arrive nowhere, so asking for one would only
        // spend a permission prompt the user gets nothing for.
        return;
    }

    // Badge and sound alongside alerts: an encrypted payload still renders as a banner, and the
    // extension replaces its text in place — the presentation options are the same either way.
    let options = UNAuthorizationOptions::Alert
        | UNAuthorizationOptions::Sound
        | UNAuthorizationOptions::Badge;
    let handler = RcBlock::new(move |granted: Bool, error: *mut NSError| {
        if !error.is_null() {
            let description = unsafe { (*error).localizedDescription() }.to_string();
            tracing::warn!(error = %description, "notification authorization failed");
        }
        if !granted.as_bool() {
            tracing::info!("notification authorization was declined; not registering with APNs");
            return;
        }
        // `registerForRemoteNotifications` is main-thread-only and this block runs on an
        // arbitrary queue, so hop back before touching UIApplication.
        tauri::async_runtime::spawn(async {
            if let Some(app) = APP.get() {
                let _ = app.run_on_main_thread(|| {
                    if let Some(mtm) = MainThreadMarker::new() {
                        UIApplication::sharedApplication(mtm).registerForRemoteNotifications();
                    }
                });
            }
        });
    });
    UNUserNotificationCenter::currentNotificationCenter()
        .requestAuthorizationWithOptions_completionHandler(options, &handler);
}

/// Install the two device-token callbacks on the live delegate's class.
///
/// Returns whether the token can now reach us — `false` when there is no delegate yet, or when
/// something already implements the selectors (see the module note on why that is a decline
/// rather than a replacement).
fn install_delegate_methods(mtm: MainThreadMarker) -> bool {
    let application = UIApplication::sharedApplication(mtm);
    let Some(delegate) = (unsafe { application.delegate() }) else {
        tracing::error!("no application delegate yet; cannot receive an APNs device token");
        return false;
    };

    // The delegate is an object like any other, and its *class* is what the runtime dispatches
    // on — so that is where the methods go, not on the instance.
    let delegate_ptr: *const AnyObject = Retained::as_ptr(&delegate).cast();
    let class: *mut AnyClass = (unsafe { &*delegate_ptr }.class() as *const AnyClass).cast_mut();

    // "v@:@@" — returns void, takes (self, _cmd, UIApplication, NSData | NSError).
    const SIGNATURE: &[u8] = b"v@:@@\0";

    let registered = unsafe {
        objc2::ffi::class_addMethod(
            class,
            sel!(application:didRegisterForRemoteNotificationsWithDeviceToken:),
            std::mem::transmute::<DidRegisterFn, Imp>(did_register_with_token),
            SIGNATURE.as_ptr().cast(),
        )
    };
    if !registered.as_bool() {
        tracing::error!(
            "the application delegate already handles didRegisterForRemoteNotifications; \
             leaving it alone and skipping push registration"
        );
        return false;
    }

    // Best-effort: without it a registration failure is silent, but the token path still works.
    let failure_registered = unsafe {
        objc2::ffi::class_addMethod(
            class,
            sel!(application:didFailToRegisterForRemoteNotificationsWithError:),
            std::mem::transmute::<DidFailFn, Imp>(did_fail_to_register),
            SIGNATURE.as_ptr().cast(),
        )
    };
    if !failure_registered.as_bool() {
        tracing::warn!("could not install the APNs registration-failure callback");
    }

    // The URL-open callback: how a consent QR scanned OUTSIDE Obsign (the iOS Camera app)
    // deep-links into the same consent approval screen. The scheme is registered in
    // Info.ios.plist, so iOS launches/foregrounds the app on `org.obsign.identitywallet:…` —
    // but without this method the URL itself arrived nowhere and the scan landed on the home
    // screen. (The old deep-link plugin was removed with the OAuth Safari flow; the
    // ASWebAuthenticationSession callback never goes through openURL, so this add-only method
    // has the selector to itself.) Best-effort like the tap callback below: without it a scan
    // still opens the app, it just cannot say where to.
    //
    // "B@:@@@" — returns BOOL, takes (self, _cmd, UIApplication, NSURL, NSDictionary).
    const OPEN_URL_SIGNATURE: &[u8] = b"B@:@@@\0";
    let open_url_registered = unsafe {
        objc2::ffi::class_addMethod(
            class,
            sel!(application:openURL:options:),
            std::mem::transmute::<OpenUrlFn, Imp>(application_open_url),
            OPEN_URL_SIGNATURE.as_ptr().cast(),
        )
    };
    if !open_url_registered.as_bool() {
        tracing::error!(
            "the application delegate already handles application:openURL:options:; \
             leaving it alone — Camera-app consent QR scans will not deep-link"
        );
    }

    // The notification-tap callback: how a `login-approval` push deep-links into the consent
    // approval screen. `didReceiveNotificationResponse` is only ever delivered to
    // `UNUserNotificationCenter`'s delegate, which no one sets today — so the method is added
    // to the same delegate class (add-only, exactly like the token callbacks) and the center's
    // delegate is pointed at the existing application delegate instance. Best-effort: without
    // it a tap still foregrounds the app, it just lands on the home screen.
    // "v@:@@@?" — returns void, takes (self, _cmd, center, response, completion block).
    const RESPONSE_SIGNATURE: &[u8] = b"v@:@@@?\0";
    let tap_registered = unsafe {
        objc2::ffi::class_addMethod(
            class,
            sel!(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:),
            std::mem::transmute::<DidReceiveResponseFn, Imp>(did_receive_notification_response),
            RESPONSE_SIGNATURE.as_ptr().cast(),
        )
    };
    if tap_registered.as_bool() {
        // Safe cast in the Objective-C model: `ProtocolObject` is a repr(transparent) view of
        // the object, and conformance is duck-typed at dispatch time — the class now responds
        // to the one selector we installed, and the center probes with respondsToSelector for
        // the rest. The delegate property is weak; the application delegate outlives the app.
        let proto: &ProtocolObject<dyn UNUserNotificationCenterDelegate> =
            unsafe { &*delegate_ptr.cast() };
        UNUserNotificationCenter::currentNotificationCenter().setDelegate(Some(proto));
    } else {
        tracing::error!(
            "the application delegate already handles didReceiveNotificationResponse; \
             leaving it alone — notification taps will not deep-link"
        );
    }

    true
}

type DidRegisterFn = unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, *mut NSData);
type DidFailFn = unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, *mut NSError);
type OpenUrlFn = unsafe extern "C-unwind" fn(
    *mut AnyObject,
    Sel,
    *mut AnyObject,
    *mut NSURL,
    *mut AnyObject,
) -> Bool;
type DidReceiveResponseFn = unsafe extern "C-unwind" fn(
    *mut AnyObject,
    Sel,
    *mut AnyObject,
    *mut UNNotificationResponse,
    *mut Block<dyn Fn()>,
);

/// `-application:didRegisterForRemoteNotificationsWithDeviceToken:`
///
/// iOS calls this on the main thread on every launch, whether or not the token changed, so the
/// work is gated on an actual change: re-registering every identity on every launch would spend
/// a round trip per identity to write rows that already say exactly this.
unsafe extern "C-unwind" fn did_register_with_token(
    _this: *mut AnyObject,
    _cmd: Sel,
    _application: *mut AnyObject,
    device_token: *mut NSData,
) {
    if device_token.is_null() {
        tracing::warn!("APNs delivered a null device token");
        return;
    }
    let token = crate::notifications::hex_encode_apns_token(&unsafe { &*device_token }.to_vec());

    match crate::notifications::record_apns_token(&token) {
        Ok(false) => tracing::debug!("APNs device token is unchanged"),
        Ok(true) => {
            tracing::info!("APNs device token changed; re-registering every identity");
            let Some(app) = APP.get().cloned() else {
                return;
            };
            tauri::async_runtime::spawn(async move {
                let topic = app.config().identifier.clone();
                let state = app.state::<crate::oauth::AppState>();
                crate::notifications::re_register_every_identity(&topic, state.pds_client()).await;
            });
        }
        Err(e) => tracing::error!(error = ?e, "could not store the APNs device token"),
    }
}

/// `-application:openURL:options:`
///
/// iOS hands the app a URL on its registered scheme — for Obsign, that is a consent QR
/// scanned from outside the app (the Camera app renders the QR's payload as a plain link).
/// The `/consent` handoff parses into the same pending-route slot a tapped notification
/// uses, so both cold start (the URL arrives before the frontend exists; the mount drain
/// finds it) and warm foreground (the event fires; the listener drains it) are already
/// covered by machinery the tap path proved out. Any URL that is not the consent handoff is
/// declined with NO so a future owner of the scheme sees its URLs untouched.
unsafe extern "C-unwind" fn application_open_url(
    _this: *mut AnyObject,
    _cmd: Sel,
    _application: *mut AnyObject,
    url: *mut NSURL,
    _options: *mut AnyObject,
) -> Bool {
    if url.is_null() {
        return Bool::NO;
    }
    let Some(absolute) = (unsafe { &*url }).absoluteString() else {
        return Bool::NO;
    };
    let Some(route) = crate::notification_routes::route_from_handoff_url(&absolute.to_string())
    else {
        return Bool::NO;
    };
    tracing::info!(kind = %route.kind, "a handoff URL carried a route");
    crate::notification_routes::store_pending_route(route.clone());
    if let Some(app) = APP.get() {
        let _ = app.emit("notification_route", route);
    }
    Bool::YES
}

/// `-userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:`
///
/// The user tapped a delivered notification. If the Notification Service Extension left an
/// `ezpdsRoute` block — which it does only for a payload that verified under HPKE Auth — the
/// route is parked for the frontend and announced as a `notification_route` event: the park
/// covers a cold start (the frontend drains it on mount), the event covers a warm foreground.
/// Everything the wallet later *displays* is re-fetched from the server by `request_id`; this
/// only decides where to navigate.
unsafe extern "C-unwind" fn did_receive_notification_response(
    _this: *mut AnyObject,
    _cmd: Sel,
    _center: *mut AnyObject,
    response: *mut UNNotificationResponse,
    completion: *mut Block<dyn Fn()>,
) {
    if !response.is_null() {
        let user_info = unsafe { &*response }
            .notification()
            .request()
            .content()
            .userInfo();
        if let Some(route) = route_from_user_info(&user_info) {
            tracing::info!(kind = %route.kind, "a verified notification tap carried a route");
            crate::notification_routes::store_pending_route(route.clone());
            if let Some(app) = APP.get() {
                let _ = app.emit("notification_route", route);
            }
        }
    }
    // iOS hands us the completion handler and waits on it; not calling it earns a watchdog log
    // and delays notification cleanup, so it is called on every path.
    if !completion.is_null() {
        unsafe { (*completion).call(()) };
    }
}

/// Extract the NSE's `ezpdsRoute` block (`{type, requestId?, did?}`, all strings) from a
/// delivered notification's `userInfo`. Anything absent or shaped differently reads as "no
/// route" — a tap on a pre-Phase-C or unverified notification just opens the app.
fn route_from_user_info(
    user_info: &NSDictionary,
) -> Option<crate::notification_routes::PendingNotificationRoute> {
    let string_at = |dict: &NSDictionary, key: &str| -> Option<String> {
        let key = NSString::from_str(key);
        let value = dict.objectForKey(key.as_ref() as &AnyObject)?;
        value.downcast::<NSString>().ok().map(|s| s.to_string())
    };

    let route_key = NSString::from_str("ezpdsRoute");
    let route = user_info
        .objectForKey(route_key.as_ref() as &AnyObject)?
        .downcast::<NSDictionary>()
        .ok()?;
    crate::notification_routes::route_from_fields(
        string_at(&route, "type"),
        string_at(&route, "requestId"),
        string_at(&route, "did"),
    )
}

/// `-application:didFailToRegisterForRemoteNotificationsWithError:`
///
/// Logged, never escalated. The ordinary causes are a simulator with no push support and a
/// device with no network at launch, both of which resolve on their own; the stored state stays
/// "no token", which every caller already handles.
unsafe extern "C-unwind" fn did_fail_to_register(
    _this: *mut AnyObject,
    _cmd: Sel,
    _application: *mut AnyObject,
    error: *mut NSError,
) {
    let description = if error.is_null() {
        "unknown error".to_string()
    } else {
        unsafe { (*error).localizedDescription() }.to_string()
    };
    tracing::warn!(error = %description, "APNs registration failed");
}
