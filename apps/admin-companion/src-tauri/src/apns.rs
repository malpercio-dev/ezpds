// pattern: Imperative Shell (iOS-only Objective-C runtime bridge)

//! How the APNs device token reaches `notifications.rs` — the console copy of the wallet's
//! bridge (`apps/identity-wallet/src-tauri/src/apns.rs`), which carries the full rationale:
//! iOS delivers the token exactly once per launch to two **application-delegate** methods
//! and exposes it nowhere else, so this module installs those methods on Tauri's live
//! delegate class (add-only — `class_addMethod` declines if the selector already exists,
//! never displacing Tauri's own behaviour) before asking iOS to register.
//!
//! On a **changed** token the callback re-registers every pairing; an unchanged token (iOS
//! re-delivers on every launch) does nothing.
//!
//! The same add-only mechanism carries the third callback: a notification **tap**
//! (`userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:`) is only
//! ever delivered to `UNUserNotificationCenter`'s delegate, which Tauri never sets — so the
//! method is added to the application delegate's class and the center's delegate pointed at
//! it. The tap handler reads the `ezpdsRoute` block the Notification Service Extension writes
//! only on the *verified* (HPKE-authenticated) path, parks it in `notification_routes` (the
//! portable, host-tested half), and emits the `notification_route` event — how an operator
//! alert deep-links into the right server's Accounts screen.
//!
//! Everything here is compiled only for iOS (`lib.rs` gates the module), so the testable
//! logic (hex encoding, change detection, the per-pairing registration sweep, the route
//! slot) lives in `notifications.rs` and `notification_routes.rs`, and this file stays the
//! smallest possible runtime plumbing.

use std::sync::OnceLock;

use block2::{Block, RcBlock};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, ProtocolObject, Sel};
use objc2::{sel, MainThreadMarker};
use objc2_foundation::{NSData, NSDictionary, NSError, NSString};
use objc2_ui_kit::UIApplication;
use objc2_user_notifications::{
    UNAuthorizationOptions, UNNotificationResponse, UNUserNotificationCenter,
    UNUserNotificationCenterDelegate,
};
use tauri::{AppHandle, Emitter};

/// The app handle the delegate callbacks resolve state through. Written once during `setup`.
static APP: OnceLock<AppHandle> = OnceLock::new();

/// Ask the user for notification permission and, if granted, ask iOS for a device token.
///
/// Called from `setup`. Fire-and-forget: the prompt is answered whenever the operator
/// answers it, the token arrives asynchronously afterwards, and everything downstream
/// treats "no token" as an ordinary state (`AWAITING_APNS_TOKEN`).
pub fn register_for_remote_notifications(app: &AppHandle) {
    if APP.set(app.clone()).is_err() {
        tracing::warn!("APNs registration was requested twice; ignoring the second call");
        return;
    }

    let Some(mtm) = MainThreadMarker::new() else {
        tracing::error!("APNs registration must run on the main thread; skipping");
        return;
    };

    if !install_delegate_methods(mtm) {
        // Without the callbacks the token would arrive nowhere, so asking for one would only
        // spend a permission prompt the operator gets nothing for.
        return;
    }

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

/// Install the device-token callbacks and the notification-tap callback on the live
/// delegate's class. Returns whether the token can now reach us.
fn install_delegate_methods(mtm: MainThreadMarker) -> bool {
    let application = UIApplication::sharedApplication(mtm);
    let Some(delegate) = (unsafe { application.delegate() }) else {
        tracing::error!("no application delegate yet; cannot receive an APNs device token");
        return false;
    };

    // The delegate is an object like any other, and its *class* is what the runtime
    // dispatches on — so that is where the methods go, not on the instance.
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

    // Best-effort: without it a registration failure is silent, but the token path works.
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

    // The notification-tap callback. Best-effort like the failure callback: without it a
    // tap still foregrounds the app, it just lands on Home.
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
type DidReceiveResponseFn = unsafe extern "C-unwind" fn(
    *mut AnyObject,
    Sel,
    *mut AnyObject,
    *mut UNNotificationResponse,
    *mut Block<dyn Fn()>,
);

/// `-application:didRegisterForRemoteNotificationsWithDeviceToken:`
///
/// iOS calls this on every launch whether or not the token changed, so the work is gated
/// on an actual change: re-registering every pairing each launch would spend a round trip
/// per relay to write rows that already say exactly this.
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
            tracing::info!("APNs device token changed; re-registering every pairing");
            let Some(app) = APP.get().cloned() else {
                return;
            };
            tauri::async_runtime::spawn(async move {
                let topic = app.config().identifier.clone();
                crate::notifications::re_register_every_pairing(&topic).await;
            });
        }
        Err(e) => tracing::error!(error = %e, "could not store the APNs device token"),
    }
}

/// `-userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:`
///
/// The operator tapped a delivered alert. If the Notification Service Extension left an
/// `ezpdsRoute` block — which it does only for a payload that verified under HPKE Auth — the
/// route is parked for the frontend and announced as a `notification_route` event: the park
/// covers a cold start (the frontend drains it on mount), the event covers a warm foreground.
/// The route only decides which pairing's screen to open; everything shown there is fetched
/// through that pairing's signed requests as usual.
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

/// Extract the NSE's `ezpdsRoute` block (`{type, server?, screen?, did?}`, all strings)
/// from a delivered notification's `userInfo`. Anything absent or shaped differently reads
/// as "no route" — a tap on an unverified notification just opens the app.
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
        string_at(&route, "server"),
        string_at(&route, "screen"),
        string_at(&route, "did"),
    )
}

/// `-application:didFailToRegisterForRemoteNotificationsWithError:`
///
/// Logged, never escalated: the ordinary causes (simulator, no network at launch) resolve
/// on their own, and the stored state stays "no token", which every caller handles.
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
