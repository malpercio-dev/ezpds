// pattern: Imperative Shell (iOS-only Objective-C runtime bridge)
//
// How the device token reaches `notifications.rs`. iOS delivers it exactly once per launch, to
// two methods on the **application delegate** — there is no polling API, no
// `UIApplication.deviceToken` property, and no Tauri plugin for it. So this module installs
// those two methods on Tauri's delegate class at startup, before asking iOS to register.
//
// Everything here is compiled only for iOS (`lib.rs` gates the whole module), which also means
// it is compiled only by the `aarch64-apple-ios` cross-compile in the PR lane and exercised only
// on a device. Both consequences shape the code: the logic that *can* be tested lives in
// `notifications.rs` (hex encoding, change detection, the registration sequence), and what stays
// here is the smallest possible amount of runtime plumbing.
//
// # Why add methods rather than swizzle
//
// `class_addMethod` fails if the class already implements the selector, and that failure mode is
// the one we want: Tauri's delegate does not implement either method today, and if a future
// version starts to, silently replacing its implementation would be a far worse outcome than
// declining and logging. Nothing here ever calls `method_setImplementation` or
// `method_exchangeImplementations`, so no existing behaviour can be displaced.
//
// # Why a process-global handle
//
// An IMP is a bare C function pointer with no capture. The callback therefore reads the
// `AppHandle` from a `OnceLock` written during `setup` — the unit-of-global shape `IdentityStore`
// and `pds_capabilities` already use — rather than threading state it structurally cannot carry.

use std::sync::OnceLock;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, Sel};
use objc2::{sel, MainThreadMarker};
use objc2_foundation::{NSData, NSError};
use objc2_ui_kit::UIApplication;
use objc2_user_notifications::{UNAuthorizationOptions, UNUserNotificationCenter};
use tauri::{AppHandle, Manager};

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

    true
}

type DidRegisterFn = unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, *mut NSData);
type DidFailFn = unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, *mut NSError);

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
