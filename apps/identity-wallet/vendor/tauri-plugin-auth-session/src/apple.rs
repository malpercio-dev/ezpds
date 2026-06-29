//! ASWebAuthenticationSession implementation for macOS and iOS.

#![allow(non_snake_case)]
#![allow(deprecated)] // initWithURL_callbackURLScheme_completionHandler for broader OS compat

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AllocAnyThread, MainThreadMarker, MainThreadOnly};
use objc2_authentication_services::{
    ASWebAuthenticationPresentationContextProviding, ASWebAuthenticationSession,
    ASWebAuthenticationSessionErrorCode, ASWebAuthenticationSessionErrorDomain,
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString, NSURL};

#[cfg(target_os = "macos")]
use objc2_app_kit::NSApplication;

#[cfg(target_os = "ios")]
use objc2_ui_kit::{UIApplication, UIScene, UIWindowScene};

// ---------------------------------------------------------------------------
// PresentationContextProvider — ObjC class implementing
// ASWebAuthenticationPresentationContextProviding
// ---------------------------------------------------------------------------

pub struct ProviderIvars {
    _placeholder: Cell<bool>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TauriAppleAuthPresentationProvider"]
    #[ivars = ProviderIvars]
    pub struct AuthPresentationProvider;

    unsafe impl NSObjectProtocol for AuthPresentationProvider {}

    unsafe impl ASWebAuthenticationPresentationContextProviding for AuthPresentationProvider {
        #[unsafe(method_id(presentationAnchorForWebAuthenticationSession:))]
        fn presentation_anchor(&self, _session: &ASWebAuthenticationSession) -> Retained<NSObject> {
            get_key_window_as_anchor()
        }
    }
);

impl AuthPresentationProvider {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(ProviderIvars {
            _placeholder: Cell::new(false),
        });
        unsafe { msg_send![super(this), init] }
    }
}

// ---------------------------------------------------------------------------
// Platform-specific: get key window as presentation anchor
// ---------------------------------------------------------------------------

/// macOS: get the key window from NSApplication.
#[cfg(target_os = "macos")]
fn get_key_window_as_anchor() -> Retained<NSObject> {
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = NSApplication::sharedApplication(mtm);
    let window = app
        .keyWindow()
        .or_else(|| app.windows().firstObject())
        .expect("No windows available for ASWebAuthenticationSession presentation anchor");
    // NSWindow -> NSResponder -> NSObject (2 levels)
    Retained::into_super(Retained::into_super(window))
}

/// iOS: get the key window from the connected UIWindowScene.
#[cfg(target_os = "ios")]
fn get_key_window_as_anchor() -> Retained<NSObject> {
    let mtm = unsafe { MainThreadMarker::new_unchecked() };
    let app = UIApplication::sharedApplication(mtm);
    let scenes = app.connectedScenes();
    for scene in &scenes {
        // Safety: In a Tauri iOS app all connected scenes are UIWindowScene.
        // UIWindowScene is a subclass of UIScene so the pointer cast is valid.
        let scene_ptr: *const UIScene = &*scene;
        let ws: &UIWindowScene = unsafe { &*(scene_ptr as *const UIWindowScene) };
        let windows = ws.windows();
        if let Some(window) = windows.firstObject() {
            // UIWindow -> UIView -> UIResponder -> NSObject (3 levels)
            return Retained::into_super(Retained::into_super(Retained::into_super(window)));
        }
    }
    panic!("No windows available for ASWebAuthenticationSession presentation anchor");
}

// ---------------------------------------------------------------------------
// Session lifetime management
// ---------------------------------------------------------------------------

/// Holds the active ASWebAuthenticationSession and its dependencies, preventing
/// them from being deallocated before the completion handler fires.
///
/// Stored in a thread-local because all access happens on the main thread
/// (creation via `DispatchQueue::main().exec_async`, completion handler also
/// called on main thread by the framework).
struct ActiveSession {
    _session: Retained<ASWebAuthenticationSession>,
    _provider: Retained<AuthPresentationProvider>,
    _completion: RcBlock<dyn Fn(*mut NSURL, *mut NSError)>,
}

thread_local! {
    static ACTIVE_SESSION: RefCell<Option<ActiveSession>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Start an ASWebAuthenticationSession and return the callback URL.
pub async fn start_session(
    auth_url: String,
    callback_url_scheme: String,
    ephemeral: bool,
) -> Result<String, String> {
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<String, String>>();

    // ASWebAuthenticationSession must be created and started on the main thread.
    dispatch2::DispatchQueue::main().exec_async(move || {
        let mtm = unsafe { MainThreadMarker::new_unchecked() };

        // Drop any previous session (e.g., from a prior auth attempt that
        // was cancelled but whose cleanup didn't run yet).
        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = None;
        });

        // Parse the auth URL
        let url_nsstring = NSString::from_str(&auth_url);
        let Some(url) = NSURL::URLWithString(&url_nsstring) else {
            let _ = tx.send(Err(format!("Invalid auth URL: {auth_url}")));
            return;
        };

        // Create the callback scheme string
        let scheme = NSString::from_str(&callback_url_scheme);

        // Build the completion handler block
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let tx_clone = Arc::clone(&tx);

        let completion_handler =
            RcBlock::new(move |callback_url: *mut NSURL, error: *mut NSError| {
                let result = if !error.is_null() {
                    let error = unsafe { &*error };
                    let domain = error.domain();
                    let code = error.code();

                    let expected_domain: &NSString =
                        unsafe { ASWebAuthenticationSessionErrorDomain };
                    let is_cancelled = *domain == *expected_domain
                        && code == ASWebAuthenticationSessionErrorCode::CanceledLogin.0;

                    if is_cancelled {
                        Err("user_cancelled".to_string())
                    } else {
                        let description = error.localizedDescription();
                        Err(format!("Auth session error: {description}"))
                    }
                } else if callback_url.is_null() {
                    Err("Auth session completed without a callback URL".to_string())
                } else {
                    let url = unsafe { &*callback_url };
                    match url.absoluteString() {
                        Some(s) => Ok(s.to_string()),
                        None => Err("Failed to get callback URL string".to_string()),
                    }
                };

                if let Some(tx) = tx_clone.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(result);
                }

                // Release the session, provider, and this block. Safe because
                // Apple's framework holds its own strong reference to the block
                // for the duration of this callback invocation.
                ACTIVE_SESSION.with(|s| {
                    *s.borrow_mut() = None;
                });

                // Bring the app back to the foreground on macOS.
                // ASWebAuthenticationSession opens a separate browser window,
                // and closing it doesn't restore focus to the originating app.
                #[cfg(target_os = "macos")]
                {
                    let mtm = unsafe { MainThreadMarker::new_unchecked() };
                    let app = NSApplication::sharedApplication(mtm);
                    app.activateIgnoringOtherApps(true);
                }
            });

        // Create the ASWebAuthenticationSession
        let session = unsafe {
            ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
                ASWebAuthenticationSession::alloc(),
                &url,
                Some(&scheme),
                RcBlock::as_ptr(&completion_handler),
            )
        };

        unsafe {
            session.setPrefersEphemeralWebBrowserSession(ephemeral);
        }

        // Set the presentation context provider (required for the auth sheet
        // to anchor to a window)
        let provider = AuthPresentationProvider::new(mtm);
        unsafe {
            session.setPresentationContextProvider(Some(ProtocolObject::from_ref(&*provider)));
        }

        // Start the session.
        let started = unsafe { session.start() };
        if !started {
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(Err("Failed to start ASWebAuthenticationSession".to_string()));
            }
            return;
        }

        // Store in thread-local to keep alive until the completion handler
        // fires and clears it.
        ACTIVE_SESSION.with(|s| {
            *s.borrow_mut() = Some(ActiveSession {
                _session: session,
                _provider: provider,
                _completion: completion_handler,
            });
        });
    });

    rx.await
        .unwrap_or_else(|_| Err("Auth session channel dropped unexpectedly".to_string()))
}
