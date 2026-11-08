//! Events from the core to the UI: the [`EventSink`] trait a shell implements.
//!
//! Fire-and-forget: an event no UI is listening for is not an error the core can act on.
//! [`Core::emit`](crate::oauth::Core::emit) serializes the payload and hands it to the sink
//! the `Core` owns.

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);

    /// Show a system notification, for news the user must get while the app is not on
    /// screen (a background job has no UI listening). Fire-and-forget, like `emit`; a shell
    /// with no notification surface drops it.
    fn notify(&self, title: &str, body: &str);
}
