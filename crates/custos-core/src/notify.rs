// pattern: Imperative Shell

//! The account-notification seam features push through: [`NotificationPayload`] and the
//! [`AccountNotifier`] trait. The sealing and relay transport live in `pds` (`notifications.rs`),
//! which installs its notifier in `CoreState.account_notifier` when `[notifications] relay` is
//! set. Features never see the relay client, so a feature crate can push without depending on
//! `pds`.

use std::future::Future;
use std::pin::Pin;

use serde::Serialize;

use crate::CoreState;

/// The plaintext a device's Notification Service Extension decrypts and renders.
///
/// Serialized camelCase, matching the wallet's decoder. `pad` is the length-quantizing
/// filler; it is meaningless to the reader and is the last field so the arithmetic below can
/// reason about it as a suffix.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPayload {
    /// Machine-readable kind, e.g. `agent_claim_pending`. The app routes on this.
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub title: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Spaces, sized so the serialized APNs body lands on a padding bucket.
    pub pad: String,
}

impl NotificationPayload {
    /// A payload with no padding yet — `pds`'s sealing step computes and applies it.
    pub fn new(kind: &'static str, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            kind,
            title: title.into(),
            body: body.into(),
            data: None,
            pad: String::new(),
        }
    }

    /// Attach structured routing data (a claim attempt id, a subject DID, …).
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Sends a notification to every device registered to an account.
///
/// Object-safe (`Pin<Box<dyn Future>>`) so it lives in `CoreState` as `Arc<dyn AccountNotifier>`.
pub trait AccountNotifier: Send + Sync {
    /// Seal and enqueue `payload` once per device registered to `did`. Never fails: a missed
    /// banner is recovered the next time the app talks to Custos. Returns how many payloads were
    /// enqueued, which some triggers branch on (the consent page shows its match code only when a
    /// push went out).
    fn notify_account<'a>(
        &'a self,
        did: &'a str,
        payload: NotificationPayload,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>>;
}

impl CoreState {
    /// Push `payload` to every device registered to `did` through the installed
    /// [`AccountNotifier`]; `0` when notifications are unconfigured.
    pub async fn notify_account(&self, did: &str, payload: NotificationPayload) -> usize {
        match &self.account_notifier {
            Some(notifier) => notifier.notify_account(did, payload).await,
            None => 0,
        }
    }
}
