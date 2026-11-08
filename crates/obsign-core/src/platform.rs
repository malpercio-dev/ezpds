//! [`Platform`]: the adapters a shell hands [`Core`](crate::oauth::Core), and [`Clock`], the
//! one platform trait without a module of its own (the others live in `keystore`, `signer`,
//! `events`, `backup_store`, `scheduler`).
//!
//! `Core` owns the adapters, so a test builds a `Core` over fakes
//! ([`crate::test_support`]) instead of installing anything process-wide.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backup_store::BackupStore;
use crate::events::EventSink;
use crate::keystore::KeyStore;
use crate::scheduler::Scheduler;
use crate::signer::Signer;

/// Wall time, injected so ceremonies and the 72-hour PLC window are testable. Every ceremony and
/// PLC-window read goes through this; the diagnostics log still stamps its own breadcrumbs.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;

    /// [`Clock::now`] as Unix seconds, for the timestamps device-key-signed envelopes carry.
    /// A clock before 1970 reads as 0; the server rejects the stale envelope.
    fn unix_timestamp(&self) -> i64 {
        self.now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    /// [`Clock::now`] as a chrono UTC instant, for the RFC 3339 fields the core writes.
    fn utc_now(&self) -> chrono::DateTime<chrono::Utc> {
        self.now().into()
    }
}

/// The host's wall clock: every production shell's [`Clock`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// The adapters a shell implements, handed to [`Core::new`](crate::oauth::Core::new).
///
/// The signer usually holds a clone of `keys` (the software signer stores its scalars there).
/// `scheduler` is `None` where background work is not a platform concern (desktop, the
/// Simulator): requests are dropped, and every job also runs in the foreground.
#[derive(Clone)]
pub struct Platform {
    pub keys: Arc<dyn KeyStore>,
    pub signer: Arc<dyn Signer>,
    pub events: Arc<dyn EventSink>,
    pub backup: Arc<dyn BackupStore>,
    pub scheduler: Option<Arc<dyn Scheduler>>,
    pub clock: Arc<dyn Clock>,
}
