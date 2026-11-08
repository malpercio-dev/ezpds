//! Fakes for every [`Platform`] adapter, and [`core`]/[`core_with_fakes`], which build a
//! [`Core`] over them. A test injects its own `Core`; nothing is installed process-wide, so
//! tests never share state.
//!
//! Compiled for this crate's tests and, through the `test-support` feature, for a dependent's
//! `[dev-dependencies]`. The feature refuses to compile without `debug_assertions`: an
//! in-memory key store in a release build would lose every key on exit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use crate::backup_store::{BackupLocation, BackupStore, Materialize};
use crate::events::EventSink;
use crate::keystore::{Accessibility, KeyStore, KeyStoreError};
use crate::oauth::Core;
use crate::platform::{Clock, Platform};
use crate::scheduler::{BackgroundJob, JobRequest, Scheduler};
use crate::signer::SoftwareSigner;

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("obsign-core's `test-support` feature must never reach a release build");

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── KeyStore ────────────────────────────────────────────────────────────────

type Item = (Vec<u8>, Accessibility);

/// An in-memory [`KeyStore`] with a cloud slot. Keys are `(cloud, account)`, modelling the
/// two-namespace split; each value carries the class its last write set, an attribute, never
/// part of the address. Deleting a missing item is [`KeyStoreError::NotFound`], as on iOS.
#[derive(Default)]
pub struct MemKeyStore {
    items: Mutex<HashMap<(bool, String), Item>>,
}

impl MemKeyStore {
    fn get_in(&self, cloud: bool, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        lock(&self.items)
            .get(&(cloud, account.to_string()))
            .map(|(data, _)| data.clone())
            .ok_or(KeyStoreError::NotFound)
    }

    fn set_in(&self, cloud: bool, account: &str, data: &[u8], class: Accessibility) {
        lock(&self.items).insert((cloud, account.to_string()), (data.to_vec(), class));
    }

    fn delete_in(&self, cloud: bool, account: &str) -> Result<(), KeyStoreError> {
        lock(&self.items)
            .remove(&(cloud, account.to_string()))
            .map(|_| ())
            .ok_or(KeyStoreError::NotFound)
    }

    /// The class `account` was last written under in the device-local namespace. iOS applies
    /// the class on fetch and never reports it, so the fake is the only place it can be
    /// asserted.
    pub fn accessibility_of(&self, account: &str) -> Option<Accessibility> {
        lock(&self.items)
            .get(&(false, account.to_string()))
            .map(|(_, class)| *class)
    }
}

impl KeyStore for MemKeyStore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        self.get_in(false, account)
    }
    fn set(&self, account: &str, data: &[u8], class: Accessibility) -> Result<(), KeyStoreError> {
        self.set_in(false, account, data, class);
        Ok(())
    }
    fn delete(&self, account: &str) -> Result<(), KeyStoreError> {
        self.delete_in(false, account)
    }
    fn get_synced(&self, account: &str) -> Result<Vec<u8>, KeyStoreError> {
        self.get_in(true, account)
    }
    fn set_synced(&self, account: &str, data: &[u8]) -> Result<(), KeyStoreError> {
        self.set_in(true, account, data, Accessibility::WhenUnlocked);
        Ok(())
    }
    fn delete_synced(&self, account: &str) -> Result<(), KeyStoreError> {
        self.delete_in(true, account)
    }
}

// ── EventSink ───────────────────────────────────────────────────────────────

/// An [`EventSink`] that records every event in order.
#[derive(Default)]
pub struct RecordingEvents {
    events: Mutex<Vec<(String, serde_json::Value)>>,
}

impl RecordingEvents {
    pub fn events(&self) -> Vec<(String, serde_json::Value)> {
        lock(&self.events).clone()
    }
}

impl EventSink for RecordingEvents {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        lock(&self.events).push((event.to_string(), payload));
    }
}

// ── BackupStore ─────────────────────────────────────────────────────────────

/// A [`BackupStore`] whose root and evicted placeholders a test sets.
///
/// No root by default, which every backup surface reads as "unavailable". A placeholder is
/// keyed by file name: `Ok(bytes)` downloads (writes `bytes` at the path and reports
/// `Ok(true)`), `Err(reason)` is a failed download, and an unknown name has no placeholder
/// (`Ok(false)`).
#[derive(Default)]
pub struct FakeBackupStore {
    root: Mutex<Option<(PathBuf, BackupLocation)>>,
    placeholders: Mutex<HashMap<String, Result<Vec<u8>, String>>>,
}

impl FakeBackupStore {
    pub fn set_root(&self, root: Option<(PathBuf, BackupLocation)>) {
        *lock(&self.root) = root;
    }

    /// An evicted file named `name` whose download yields `bytes`.
    pub fn evicted(&self, name: &str, bytes: &[u8]) {
        lock(&self.placeholders).insert(name.to_string(), Ok(bytes.to_vec()));
    }

    /// An evicted file named `name` whose download fails with `reason`.
    pub fn evicted_failing(&self, name: &str, reason: &str) {
        lock(&self.placeholders).insert(name.to_string(), Err(reason.to_string()));
    }
}

impl BackupStore for FakeBackupStore {
    fn root(&self) -> Option<(PathBuf, BackupLocation)> {
        lock(&self.root).clone()
    }

    fn materialize<'a>(&'a self, path: &'a Path) -> Materialize<'a> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let outcome = lock(&self.placeholders).get(&name).cloned();
        Box::pin(async move {
            match outcome {
                Some(Ok(bytes)) => {
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    tokio::fs::write(path, bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                    Ok(true)
                }
                Some(Err(reason)) => Err(reason),
                None => Ok(false),
            }
        })
    }
}

// ── Scheduler ───────────────────────────────────────────────────────────────

/// What a [`RecordingScheduler`] was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerCall {
    Schedule(JobRequest),
    Cancel(BackgroundJob),
}

/// A [`Scheduler`] that records every request in order.
#[derive(Default)]
pub struct RecordingScheduler {
    calls: Mutex<Vec<SchedulerCall>>,
}

impl RecordingScheduler {
    pub fn calls(&self) -> Vec<SchedulerCall> {
        lock(&self.calls).clone()
    }
}

impl Scheduler for RecordingScheduler {
    fn schedule(&self, request: JobRequest) {
        lock(&self.calls).push(SchedulerCall::Schedule(request));
    }
    fn cancel(&self, job: BackgroundJob) {
        lock(&self.calls).push(SchedulerCall::Cancel(job));
    }
}

// ── Clock ───────────────────────────────────────────────────────────────────

/// A [`Clock`] that reads one instant until a test moves it.
pub struct FixedClock {
    now: Mutex<SystemTime>,
}

impl FixedClock {
    pub fn new(now: SystemTime) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    pub fn set(&self, now: SystemTime) {
        *lock(&self.now) = now;
    }

    pub fn advance(&self, by: Duration) {
        *lock(&self.now) += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        *lock(&self.now)
    }
}

// ── Core ────────────────────────────────────────────────────────────────────

/// Handles on the fakes behind a [`core_with_fakes`] `Core`.
#[derive(Clone)]
pub struct Fakes {
    pub keys: Arc<MemKeyStore>,
    pub events: Arc<RecordingEvents>,
    pub backup: Arc<FakeBackupStore>,
    pub scheduler: Arc<RecordingScheduler>,
    pub clock: Arc<FixedClock>,
}

/// A [`Core`] over fresh fakes: an empty key store, the software signer over it, no backup
/// location, a clock fixed at the moment of the call, and an unroutable plc.directory.
pub fn core() -> Core {
    core_with_fakes().0
}

/// [`core`] with its clock fixed at `unix_secs`, for tests that pin a signed timestamp.
pub fn core_at(unix_secs: u64) -> Core {
    let (core, fakes) = core_with_fakes();
    fakes
        .clock
        .set(std::time::UNIX_EPOCH + Duration::from_secs(unix_secs));
    core
}

/// [`core`], plus handles to inspect or steer its fakes.
pub fn core_with_fakes() -> (Core, Fakes) {
    let fakes = Fakes {
        keys: Arc::default(),
        events: Arc::default(),
        backup: Arc::default(),
        scheduler: Arc::default(),
        clock: Arc::new(FixedClock::new(SystemTime::now())),
    };
    let core = Core::new(Platform {
        keys: fakes.keys.clone(),
        signer: Arc::new(SoftwareSigner::new(fakes.keys.clone())),
        events: fakes.events.clone(),
        backup: fakes.backup.clone(),
        scheduler: Some(fakes.scheduler.clone()),
        clock: fakes.clock.clone(),
    });
    // An unroutable plc.directory, so a test that forgot `with_pds_client` fails rather than
    // reaching the real directory.
    let core = core.with_pds_client(crate::pds_client::new_for_test(
        "http://127.0.0.1:9".to_string(),
    ));
    (core, fakes)
}
