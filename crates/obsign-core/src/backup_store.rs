//! Where the user-held backup lives: the [`BackupStore`] trait a shell implements.
//!
//! The media and posts mirrors (`blob_backup`, `repo_backup`) write into a directory the
//! platform chooses. On iOS that is the app's iCloud Drive container, which survives the
//! device; with iCloud Drive off there is no acceptable location on a real device, because a
//! silent local fallback would tell the user they hold a device-loss-surviving copy when they
//! do not. Off-device (macOS, the Simulator) a local app-data directory keeps the surface
//! exercisable. A cloud folder can also evict a file to a placeholder, which restore must
//! download before reading.
//!
//! Installation follows [`keystore`](crate::keystore). An uninstalled store reports no
//! location, so every backup surface reads "unavailable" rather than writing somewhere the
//! user was not told about.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::OnceLock;

use serde::Serialize;

/// Where the mirror lives, as reported to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupLocation {
    /// The app's iCloud Drive ubiquity container (survives the device; Files-app visible).
    Icloud,
    /// A local app-data directory (dev/simulator/desktop fallback, or the env override).
    Local,
}

pub type Materialize<'a> = Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;

pub trait BackupStore: Send + Sync {
    /// The mirror's root directory, or `None` when no acceptable location exists right now
    /// (iCloud Drive off on a device). Asked on every use: the answer changes when the user
    /// signs in or out of iCloud.
    fn root(&self) -> Option<(PathBuf, BackupLocation)>;

    /// If `path` was evicted to a cloud placeholder, download it and return `Ok(true)` once
    /// the real file is at `path`. `Ok(false)` means there is no placeholder (the file is
    /// genuinely missing); `Err` means the download failed or timed out.
    fn materialize<'a>(&'a self, path: &'a Path) -> Materialize<'a>;
}

static INSTALLED: OnceLock<Box<dyn BackupStore>> = OnceLock::new();

/// Install the process-wide store. The second and later calls are refused and hand the store
/// back.
pub fn install(store: Box<dyn BackupStore>) -> Result<(), Box<dyn BackupStore>> {
    INSTALLED.set(store)
}

/// The installed store's root, or `None` when nothing is installed.
pub fn root() -> Option<(PathBuf, BackupLocation)> {
    INSTALLED.get().and_then(|store| store.root())
}

/// The installed store's [`BackupStore::materialize`]; with nothing installed there are no
/// placeholders.
pub async fn materialize(path: &Path) -> Result<bool, String> {
    match INSTALLED.get() {
        Some(store) => store.materialize(path).await,
        None => Ok(false),
    }
}
