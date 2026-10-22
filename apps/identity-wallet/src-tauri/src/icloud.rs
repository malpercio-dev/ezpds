//! The wallet's [`BackupStore`]: where the user-held media and posts mirrors live, and how an
//! evicted iCloud file is brought back. `run()` installs [`AppBackupStore`] in `setup`.
//!
//! The rules (see `obsign_core::backup_store` for why): the iCloud Drive ubiquity container
//! when the user has iCloud Drive on; on a real device with it off, **no** location; on every
//! other target (macOS, the Simulator), a local app-data directory so the surface stays
//! exercisable off-device.

use std::path::{Path, PathBuf};

use obsign_core::backup_store::{BackupLocation, BackupStore, Materialize};

pub(crate) struct AppBackupStore {
    /// Resolves the app-data directory for the off-device fallback.
    #[cfg_attr(all(target_os = "ios", not(target_env = "sim")), allow(dead_code))]
    pub(crate) app: tauri::AppHandle,
}

impl BackupStore for AppBackupStore {
    fn root(&self) -> Option<(PathBuf, BackupLocation)> {
        if let Some(dir) = ubiquity_documents_dir() {
            return Some((dir, BackupLocation::Icloud));
        }
        #[cfg(all(target_os = "ios", not(target_env = "sim")))]
        {
            None
        }
        #[cfg(not(all(target_os = "ios", not(target_env = "sim"))))]
        {
            use tauri::Manager;
            let dir = self.app.path().app_data_dir().ok()?.join("blob-backup");
            Some((dir, BackupLocation::Local))
        }
    }

    fn materialize<'a>(&'a self, path: &'a Path) -> Materialize<'a> {
        Box::pin(async move {
            #[cfg(target_os = "ios")]
            {
                icloud_materialize(path).await
            }
            #[cfg(not(target_os = "ios"))]
            {
                let _ = path;
                Ok(false)
            }
        })
    }
}

/// The app's iCloud Drive ubiquity container `Documents/` directory, if available.
///
/// `URLForUbiquityContainerIdentifier(nil)` resolves the app's default container
/// (from the `com.apple.developer.ubiquity-container-identifiers` entitlement) and
/// extends the sandbox to it; iOS syncs anything written there and the mirror is
/// user-visible in the Files app. Returns `None` when the user has iCloud Drive off
/// (or the entitlement is absent). Called off the main thread by construction —
/// Tauri async commands run on a worker pool, and Apple documents the call as
/// potentially slow.
#[cfg(target_os = "ios")]
fn ubiquity_documents_dir() -> Option<PathBuf> {
    use objc2_foundation::NSFileManager;
    let manager = NSFileManager::defaultManager();
    let url = manager.URLForUbiquityContainerIdentifier(None)?;
    let path = url.path()?;
    Some(PathBuf::from(path.to_string()).join("Documents"))
}

#[cfg(not(target_os = "ios"))]
fn ubiquity_documents_dir() -> Option<PathBuf> {
    None
}

/// How long to wait for iOS to finish downloading an evicted placeholder before giving
/// up on that blob (recorded as a per-blob failure). Bounded so restoring a large,
/// mostly-evicted mirror can't wedge indefinitely on one slow or stalled download.
#[cfg(target_os = "ios")]
const MATERIALIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
/// How often to re-check whether the file has materialized while awaiting the download.
#[cfg(target_os = "ios")]
const MATERIALIZE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// iOS: if `path` has an evicted `.{name}.icloud` placeholder, ask iCloud to download it
/// and poll (bounded) until the real file appears at `path`. Contract per
/// `BackupStore::materialize`.
#[cfg(target_os = "ios")]
async fn icloud_materialize(path: &Path) -> Result<bool, String> {
    let Some(placeholder) = icloud_placeholder_path(path) else {
        return Ok(false);
    };
    // No `.icloud` sibling → the file is genuinely gone, not merely evicted.
    if !tokio::fs::try_exists(&placeholder).await.unwrap_or(false) {
        return Ok(false);
    }

    // Kick off the download (this also extends our sandbox to the item). Confined to a
    // synchronous helper so no non-`Send` Foundation object is held across an await.
    start_downloading_ubiquitous_item(path)?;

    let deadline = tokio::time::Instant::now() + MATERIALIZE_TIMEOUT;
    loop {
        // iOS replaces the placeholder with the real file at the original path once the
        // download completes; a partial download never surfaces here (and if one somehow
        // did, restore's own CID check would reject it before upload).
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "iCloud did not finish downloading within {}s",
                MATERIALIZE_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(MATERIALIZE_POLL_INTERVAL).await;
    }
}

/// `…/blobs/{name}` → `…/blobs/.{name}.icloud`, iOS's evicted-placeholder naming.
#[cfg(target_os = "ios")]
fn icloud_placeholder_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!(".{name}.icloud")))
}

/// Ask `NSFileManager` to begin downloading the ubiquitous item at `path`. Synchronous
/// and self-contained: every Foundation object is created and dropped here, so the
/// caller's future stays `Send`.
#[cfg(target_os = "ios")]
fn start_downloading_ubiquitous_item(path: &Path) -> Result<(), String> {
    use objc2_foundation::{NSFileManager, NSString, NSURL};

    let path_str = path
        .to_str()
        .ok_or_else(|| "blob path is not valid UTF-8".to_string())?;
    let ns_path = NSString::from_str(path_str);
    // objc2 exposes both of these as safe wrappers (same as the `NSFileManager` call in
    // `ubiquity_documents_dir`); the returned `NSError` is formatted via its Debug impl.
    let url = NSURL::fileURLWithPath(&ns_path);
    let manager = NSFileManager::defaultManager();
    manager
        .startDownloadingUbiquitousItemAtURL_error(&url)
        .map_err(|e| format!("failed to start iCloud download: {e:?}"))
}
