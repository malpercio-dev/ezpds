//! Background backup policy. The blob backup (`blob_backup`) and repo backup (`repo_backup`)
//! each ship an explicit action plus an opportunistic pass on app open; this module asks the
//! platform's [`Scheduler`](crate::scheduler) to also run both mirrors in the background, so
//! an opted-in identity's mirrors stay topped up without the user opening the app.
//!
//! When the job fires, [`run_backup_sweep`] runs both mirror passes over every managed DID,
//! sequentially, alternating which mirror leads across fires via the durable global Keychain
//! turn `background-backup-next-mirror`: the platform's task budget can expire between the
//! two passes, so the alternation keeps it from systematically starving either mirror. Each
//! pass is gated on its own per-DID opt-in flag, so the two opt-ins are honored independently.
//! Overlap with a foreground pass is safe: the per-DID mirror locks serialize writes and the
//! passes are idempotent (content-addressed, atomically-replaced files), so an interrupted
//! sweep self-heals. `run_sweep_with` is the unit-tested loop, generic over the step's error
//! type so one loop drives both mirrors.
//!
//! User-tunable policy is app-global (`BackgroundBackupSettings`, Keychain account
//! `blob-backup-settings`; camelCase `backgroundEnabled`/`requireExternalPower`/`wifiOnly`,
//! defaults on/off/off) because the sweep is one job over every opted-in identity.
//! [`apply_schedule`] turns the settings into a request: none when background backups are off;
//! otherwise network required, external power per the setting, and "unmetered only" for
//! `wifiOnly`, no sooner than every 12 hours.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::scheduler::{BackgroundJob, JobRequest};
use crate::{blob_backup, repo_backup};

/// The earliest the platform may run the next sweep, after the request is (re-)armed. A floor,
/// not a deadline. ~12h keeps the mirror fresh (new media is protected within a day) without
/// asking to wake more often than a media backup needs to.
const EARLIEST_BEGIN_AFTER: Duration = Duration::from_secs(12 * 60 * 60);

// ── User-tunable settings (app-global) ───────────────────────────────────────

/// Global Keychain account holding the background-backup settings JSON. App-wide (not
/// per-DID): the sweep is one `BGProcessingTask` covering every opted-in identity, so its
/// power/network policy is a single shared setting.
pub const SETTINGS_ACCOUNT: &str = "blob-backup-settings";

/// Global Keychain account holding the mirror that should lead the next background sweep.
/// The task budget can expire between the two mirror passes, so this durable cross-fire turn
/// makes that interruption fair over time.
pub const NEXT_MIRROR_ACCOUNT: &str = "background-backup-next-mirror";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mirror {
    Blob,
    Repo,
}

impl Mirror {
    const fn encoded(self) -> &'static [u8] {
        match self {
            Self::Blob => b"blob",
            Self::Repo => b"repo",
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::Blob => Self::Repo,
            Self::Repo => Self::Blob,
        }
    }
}

/// Claim the lead position for this fire and durably hand the next fire to the other mirror.
/// Missing/corrupt/unreadable state starts with blobs for backward compatibility. Keychain
/// trouble is non-fatal: the sweep still protects data, and the next fire retries the flip.
fn take_mirror_lead() -> Mirror {
    let lead = match crate::keystore::get_item(NEXT_MIRROR_ACCOUNT) {
        Ok(raw) if raw == Mirror::Repo.encoded() => Mirror::Repo,
        Ok(raw) if raw == Mirror::Blob.encoded() => Mirror::Blob,
        Ok(_) => {
            tracing::warn!(
                "background backup: mirror-order state is invalid; restarting with blob first"
            );
            Mirror::Blob
        }
        Err(e) if crate::keystore::is_not_found(&e) => Mirror::Blob,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "background backup: could not read mirror-order state; using blob first"
            );
            Mirror::Blob
        }
    };

    if let Err(e) = crate::keystore::store_item(NEXT_MIRROR_ACCOUNT, lead.other().encoded()) {
        tracing::warn!(
            error = %e,
            "background backup: could not persist the next mirror order"
        );
    }
    lead
}

/// User-tunable policy for the background media-backup sweep. App-global. Serializes as
/// camelCase to match the `$lib/ipc` `BackgroundBackupSettings` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundBackupSettings {
    /// Whether iOS may wake the app to run a backup sweep at all. Off keeps the
    /// opportunistic app-open pass but stops OS-scheduled wakes.
    pub background_enabled: bool,
    /// Only run the sweep while the device is on external power (charging). Off by default
    /// so the sweep isn't starved on devices that rarely charge on a predictable schedule.
    pub require_external_power: bool,
    /// Skip the sweep on a cellular (metered) link — a video-heavy account's mirror can be
    /// large. Enforced at fire time via a reachability check (`BGProcessingTaskRequest`
    /// can't express "Wi-Fi only").
    pub wifi_only: bool,
}

impl Default for BackgroundBackupSettings {
    fn default() -> Self {
        Self {
            background_enabled: true,
            require_external_power: false,
            wifi_only: false,
        }
    }
}

/// Error from the background-backup settings commands. Serializes as
/// `{ "code": "SCREAMING_SNAKE_CASE" }` like the sibling wallet error enums.
#[derive(Debug, Serialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackgroundBackupError {
    #[error("keychain error: {message}")]
    KeychainError { message: String },
    #[error("could not encode settings: {message}")]
    SerializationError { message: String },
}

/// Read the persisted settings, or the defaults when unset or unreadable. A corrupt/
/// unreadable value reads as the defaults (background on), never an error — a diagnostic
/// hiccup must not silently disable a backup the user relies on.
pub fn load_settings() -> BackgroundBackupSettings {
    crate::keystore::get_item(SETTINGS_ACCOUNT)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

/// Tauri command: the current background-backup settings, for the Settings screen.
pub fn get_background_backup_settings() -> BackgroundBackupSettings {
    load_settings()
}

/// Tauri command: persist the background-backup settings and re-apply the schedule (submit or
/// cancel the background request to match them).
/// Returns the stored settings.
pub fn set_background_backup_settings(
    settings: BackgroundBackupSettings,
) -> Result<BackgroundBackupSettings, BackgroundBackupError> {
    let json =
        serde_json::to_vec(&settings).map_err(|e| BackgroundBackupError::SerializationError {
            message: e.to_string(),
        })?;
    crate::keystore::store_item(SETTINGS_ACCOUNT, &json).map_err(|e| {
        BackgroundBackupError::KeychainError {
            message: e.to_string(),
        }
    })?;
    apply_schedule();
    Ok(settings)
}

/// Submit or withdraw the background request to match the current settings. Called at
/// startup and whenever the settings change.
pub fn apply_schedule() {
    let settings = load_settings();
    if settings.background_enabled {
        crate::scheduler::schedule(JobRequest {
            job: BackgroundJob::BackupMirror,
            earliest_after: EARLIEST_BEGIN_AFTER,
            // Both passes fetch over the network.
            requires_network: true,
            requires_external_power: settings.require_external_power,
            unmetered_only: settings.wifi_only,
        });
    } else {
        // Drop any pending request so a disabled setting takes effect immediately.
        crate::scheduler::cancel(BackgroundJob::BackupMirror);
    }
}

/// Summary of one background sweep — counts only, for `tracing` and the unit tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackupSweepReport {
    /// Opted-in identities the sweep attempted a pass for.
    pub attempted: u32,
    /// Attempts that completed without error.
    pub succeeded: u32,
    /// Attempts that returned an error (logged, never aborts the sweep).
    pub failed: u32,
    /// Identities skipped because the user has not opted in.
    pub skipped: u32,
}

/// Sweep core: back up every opted-in identity, degrading per-DID — one identity's failure
/// is tallied and logged, never stops the others. Generic over the opt-in predicate, the
/// per-DID backup step, AND its error type (`E: Display`, the only thing the sweep does with a
/// failure is log it) so the one tested loop drives both the blob mirror
/// (`blob_backup::BlobBackupError`) and the repo mirror (`repo_backup::RepoBackupError`). Fully
/// unit-testable without a live PDS, Keychain, or iCloud. Sequential by design: the passes share
/// the network and the process-global per-DID mirror locks, and a background sweep has no reason
/// to race them concurrently.
pub async fn run_sweep_with<F, Fut, E>(
    dids: &[String],
    is_enabled: impl Fn(&str) -> bool,
    backup_one: F,
) -> BackupSweepReport
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let mut report = BackupSweepReport::default();
    for did in dids {
        if !is_enabled(did) {
            report.skipped += 1;
            continue;
        }
        report.attempted += 1;
        match backup_one(did.clone()).await {
            Ok(()) => report.succeeded += 1,
            Err(e) => {
                tracing::warn!(did = %did, error = %e, "background backup: pass failed");
                report.failed += 1;
            }
        }
    }
    report
}

/// Run one background backup wake-up over every managed identity: both mirror passes,
/// alternating which leads on each fire (see the module doc). The scheduler has already
/// applied the network conditions before calling this.
pub async fn run_backup_sweep(core: &crate::oauth::Core) {
    let dids = crate::identity_store::IdentityStore
        .list_identities()
        .unwrap_or_default();

    // The platform aborts the whole job when its bounded budget expires. Claim and flip the
    // durable lead turn before either pass starts, so repeated expirations cannot always
    // discard the same trailing mirror.
    match take_mirror_lead() {
        Mirror::Blob => {
            run_blob_sweep(core, &dids).await;
            run_repo_sweep(core, &dids).await;
        }
        Mirror::Repo => {
            run_repo_sweep(core, &dids).await;
            run_blob_sweep(core, &dids).await;
        }
    }
}

async fn run_blob_sweep(core: &crate::oauth::Core, dids: &[String]) {
    let blob = run_sweep_with(dids, blob_backup::is_backup_enabled, |did| async move {
        blob_backup::run_backup_for_did(core, &did)
            .await
            .map(|_| ())
    })
    .await;
    tracing::info!(
        attempted = blob.attempted,
        succeeded = blob.succeeded,
        failed = blob.failed,
        skipped = blob.skipped,
        "background blob backup sweep complete"
    );
}

async fn run_repo_sweep(core: &crate::oauth::Core, dids: &[String]) {
    let repo = run_sweep_with(dids, repo_backup::is_backup_enabled, |did| async move {
        repo_backup::run_backup_for_did(core, &did)
            .await
            .map(|_| ())
    })
    .await;
    tracing::info!(
        attempted = repo.attempted,
        succeeded = repo.succeeded,
        failed = repo.failed,
        skipped = repo.skipped,
        "background repo backup sweep complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use blob_backup::BlobBackupError;
    use repo_backup::RepoBackupError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn dids(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn sweep_backs_up_only_opted_in_identities() {
        let all = dids(&["did:plc:a", "did:plc:b", "did:plc:c"]);
        // b is opted out.
        let enabled = |did: &str| did != "did:plc:b";
        let backed_up = Mutex::new(Vec::new());

        let report = run_sweep_with(&all, enabled, |did| {
            let backed_up = &backed_up;
            async move {
                backed_up.lock().unwrap().push(did);
                Ok::<(), BlobBackupError>(())
            }
        })
        .await;

        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 2,
                succeeded: 2,
                failed: 0,
                skipped: 1,
            }
        );
        assert_eq!(
            *backed_up.lock().unwrap(),
            vec!["did:plc:a".to_string(), "did:plc:c".to_string()]
        );
    }

    #[tokio::test]
    async fn sweep_degrades_per_did_and_continues() {
        let all = dids(&["did:plc:a", "did:plc:b", "did:plc:c"]);
        let attempts = AtomicUsize::new(0);

        // The middle identity fails; the sweep must still attempt the third.
        let report = run_sweep_with(
            &all,
            |_| true,
            |did| {
                let attempts = &attempts;
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    if did == "did:plc:b" {
                        Err(BlobBackupError::NetworkError {
                            message: "boom".to_string(),
                        })
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 3,
                succeeded: 2,
                failed: 1,
                skipped: 0,
            }
        );
    }

    #[tokio::test]
    async fn sweep_with_no_opted_in_identities_does_nothing() {
        let all = dids(&["did:plc:a", "did:plc:b"]);
        let called = AtomicUsize::new(0);

        let report = run_sweep_with(
            &all,
            |_| false,
            |did| {
                let called = &called;
                async move {
                    called.fetch_add(1, Ordering::SeqCst);
                    let _ = did;
                    Ok::<(), BlobBackupError>(())
                }
            },
        )
        .await;

        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 0,
                succeeded: 0,
                failed: 0,
                skipped: 2,
            }
        );
    }

    #[tokio::test]
    async fn sweep_over_empty_identity_list_is_a_noop() {
        let report = run_sweep_with(
            &[],
            |_| true,
            |_did| async { Ok::<(), BlobBackupError>(()) },
        )
        .await;
        assert_eq!(report, BackupSweepReport::default());
    }

    // The generic sweep core drives the repo mirror too: its per-DID step returns
    // `RepoBackupError` rather than `BlobBackupError`, and a per-DID failure still degrades
    // (logged + tallied) without stopping the remaining identities — proving one tested loop
    // covers both mirrors after the error-type generalization.
    #[tokio::test]
    async fn sweep_drives_repo_error_type_and_degrades() {
        let all = dids(&["did:plc:a", "did:plc:b", "did:plc:c"]);
        let attempts = AtomicUsize::new(0);

        let report = run_sweep_with(
            &all,
            |_| true,
            |did| {
                let attempts = &attempts;
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    if did == "did:plc:b" {
                        Err(RepoBackupError::NetworkError {
                            message: "boom".to_string(),
                        })
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            report,
            BackupSweepReport {
                attempted: 3,
                succeeded: 2,
                failed: 1,
                skipped: 0,
            }
        );
    }

    // The blob and repo opt-ins are honored independently. Over one shared DID list, each
    // mirror's sweep selects only the identities opted into THAT mirror — a DID opted into blob
    // only is never repo-backed-up, and vice versa; a DID opted into both is swept by both.
    #[tokio::test]
    async fn blob_and_repo_opt_in_are_independent() {
        let all = dids(&["did:plc:blob-only", "did:plc:repo-only", "did:plc:both"]);
        let blob_enabled = |did: &str| did == "did:plc:blob-only" || did == "did:plc:both";
        let repo_enabled = |did: &str| did == "did:plc:repo-only" || did == "did:plc:both";

        let blobbed = Mutex::new(Vec::new());
        let blob_report = run_sweep_with(&all, blob_enabled, |did| {
            let blobbed = &blobbed;
            async move {
                blobbed.lock().unwrap().push(did);
                Ok::<(), BlobBackupError>(())
            }
        })
        .await;

        let repoed = Mutex::new(Vec::new());
        let repo_report = run_sweep_with(&all, repo_enabled, |did| {
            let repoed = &repoed;
            async move {
                repoed.lock().unwrap().push(did);
                Ok::<(), RepoBackupError>(())
            }
        })
        .await;

        // Each mirror touched only its own opted-in identities.
        assert_eq!(
            *blobbed.lock().unwrap(),
            vec!["did:plc:blob-only".to_string(), "did:plc:both".to_string()]
        );
        assert_eq!(
            *repoed.lock().unwrap(),
            vec!["did:plc:repo-only".to_string(), "did:plc:both".to_string()]
        );
        assert_eq!(blob_report.attempted, 2);
        assert_eq!(blob_report.skipped, 1);
        assert_eq!(repo_report.attempted, 2);
        assert_eq!(repo_report.skipped, 1);
    }

    #[test]
    fn settings_default_to_background_on_no_power_no_wifi_gate() {
        let d = BackgroundBackupSettings::default();
        assert!(d.background_enabled);
        assert!(!d.require_external_power);
        assert!(!d.wifi_only);
    }

    #[test]
    fn settings_round_trip_as_camel_case() {
        let s = BackgroundBackupSettings {
            background_enabled: false,
            require_external_power: true,
            wifi_only: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"backgroundEnabled\":false"));
        assert!(json.contains("\"requireExternalPower\":true"));
        assert!(json.contains("\"wifiOnly\":true"));
        let back: BackgroundBackupSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn mirror_lead_alternates_durably_across_fires() {
        crate::keystore::clear_for_test();

        assert_eq!(take_mirror_lead(), Mirror::Blob);
        assert_eq!(
            crate::keystore::get_item(NEXT_MIRROR_ACCOUNT).unwrap(),
            Mirror::Repo.encoded()
        );
        assert_eq!(take_mirror_lead(), Mirror::Repo);
        assert_eq!(
            crate::keystore::get_item(NEXT_MIRROR_ACCOUNT).unwrap(),
            Mirror::Blob.encoded()
        );
        assert_eq!(take_mirror_lead(), Mirror::Blob);
    }

    #[test]
    fn invalid_mirror_lead_state_recovers_to_blob_then_repo() {
        crate::keystore::clear_for_test();
        crate::keystore::store_item(NEXT_MIRROR_ACCOUNT, b"invalid").unwrap();

        assert_eq!(take_mirror_lead(), Mirror::Blob);
        assert_eq!(take_mirror_lead(), Mirror::Repo);
    }
}
