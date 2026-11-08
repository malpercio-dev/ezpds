# Android storage for user-held backups

Date: 2026-11-07. Wayfinder MM-613, research ticket MM-623.

The wallet's mirrors (media blobs, repo CAR snapshot) must survive app uninstall and may be hundreds of MB. On iOS they live in an iCloud Drive container behind `BackupStore::root() -> Option<(PathBuf, BackupLocation)>` (`crates/obsign-core/src/backup_store.rs`). This note records what Android offers, from developer.android.com and Google Play policy pages only. Facts carry the API level they hold from. Anything the primary docs do not state is marked **Unconfirmed**. This note makes no recommendation.

## 1. Storage Access Framework (SAF)

Source for all of section 1 unless noted: https://developer.android.com/training/data-storage/shared/documents-files

- **Tree picker.** `ACTION_OPEN_DOCUMENT_TREE` is available from API 21. The user grants access to a directory and everything below it. Needs no permission.
- **Restrictions from API 30.** The picker cannot grant the internal-storage root, the root of any reliable SD card volume, or the `Download` directory. A subfolder of any of these can still be chosen.
- **Survives reboot: yes (API 19+).** Without `takePersistableUriPermission` a grant "lasts until the user's device restarts" (same guide). `ContentResolver.takePersistableUriPermission` (added API 19) says "Once taken, the permission grant will be remembered across device reboots": https://developer.android.com/reference/android/content/ContentResolver#takePersistableUriPermission(android.net.Uri,%20int)
- **Survives moving or deleting the document: no.** The guide warns that even after taking the grant, access is lost "if the associated document is moved or deleted"; the app must ask again.
- **Survives app update: Unconfirmed.** The docs do not mention updates. Nothing in them says an update clears grants.
- **Survives uninstall and reinstall: Unconfirmed in the docs.** No page I fetched says what happens to persisted URI grants when the app is removed. The grants are scoped to the app's package and uid, and I expect them to be cleared. Treat the folder as needing a re-pick after reinstall until verified on a device. The files themselves remain: SAF files "remain on the device after your app is uninstalled" (same guide), and the storage overview table lists "Documents and other files: Files removed on app uninstall? No": https://developer.android.com/training/data-storage
- **Persisted-grant cap: Unconfirmed.** The reference page does not state a number.
- **Reaching a document from native code.** `ContentResolver.openFileDescriptor(uri, mode)` returns a `ParcelFileDescriptor`. Modes are "r", "w", "wt", "wa", "rw", "rwt". The reference warns that "exact implementation of these may differ for each Provider" and that "w" may or may not truncate. Exclusive "r" or "w" may return "a pipe or socket pair to enable streaming"; "rw" "implies a file on disk that supports seeking": https://developer.android.com/reference/android/content/ContentResolver
  - `ParcelFileDescriptor.detachFd()` (API 12) returns the native fd and detaches it: "You are now responsible for closing the fd in native code." It also says not to detach when the creator expects a reliable signal through `close()`/`closeWithError()`. `getFd()` leaves ownership with the PFD. `dup()` shares file position: https://developer.android.com/reference/android/os/ParcelFileDescriptor
  - So a raw fd that Rust wraps as `std::fs::File` (via `FromRawFd`) is supported by the documented API. For a seekable `File` use "rw" or "r". Whether a given provider hands back a seekable file or a pipe is provider-dependent. For the local `ExternalStorageProvider` I expect a real file, but the docs do not say so (**Unconfirmed**).
- **Child operations on a granted tree.** In `DocumentsContract` (https://developer.android.com/reference/android/provider/DocumentsContract):
  - list children: `buildChildDocumentsUriUsingTree` (API 21), then query the child URI.
  - create: `createDocument` (API 21).
  - rename: `renameDocument` (API 21), only for documents with `FLAG_SUPPORTS_RENAME`.
  - move: `moveDocument` (API 24), only for documents with `FLAG_SUPPORTS_MOVE`.
  - delete: `deleteDocument` (API 19), only for documents with `FLAG_SUPPORTS_DELETE`.
  - Support is per provider and per document, read from `Document.COLUMN_FLAGS` (guide above). `DocumentFile` (androidx) wraps the same calls.
  - Create cannot overwrite: for `ACTION_CREATE_DOCUMENT` the guide says a same-named file gets " (1)" appended. The guide states this for `ACTION_CREATE_DOCUMENT` only; `createDocument` on a tree is likely the same (**Unconfirmed**). Write-temp-then-rename needs `FLAG_SUPPORTS_RENAME` on the provider. Replacing in place needs `openFileDescriptor(uri, "wt")`, where truncation is provider-dependent.
- **Performance.** The guide cautions: "If you iterate through a large number of files within the directory that's accessed using `ACTION_OPEN_DOCUMENT_TREE`, your app's performance might be reduced." No numbers are given. A document provider is reached through binder and a cursor per directory, not a syscall, so many small files cost more than a few large ones (inference).
- **Cloud providers.** A tree can be on a cloud provider. The guide notes size may be unknown ("remote files") and that virtual files (API 25+) have no binary form and cannot be opened with `openInputStream`. This is the Android analogue of iCloud placeholders in `BackupStore::materialize`.
- **Play Services: no.** SAF is part of the platform. Whether the picker offers a given provider (for example Google Drive) depends on the apps installed.

## 2. MediaStore `Downloads` and `Files`

Source: https://developer.android.com/training/data-storage/shared/media unless noted.

- **Collection.** `MediaStore.Downloads` exists from API 29 ("isn't available on Android 9 (API level 28) and lower").
- **Non-media files: allowed.** The guide says "it's possible to store general-purpose files in either the `Documents/` folder or the `Download/` folder, including non-media files", but "it's better to use the Storage Access Framework for these use cases".
- **Survives uninstall: yes for the files.** "Even after your app is uninstalled, these files remain on the user's device."
- **Reinstall attribution (API 29+).** Each file is attributed to one app. After uninstall and reinstall the app must hold `READ_EXTERNAL_STORAGE` to read the files it created, because "the system considers the file to be attributed to the previously installed version". Without that permission the reinstalled app cannot see its own old files. On API 33+ the media permissions (`READ_MEDIA_*`) do not cover non-media files. Whether `READ_EXTERNAL_STORAGE` still has effect for this on API 33+ is **Unconfirmed**; the page I read does not say.
- **Own files without permission.** From API 29 no storage permission is needed for files the app owns, "including files in the `MediaStore.Downloads` collection".
- **`MediaStore.Files`.** With scoped storage it shows only the photos, videos and audio the app created. Without scoped storage it shows all media types. It is not a general file listing for an app that has scoped storage.
- **Path-addressable.**
  - API 29: not by default. Direct paths to other shared-storage files need `requestLegacyExternalStorage="true"` plus `READ_EXTERNAL_STORAGE`, and the use-cases guide recommends that only as a temporary opt-out. It applies only when targeting API 29 or lower; "After you update your app to target Android 11 (API level 30), the system ignores the `requestLegacyExternalStorage` attribute": https://developer.android.com/training/data-storage/use-cases
  - API 30 and up: direct `File` API and native `fopen()` are allowed for shared storage, but an app with no permissions gets this only for its app-specific directory and "media files that are attributed to your app". Otherwise a `FileNotFoundException` occurs.
  - Performance: sequential direct-path reads match MediaStore. Random reads and writes "can be up to twice as slow".
  - Creating a file means `ContentResolver.insert` with `DISPLAY_NAME` and `RELATIVE_PATH`, never the `DATA` column. The `DATA` column can be used to read existing files.
  - Whether a path to a self-created `Downloads` file works for a non-media file on API 30+ is **Unconfirmed**. The documented rule covers "media files attributed to your app".
- **`MANAGE_EXTERNAL_STORAGE` ("all files access", API 30+).** Source: https://developer.android.com/training/data-storage/manage-all-files
  - Grants read and write to all of shared storage including direct path access, except `Android/data` and most of `Android/`. The user turns it on in a Settings page.
  - Google Play policy (https://support.google.com/googleplay/android-developer/answer/10467955): the permission is for core functionality and needs the Permissions Declaration Form and approval. "Backup and restore apps" are named as an eligible use, with the condition that the app must show a need to "automatically access multiple directories outside of its app-specific storage space". Media access and per-file picker flows are prohibited uses. Apps that skip the form "may be removed from Google Play".
  - Whether a wallet that backs up its own two folders would qualify is **Unconfirmed**. It is a Play review decision, and the app writes to one folder it could create through MediaStore or SAF.

## 3. App-specific external storage (`getExternalFilesDir`)

Source: https://developer.android.com/training/data-storage/app-specific unless noted.

- **Path-addressable: yes.** Plain `File` or `fopen`, no permission from API 19. From API 30 an app cannot create its own app-specific directory on external storage manually, but the one from `getExternalFilesDir` is provided.
- **Deleted on uninstall: yes.** "When the user uninstalls your app, the files saved in app-specific storage are removed." The guide says not to use it for anything the user expects to persist independently of the app. The storage overview table agrees (app-specific files: removed on uninstall, yes): https://developer.android.com/training/data-storage
- **Not guaranteed present.** "Aren't guaranteed to be accessible, such as when a removable SD card is taken out." Check `Environment.getExternalStorageState()`.
- **Auto Backup: included by default, not excluded.** The question assumed an exclusion; the docs say the opposite. Auto Backup includes "Files on external storage in the directory returned by `getExternalFilesDir(String)`" (API 23+). Excluded by default are only `getCacheDir()`, `getCodeCacheDir()` and `getNoBackupFilesDir()`. An app can exclude it with the `external` domain in its backup rules. Source: https://developer.android.com/identity/data/autobackup
- **Other apps.** Not readable by other apps from API 30 even with permission. This makes it a poor place for a copy the user should be able to find and move.

## 4. Auto Backup size cap

Source: https://developer.android.com/identity/data/autobackup

- "Every app can allocate up to 25 MB of backup data per app user." Backup data is "limited to 25 MB per app" in a private Google Drive folder and does not count toward the user's quota. Applies to apps targeting API 23+.
- Over the cap, the system calls `onQuotaExceeded()` and "doesn't back up data to the cloud".
- Only the most recent backup is kept. The data "can't be read by the user or other apps".
- Conclusion: hundreds of MB cannot ride on Auto Backup. Device-to-device transfer rules are separate in Android 12+ (`<device-transfer>`), and the docs suggest large files can be sent through that path but not the cloud one. That path is not a user-held backup.
- Auto Backup needs Google Drive on the device (Play Services); the docs describe the target as the user's Google Drive.

## 5. Writes while the device is locked

- **Credential-encrypted (CE) storage** is the default location and "only available after the user has unlocked the device". It stays available "until the user restarts the device". Enabling a lock screen afterwards does not remove it. Device-encrypted (DE) storage is available before first unlock, but only to components marked `android:directBootAware`. By default apps do not run in Direct Boot. Source: https://developer.android.com/privacy-and-security/direct-boot (API 24+).
- **Scope of "locked".** The question's case is "locked after first unlock". By the page above, CE storage is available after the first successful unlock until reboot, so a later screen lock does not remove it. The page does not name the lock-screen case directly; this is read from "until the user restarts the device".
- **WorkManager.** Work runs "sometime after its Constraints are met", with a 10-minute limit per run. `WorkManager.initialize` "throws an `IllegalStateException` when attempting to initialize in direct boot mode". The WorkManager pages do not say whether a `Worker` runs before first unlock, so the app should assume it does not until the user unlocks once after boot (**Unconfirmed**). Sources: https://developer.android.com/reference/androidx/work/WorkManager and https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started
- **Per location, after first unlock:**
  - App-specific external storage: lives on the user's CE-protected area. Writable after first unlock.
  - MediaStore Downloads: same, written through the MediaStore provider. Writable after first unlock.
  - SAF tree: depends on the provider. `ExternalStorageProvider` sits on the same CE-protected storage. A cloud provider also needs the network and its own app. The docs do not say how providers behave before unlock (**Unconfirmed**).
  - None of these is writable in a pure pre-unlock state, because the wallet is not Direct Boot aware.

## 6. Summary

| Option | Survives uninstall | Reach from Rust | Needs Play Services | UX cost | Min API |
|---|---|---|---|---|---|
| SAF tree (`ACTION_OPEN_DOCUMENT_TREE`) | Files yes. Grant: unconfirmed, expect re-pick | fd via `openFileDescriptor` + `detachFd` (documented). No path | No | Pick a folder once; re-pick after uninstall, a moved or deleted folder, and probably reinstall | 21 (grant persistence 19, `detachFd` 12) |
| MediaStore `Downloads` (own files) | Files yes. Reinstalled app needs `READ_EXTERNAL_STORAGE` to see them | Content URI + fd; direct path on 30+ is documented for media files attributed to the app only | No | Never (no picker) | 29 |
| `MANAGE_EXTERNAL_STORAGE` + shared path | Yes | Plain path | No | Settings toggle once; Play declaration and review | 30 |
| Legacy opt-out (`requestLegacyExternalStorage`) | Yes | Plain path | No | Storage permission prompt | 29 only; ignored when targeting 30+ |
| `getExternalFilesDir` | No | Plain path | No | Never | 19 |
| Auto Backup | Yes (restored on install) | Backs up private files; cannot carry the mirrors | Effectively yes (Google Drive) | Never | 23, cap 25 MB |

## What this means for the `BackupStore` trait

The trait returns a `PathBuf`. Only the app-specific directory (which dies on uninstall), `MANAGE_EXTERNAL_STORAGE`, and a pre-API-30 opt-out give a stable path that outlives the app. The one option that needs no special permission and no Play review, the SAF tree, hands out file descriptors, not paths. That is the fact the later decision ticket weighs.

## Unconfirmed, to check on a device or in AOSP source

1. Persisted SAF grants across app update, and across uninstall and reinstall.
2. Persisted-grant count cap.
3. Whether the local `ExternalStorageProvider` returns a seekable file for "rw" and honours `FLAG_SUPPORTS_RENAME`.
4. `READ_EXTERNAL_STORAGE` for reinstall visibility of non-media `Downloads` files on API 33+.
5. Direct path to a self-created non-media `Downloads` file on API 30+.
6. WorkManager `Worker` execution before first unlock, and SAF provider behaviour before unlock.
7. Play approval odds for `MANAGE_EXTERNAL_STORAGE` for this app.
