# Android share-1 cloud slot: what the platform offers

Researched 2026-11-07 for the wayfinder map (MM-613, ticket MM-622). Primary sources only: developer.android.com, developers.google.com, grapheneos.org. Anything not stated by a source is marked **unconfirmed**.

## Context: what "cloud slot" means to the core

`crates/obsign-core/src/keystore.rs` gates `*_synced` accessors (`store_item_synced`, `get_item_synced`, `delete_item_synced`) behind `syncs_to_icloud`, which allows only the recovery-share-1 account. The slot is optional: a platform without one leaves the `*_synced` trait methods returning their defaults. The requirement is a small secret blob, written once, read back on another device of the same user, that the vendor cannot read.

## 1. Block Store (`com.google.android.gms.auth.blockstore`)

**Limits.** "Block Store allows developers to save and restore up to 16 byte arrays" and the entry limit is "maximum 4kb per entry" (https://developer.android.com/identity/block-store). The API reference disagrees: `MAX_SIZE` = 1024 and `MAX_ENTRY_COUNT` = 16 (https://developers.google.com/android/reference/com/google/android/gms/auth/blockstore/BlockstoreClient). **The per-entry cap is unresolved (1 KB vs 4 KB).** A share fits either way; budget for 1 KB. No separate total byte cap is stated beyond 16 entries.

**Encryption.** Data is "end-to-end encrypted when possible." E2EE requires Android 9 or higher and a screen lock (PIN, pattern or password); `isEndToEndEncryptionAvailable()` returns false otherwise, and Google recommends checking it before enabling cloud backup (same Block Store page). Without E2EE the sample code stores "only for D2D restore", i.e. no cloud copy.

**Can Google read it?** The Block Store pages say only "end-to-end encrypted when possible" and never state in so many words that Google cannot read the data. The Cloud Key Vault whitepaper, describing Android backup infrastructure (Block Store says it is "built on top of the Backup and Restore infrastructure"), says: "Google's servers have no ability to access or restore the contents of the encrypted backups -- only a device with the user's LSKF can decrypt the backups" (https://developer.android.com/about/versions/pie/security/ckv-whitepaper). That whitepaper is dated 2018 and marked work-in-progress, and it is about Android backups generally. **Whether it applies to Block Store verbatim is an inference, not a Block Store-specific statement.**

**Requirements.** Library is "powered by Google Play services" (`play-services-auth-blockstore`). Device-to-device restore works only through flows that transfer the Google Account: "If the Google Account is not transferred, neither will the Block Store data" (https://developer.android.com/identity/block-store/testing-restore-flows). The reference says D2D transfer happens "if a google account is also transferred."

**Restore semantics.** Both paths exist.
- Device-to-device at setup (cable, Samsung Smart Switch, Android wireless restore). Source Android 6+; target Android 9+.
- Cloud restore at setup ("Can't use old phone"), signing in with an account that "needs to be the same as the backup account in your source device". Source Android 6+; target Pixel from Android 9, all other vendors Android 12+ (https://developer.android.com/identity/block-store).
- Restore is part of the setup/restore flow; the docs describe no way to pull from the cloud into an already-set-up device. **Unconfirmed** beyond that absence.

**Uninstall/reinstall.** If Backup is enabled (Settings > Google > Backup), Block Store data persists across uninstall and reinstall on the same device. The reference says data "may be cleared by Google Play services on certain user actions," e.g. clearing storage. Calling `storeBytes` with `shouldBackupToCloud` false or unset deletes that device's previously backed-up cloud bytes at the next sync.

**No Google account.** Not stated directly. Cloud restore requires signing in to the backup account, and D2D requires account transfer, so a no-account user has no documented restore path. **Unconfirmed** whether local-only storage still works with no account.

## 2. Drive `appDataFolder`

Sources: https://developers.google.com/workspace/drive/api/guides/appdata, scope list https://developers.google.com/identity/protocols/oauth2/scopes.

- Scope `https://www.googleapis.com/auth/drive.appdata` ("See, create, and delete its own configuration data in your Google Drive"); OAuth 2.0 user authorization required.
- Hidden from the user and other Drive apps; not openable in the Drive UI. Users can delete the folder themselves. Deleted when the user uninstalls the app from My Drive (disconnecting it in Drive, not the Android uninstall).
- Files cannot be shared or trashed.
- Encryption and Google's ability to read: **not stated** on the appdata or files pages. The API offers no client-side encryption, so a share would need app-level encryption under a key Google does not hold.
- Needs network, OAuth consent and a Google account. Not tied to a device, so it survives device loss and Android uninstall.

## 3. Auto Backup / Key-Value Backup

Sources: https://developer.android.com/identity/data/autobackup, https://developer.android.com/identity/data/keyvaluebackup.

- Encryption: "end-to-end encrypted on devices running Android 9 or higher using the device's PIN, pattern, or password." The XML flag `clientSideEncryption` requires backup enabled and a screen lock; `disableIfNoEncryptionCapabilities="true"` in `<cloud-backup>` blocks cloud upload when encryption is unavailable. Device-to-device transfers continue regardless.
- Size: 25 MB per app per user (Auto Backup); 5 MB for key-value backup. Over quota, nothing uploads.
- Selective include: yes. With `android:dataExtractionRules` (target API 31+), an `<include>` means the system "backs up only the files specified", and `<exclude>` takes precedence. Separate rule sets for `<cloud-backup>`, `<device-transfer>`, and (Android 16 QPR2) `<cross-platform-transfer>`. Apps targeting 30 or lower use `fullBackupContent`. Backed-up domains are app files, databases, shared prefs and the external files dir; Keystore keys are not files and are not covered.
- Restore: when the app is installed. At setup the user picks a backup dataset; without the setup wizard the device restores only its own backups. Stored in the user's Drive, protected by Google Account credentials; backup must be enabled; roughly daily when idle on Wi-Fi.
- Android 12+ nuance: on some OEMs `allowBackup="false"` disables cloud backup but not D2D.
- The same page tells developers to use Block Store, not files, for credentials and tokens.
- Key-value backup: the transport "is not guaranteed to be available on all Android-powered devices"; the app cannot tell which transport is in use.
- The user can disable backup; the Backup Service then deletes saved data and will not restore it later.

## 4. Without Google Play services

- Block Store: a Google Play services library, so it needs Play services. GrapheneOS sandboxed Play runs Play services as an unprivileged app with "a small subset of privileged functionality" unavailable (https://grapheneos.org/features, https://grapheneos.org/faq). **Unconfirmed from primary sources** whether Block Store cloud backup or restore works there; the GrapheneOS pages read do not mention it.
- Drive appDataFolder: a REST API reachable by plain OAuth over HTTPS, so Play services is not inherently required if the app runs the OAuth flow itself. This is an inference; not tested and not stated by Google.
- Auto Backup: an AOSP framework feature, but the Google transport depends on Play services and is "not guaranteed to be available on all" devices. GrapheneOS says AOSP APIs normally provided through Play services "will continue to be implemented using open source providers like the Seedvault backup app", and Seedvault "must be explicitly enabled". Seedvault is a different transport with its own encryption and storage target, not a Google cloud slot.

## 5. Comparison

| Option | Vendor can read? | Survives device loss? | Needs Google account? |
|---|---|---|---|
| Block Store cloud backup | Conditional: documented only as "E2EE when possible" (Android 9+, screen lock); the whitepaper says Google cannot, applicability to Block Store is inferred | Yes, via cloud restore at setup with the same account | Yes (cloud restore, account transfer) |
| Drive appDataFolder | Not stated; treat as yes unless the app encrypts under its own key | Yes | Yes (OAuth) |
| Auto Backup, one included file | Conditional: E2EE on Android 9+ with screen lock, otherwise Google-held; `disableIfNoEncryptionCapabilities` forces the former | Yes, restore at install or setup, if backup is enabled | Yes (Drive-backed) |
| Block Store, D2D only (no cloud flag) | No cloud copy | No (needs the old device) | Account transfer required |

## Unconfirmed / open

1. Block Store per-entry cap: 4 KB (guide) vs 1024 (reference).
2. No Block Store-specific statement that Google cannot read cloud data.
3. Block Store and Drive behavior with no Google account, and Block Store on GrapheneOS sandboxed Play.
4. Drive appDataFolder encryption and Google's access: no first-party statement found.
