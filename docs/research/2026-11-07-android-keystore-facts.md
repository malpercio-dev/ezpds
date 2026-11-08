# Android Keystore facts for the Signer and KeyStore rows

Researched 2026-11-07 for the Android platform-delta plan (wayfinder map MM-613, ticket MM-621). Sources are developer.android.com reference and guides, source.android.com (CDD, Keystore docs), and AOSP source. Each fact names its source and the API level it holds from. Anything not stated by a primary source is marked **unconfirmed**.

Vocabulary: `Signer` is `crates/obsign-core/src/signer.rs`; `KeyStore` and `Accessibility { WhenUnlocked, AfterFirstUnlock }` are `crates/obsign-core/src/keystore.rs`.

## 1. Security level and hardware binding

| Fact | From | Source |
|---|---|---|
| `KeyInfo.isInsideSecureHardware()` returns true if the key resides in secure hardware (TEE or Secure Element). Added API 23, **deprecated API 31**, superseded by `getSecurityLevel()`. | 23 | https://developer.android.com/reference/android/security/keystore/KeyInfo |
| `KeyInfo.getSecurityLevel()` returns one of `SECURITY_LEVEL_SOFTWARE` (0), `TRUSTED_ENVIRONMENT` (1), `STRONGBOX` (2), `UNKNOWN` (-2), `UNKNOWN_SECURE` (-1). TEE and StrongBox mean the key material is plaintext only inside secure hardware. | 31 | same page; constants: https://developer.android.com/reference/android/security/keystore/KeyProperties |
| `UNKNOWN_SECURE` means that, because of the caller's target API level, no exact statement can be made, but the level is at least equivalent to TEE. `UNKNOWN` means no assumption can be made. | 31 | KeyProperties page |
| Guide text: apps targeting API 29+ inspect `getSecurityLevel()`; apps targeting API 28 or lower inspect `isInsideSecureHardware()`. The reference page lists `getSecurityLevel()` as added in API 31, so the guide's "API 29" is the target-SDK gate and the method itself exists only on devices running API 31+. Treat the two as a discrepancy in Google's docs. | 28 / 29 / 31 | https://developer.android.com/privacy-and-security/keystore |
| Consequence for the adapter on a floor of API 28: devices on API 28-30 can only be classified with `isInsideSecureHardware()` (true = TEE or StrongBox, no way to tell them apart from `KeyInfo`). On API 31+, use `getSecurityLevel()` for the three-way answer. A StrongBox claim on API 28-30 has to come from what the adapter requested (see below), not from `KeyInfo`. This is an inference from the two rows above. | 28 | inference |
| Obtaining `KeyInfo`: `KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore").getKeySpec(privateKey, KeyInfo.class)`; for a symmetric key use `SecretKeyFactory`. | 23 | KeyInfo page |
| `KeyGenParameterSpec.Builder.setIsStrongBoxBacked(boolean)`: "Sets whether this key should be protected by a StrongBox security chip." The reference page does not describe failure. | 28 | https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder |
| Failure: `StrongBoxUnavailableException` (extends `java.security.ProviderException`, a `RuntimeException`): "an operation could not be performed because the requested security hardware is not available." Added API 28. | 28 | https://developer.android.com/reference/android/security/keystore/StrongBoxUnavailableException |
| The Keystore guide says the framework throws it "if the StrongBox KeyMint does not support the specified algorithm or key size", and tells apps to then generate the key without `setIsStrongBoxBacked(true)`. It also says to check `PackageManager.FEATURE_STRONGBOX_KEYSTORE` first. It does not say in so many words that the exception is thrown when the device has no StrongBox at all; the exception class description does cover that case. | 28 | https://developer.android.com/privacy-and-security/keystore (section "Use StrongBox KeyMint") |
| StrongBox supports ECDSA and ECDH on P-256, AES 128/256, RSA 2048, HMAC-SHA256, 3DES. A P-256 signing key is therefore a valid StrongBox request. | 28 | same guide |
| The guide's caution: StrongBox is slower, more resource-constrained, and supports fewer concurrent operations. | 28 | same guide |
| Whether StrongBox accepts `DIGEST_NONE` for ECDSA: **unconfirmed** in the pages read. Generate with `SHA-256` only if the adapter signs message input (see section 2). | | |

Requirements on devices (CDD):

- **CDD section 9.11 "Keys and Credentials", requirement [C-1-1]**: "When the device implementation supports a secure lock screen, it: MUST back up the keystore implementation with an isolated execution environment." The same section requires lock-screen authentication to run in that environment ([C-1-3]) and the attestation signing key to live in secure hardware ([C-1-4]). Present in Android 17 CDD and in the Android 9 (API 28) CDD, with the same conditional form. Sources: https://source.android.com/docs/compatibility/17/android-17-cdd and https://source.android.com/docs/compatibility/9/android-9-cdd.
- Section 2.2.5 of the Android 17 CDD (Security Model, Handheld) lists the same keystore requirement unconditionally as 9.11/H-0-2 ("MUST back up the keystore implementation with an isolated execution environment"), plus H-0-3 (RSA, AES, ECDSA, HMAC in a securely isolated area) and H-0-5 (key attestation with a hardware-protected signing key). Same URL. The extraction of this table came through the fetch tool's summariser; re-read the CDD page before quoting these IDs in the plan.
- **Exemption**: both CDD versions exempt a device that launched on an earlier Android release, unless it declares the fingerprint feature, from the isolated-keystore requirement. So "software-only Keystore" is not impossible on a conforming device that was upgraded to API 28+.
- **CDD 9.11.2 StrongBox**: a device that declares `FEATURE_STRONGBOX_KEYSTORE` MUST provide dedicated secure hardware, a discrete CPU, tamper and side-channel resistance, and so on. Android 17 CDD, same URL.
- Meaning for "refuse a physical device that reports software-only Keystore": the CDD obliges a TEE-backed keystore on any device that has a secure lock screen, and unconditionally on handhelds that launched with Android 9 or later. A physical device whose `KeyInfo` reports software (`isInsideSecureHardware()` false, or `SECURITY_LEVEL_SOFTWARE`) is therefore non-conformant, an upgraded legacy device inside the exemption, or an emulator. The CDD does not give an app a way to tell the last two apart from the first; that distinction is **unconfirmed** and is left to the plan. The exemption means a refusal will occasionally hit a conforming old device.

## 2. P-256 signing

- Generate: `KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")`, initialised with `new KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN | PURPOSE_VERIFY).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests(DIGEST_SHA256, ...).build()`. The class docs give a worked "NIST P-256 (aka secp256r1 aka prime256v1)" example. API 23. Sources: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec and https://developer.android.com/privacy-and-security/keystore (the guide's EC example omits the curve spec; the class doc includes it).
- Sign: `Signature.getInstance("SHA256withECDSA")`, `initSign(privateKey)`, `update(data)`, `sign()`. The guide shows exactly this. API 23. Source: Keystore guide.
- `setDigests` "must be specified for signing/verification keys"; the key refuses any digest not authorised. API 23. Source: KeyGenParameterSpec.Builder page.
- **Signature encoding**: the pages read do not state it. The Android `Signature` reference lists `SHA256withECDSA` as available from API 11 and lists no `...inP1363Format` algorithm anywhere in its algorithm table. https://developer.android.com/reference/java/security/Signature. The JCA convention for `SHA256withECDSA` is an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`, but **the DER claim is unconfirmed from a developer.android.com or AOSP page**. The adapter must treat the output as DER, parse r and s, left-pad each to 32 bytes, and reject anything that does not parse.
- **Low-S**: nothing in the reviewed pages says the Keystore normalises S. **Unconfirmed**; assume it does not, and have the adapter normalise (`s > n/2` becomes `n - s`) after DER decoding, exactly as `SoftwareSigner` does with `normalize_s`.
- **Pre-hashed input**: `KeyProperties.DIGEST_NONE` (API 23) is documented as "No digest: sign/authenticate the raw message", and `setDigests` says TLS stacks use it because they compute the digest themselves and have the private key sign it. https://developer.android.com/reference/android/security/keystore/KeyProperties and the Builder page. `NONEwithECDSA` is in the `Signature` algorithm table (API 11+). So the Keystore can sign a caller-supplied digest when the key is generated with `DIGEST_NONE` authorised. Whether the Keystore accepts a 32-byte input as a digest, truncates a longer input, or rejects it is **unconfirmed** from these pages. The trait's `SignFn` takes a message, not a digest, so `SHA256withECDSA` with `DIGEST_SHA256` is the shape that needs no pre-hash support.
- Public key: `keyPair.getPublic().getEncoded()` returns X.509 SubjectPublicKeyInfo DER; the compressed SEC1 point the trait returns must be extracted from it. The class docs do not state this; **unconfirmed from a primary page** beyond the standard `PublicKey.getEncoded()` contract.

## 3. Protection classes

### `setUnlockedDeviceRequired(true)` (API 28)

Source: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder

- "Authorized to be used only while the device is unlocked." The device counts as locked for a user "when the user's apps are currently inaccessible and some form of lock screen authentication is required to regain access".
- Public-key operations are not restricted and work while locked. On Android 11 (API 30) and lower, encryption and verification with symmetric keys were also not restricted; decryption and signing were.
- Such keys can be generated or imported while locked, provided the device was unlocked at least once since reboot, but cannot be used until unlock.
- It is distinct from `setUserAuthenticationRequired(true)`; they can be combined.
- **Caveats the doc lists for Android 12 through 14 (API 31-34)**: with no secure lock screen the keys cannot be generated, imported, or used; removing the secure lock screen deletes all of that user's unlocked-device-required keys; unlocking with a non-strong biometric (face on many devices) does not re-authorise them; biometric unlock does not re-authorise them in profiles that share the parent's lock. Fixed in Android 15 (API 35). The doc's advice: use the flag only on Android 15 and higher.
- `KeyInfo.isUnlockedDeviceRequired()` reads it back; the reference page marks it "added in version 36.1" (an API-level label quirk; the setter is API 28).
- AOSP lists "keys that are only usable when the device is unlocked" as a KeyMint 4.1 addition (Android 10 era) and describes `lock`/`unlock` permissions that evict and restore super-keys. https://source.android.com/docs/security/features/keystore

### Credential-encrypted vs device-encrypted storage

Source: https://developer.android.com/training/articles/direct-boot (Android 7.0 / API 24 onward)

- Credential-encrypted (CE) storage is the default and "available after the user has successfully unlocked the device and until the user restarts the device". If the user enables a lock screen after unlocking, CE stays available. So once the device has been unlocked after boot, CE remains readable when the screen locks again.
- Device-encrypted (DE) storage is available during Direct Boot and after unlock, using a key available after verified boot. Google says not to use it as a general-purpose encrypted store, and not to migrate passwords or tokens into it.
- Components run before first unlock only if marked `android:directBootAware="true"`; `ACTION_LOCKED_BOOT_COMPLETED` and `ACTION_USER_UNLOCKED` mark the two stages; `UserManager.isUserUnlocked()` reports the state.

### Key without the flag while the screen is locked

The reference text above says only keys with the flag are tied to the unlocked state. Nothing in the pages read states in one sentence that an unflagged Keystore key is usable while the screen is locked after first unlock. That follows from the flag being the thing that adds the restriction, and from the Direct Boot doc's CE availability, but it is an **inference, unconfirmed by an explicit statement**. Before first unlock, a key that guards CE-stored data is unusable because the data is not readable; whether the key itself works in Direct Boot is **unconfirmed** and does not matter if the ciphertext sits in CE storage.

### Mapping the core's two classes (proposal for the plan, built on the facts above)

| `Accessibility` | Keystore configuration | Ciphertext location | Notes |
|---|---|---|---|
| `AfterFirstUnlock` | AES-256-GCM key generated with no `setUnlockedDeviceRequired`, no user-authentication requirement | file under `Context.getFilesDir()` (CE) | readable while locked, once the device was unlocked since boot; matches the in-process push unseal need |
| `WhenUnlocked` | AES-256-GCM key generated with `setUnlockedDeviceRequired(true)` | file under `getFilesDir()` (CE) | on API 28-30 the flag does not block symmetric encryption (writes succeed while locked) but does block decryption; on API 31-34 apply the four caveats above; reliable only from API 35 |

Because the reliability of the flag is weak below API 35, a plan that depends on `WhenUnlocked` being enforced by the Keystore on API 28-34 cannot rely on it; the app's own lock state is the other half. That is a design choice for the plan, not a documented fact.

## 4. Blob storage

### `androidx.security:security-crypto`

- Release notes: **version 1.1.0-alpha07 (April 9, 2025)** and **1.1.0-beta01 (June 4, 2025)** both say "Deprecated all APIs in favour of existing platform APIs and direct use of Android Keystore." **Stable 1.1.0 was released July 30, 2025.** Source: https://developer.android.com/jetpack/androidx/releases/security (section Security-Crypto). `EncryptedSharedPreferences`, `EncryptedFile`, and `MasterKey`/`MasterKeys` are in that library.
- Recommendation: platform APIs and the Android Keystore directly. The release note names no replacement library. Any further Google guidance on a migration path is **unconfirmed** in the pages read.
- The plain shape (no library): generate an AES-256-GCM key in `AndroidKeyStore` (`KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")` with `BLOCK_MODE_GCM`, `ENCRYPTION_PADDING_NONE`), encrypt with `Cipher`, write IV plus ciphertext to a file in app-private storage. `BLOCK_MODE_GCM` and `KEY_ALGORITHM_AES` are API 23. https://developer.android.com/reference/android/security/keystore/KeyProperties. The class docs include an AES-GCM example (key2). Source: KeyGenParameterSpec page.

### Excluding files from Auto Backup and device transfer

Source: https://developer.android.com/identity/data/autobackup

- By default Auto Backup (API 23+) includes shared preferences, `getFilesDir()`, `getDatabasePath()`, and `getExternalFilesDir()`. It excludes `getCacheDir()`, `getCodeCacheDir()`, and `getNoBackupFilesDir()`, and those exclusions cannot be overridden by an `<include>`.
- **Simplest exclusion**: write the ciphertext under `Context.getNoBackupFilesDir()` (API 21). It is excluded from backup by the rules above. Whether `getNoBackupFilesDir()` also stays out of a device-to-device transfer is **unconfirmed**: the page excludes it from "backup operations" and, in the `<device-transfer>` discussion, says a missing section means everything "except for `no-backup` and `cache` directories" transfers, which does indicate exclusion from transfers as well.
- `android:allowBackup="false"` on `<application>` disables backup (default `true`). **For apps targeting API 31+, on devices from some manufacturers, `allowBackup="false"` disables cloud backup but not device-to-device transfer.**
- **API 30 and lower (also used on API 31+ if targetSdk is 30 or lower)**: `android:fullBackupContent="@xml/backup_rules"` on `<application>`, and in `res/xml/backup_rules.xml`:
  ```xml
  <full-backup-content>
    <exclude domain="file" path="keystore-blobs/"/>
  </full-backup-content>
  ```
  Domains: `file`, `database`, `sharedpref`, `external`, `root`, and their `device_*` forms. `path` supports no wildcards and no `..`; a directory path covers its subdirectories.
- **API 31+ targets**: `android:dataExtractionRules="@xml/data_extraction_rules"` on `<application>` and:
  ```xml
  <data-extraction-rules>
    <cloud-backup>
      <exclude domain="file" path="keystore-blobs/"/>
    </cloud-backup>
    <device-transfer>
      <exclude domain="file" path="keystore-blobs/"/>
    </device-transfer>
  </data-extraction-rules>
  ```
  (The doc's own sample writes `android:dataExtractionRules="backup_rules.xml"`; the usual resource form is `@xml/...`.) Both attributes are needed for an app that supports both ranges. If an `<include>` exists, only included paths are backed up; `<exclude>` wins when both match. A mode with no rules (for example no `<device-transfer>`) is fully enabled except no-backup and cache directories. `<cross-platform-transfer platform="ios">` exists from Android 16 QPR2 (API 36.1); a missing section there is a mode with no rules, so confirm its default before shipping on that release. **Unconfirmed**.
- Does Auto Backup carry Keystore keys themselves? The page does not say. **Unconfirmed**; AOSP documents keys as non-exportable (https://developer.android.com/privacy-and-security/keystore: "key material remaining non-exportable"). A restored ciphertext file with no key is the failure mode the exclusion prevents.
- Google's own tip on that page: for user credentials and tokens, use Block Store rather than shared preferences or a file; not a fit for device-bound keys.

## 5. Alias naming

- `KeyGenParameterSpec.Builder(String keystoreAlias, int purposes)`: "alias of the entry in which the generated key will appear in Android KeyStore. Must not be empty. This value cannot be `null`." API 23. Source: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder
- Keystore domain model: apps identify keys by a string alias that maps to the `APP` domain; the caller's UID is included, so aliases do not collide across apps. https://source.android.com/docs/security/features/keystore
- Maximum length, permitted character set (for example `:`), and case sensitivity: **unconfirmed**. The reference pages state none, and the AOSP `keystore2/src/utils.rs` shows no alias validation (alias length appears only in a binder-size estimate). Other keystore2 files were not read. https://android.googlesource.com/platform/system/security/+/refs/heads/main/keystore2/src/utils.rs
- Consequence for freezing aliases derived from `did:plc:...`: a `did:plc` is 32 characters (`did:plc:` + 24), well short of any plausible limit, but the colon and case behaviour are unverified. The plan should either test on a device and on the lowest-API emulator image, or map each DID to a fixed-alphabet alias (for example `ezpds-device-key-` plus the 24-character base32 identifier) before freezing.
