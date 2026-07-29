# Changelog

All notable user-visible changes to ezpds are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes are collected in `changelog.d/` during development and inserted here when
`just set-version` prepares a release. There is intentionally no `Unreleased` section.

## [0.10.1] - 2026-07-29

### Fixed

- The notification relay can now actually reach Apple. Its HTTP client was built without HTTP/2 support — a default feature lost when the workspace opted out of defaults — and Apple's push service speaks nothing else, so every real delivery failed in transport with a connection error while the relay's own tests (whose stand-in APNs speaks HTTP/1.1) stayed green. Pushes sealed for your device now arrive.


## [0.10.0] - 2026-07-29

### Added

- Obsign can now receive the encrypted notifications your Custos instance sends. On first launch it asks permission, generates a notification key that never leaves the device, and tells each of your identities' servers where to reach it — so a notification can be sealed to your phone specifically, and read nowhere else. What that protects is the notification's *content*: neither the relay in the middle nor Apple can see what one says. It does not hide that a notification happened — your own server is told which device to reach, and Apple necessarily handles delivery — so what is kept from everyone in between is the message, not the fact of it. The key is used for nothing else: it never signs anything, and losing it costs you banners rather than an identity. Obsign also re-checks which signing keys your instance publishes every time it contacts it. That is what keeps the window short if one of those keys is ever compromised — a key your operator revokes stops being trusted by your phone the next time the two talk, without you doing anything. Registration is quiet by design: on a simulator, or for an identity hosted somewhere that runs no relay, Obsign simply carries on with notifications switched off rather than reporting an error you cannot act on. Both Obsign and Admin Companion now require iOS 17, which is where Apple's encrypted-notification support begins.

- Obsign now reads the encrypted notifications your Custos instance sends. Until now your phone could receive one but not open it, so every notification arrived as a placeholder; a small extension bundled with the app now unseals each one the moment it arrives — on the lock screen, without waking the app, and without the relay in the middle or Apple ever seeing the text. What you read is what your server wrote.
  
  When a notification *cannot* be opened, Obsign says so plainly rather than showing you something that looks genuine. iOS does not let an app silently discard a notification, so anything that fails to unseal — a relay sending noise, a message signed with a key your phone has not seen, or one arriving before you have unlocked your phone since restarting it — appears as an explicit "Couldn't verify a notification from your Custos instance". It is never dressed up as real content, which is what stops whoever carries your notifications from being able to put words in your server's mouth.
  
  Because that notice on its own cannot tell you *which* of those happened, Settings gains a Notifications section that can. It counts the recent failures and names the likely cause in plain language — and, where there is something to do, says what: a key mismatch is usually fixed by opening one of your identities, since Obsign refreshes the keys on every contact with your server, while a run of unrecognisable notifications points at the relay rather than at anything of yours being at risk. Once you have dealt with it, you can clear the record so the next real report is not lost in an old one.

- The notification relay can now be deployed: it ships its own container image and Railway config, so you can run one yourself instead of pointing your instance at ours. A relay serves no web address at all — it is reached over an encrypted peer connection by its node id — so there is nothing to expose to the internet and nothing to put behind a domain. Its database is disposable, since everything in it is rebuilt when instances re-enroll, but its node key is the relay's address and can be supplied as a deployment secret so it survives the machine being rebuilt. A new operator runbook walks the whole path: getting an Apple push key, starting the relay, handing out single-use enrollment codes to the instances you serve (or turning that ceremony off when you are the only tenant), checking a notification arrives end to end, and reading the outcome the relay reports when one does not. It is also honest about the boundary: your own relay can only push to apps belonging to your own Apple developer team, so the official Obsign apps still need the official relay — which is precisely why that relay is built to see nothing.

- Signing in to an app can now come to you. When a sign-in page knows which account it is for, your Custos instance sends a sealed push to Obsign; tapping it opens the approval screen directly on that request — nothing to look up, no sign-in code to copy over, no QR to scan. The push travels the same encrypted path as every Obsign notification: what the relay and Apple carry is a sealed payload and an opaque delivery handle, so who the login is for, which app asked, and where it came from stay hidden from everyone between your server and your phone. (Like any courier, the relay can see that *something* was delivered — it just can't read what.) And Obsign only acts on a tapped notification it could cryptographically verify came from your instance.
  
  Because a prompt that finds *you* is exactly where tap-fatigue attacks live, approval on this channel demands one extra proof: the sign-in page shows a two-digit number, and Obsign requires you to type it before Face ID. If someone else started that login, you are not looking at their screen, so there is nothing you can type — a blind "Approve" is impossible, and your server enforces the number, not just the app. A wrong number never kills the request; denying it (which needs no number) does, and is exactly the right answer to a prompt you did not start.
  
  If the push never arrives — notifications off, relay down, a new phone — nothing is lost: the same sign-in page still shows the typed code and the QR, and either one opens the same request in Obsign, where the number is still asked for and still on the page in front of you.

- OAuth endpoints now emit structured operator logs for every token/revocation rejection (error code + description), every authorization error redirect, and each completed authorization-code exchange (client + account) — no token material — so failed third-party logins can be diagnosed from server logs instead of request counters.


## [0.9.2] - 2026-07-27

### Fixed

- OAuth `include:` permission-set expansion now skips individual entries that cannot be converted to a valid scope (matching the reference implementation) instead of rejecting the whole set — fixes logins from apps requesting Bluesky's `app.bsky.authCreatePosts` set, whose `inheritAud` video-upload entry is unrenderable without an `?aud=` parameter.


## [0.9.1] - 2026-07-27

### Fixed

- OAuth logins from browser-based atproto apps (which request `response_mode=fragment`, the official client library's default) now complete: the authorization response is delivered in the URL fragment when requested instead of always in the query string, and the server metadata advertises `response_modes_supported`.

- Third-party atproto apps that send a direct (non-PAR) authorization request no longer fail with "client_id is not registered": the authorize endpoint now resolves an unknown URL-shaped client's metadata document live, exactly as the PAR endpoint already did, and enforces the same private-use-scheme redirect rule.


## [0.9.0] - 2026-07-27

### Added

- Groundwork for encrypted push notifications: Custos gained the sealing layer that will let a self-hosted instance send notifications through a relay it does not have to trust. Payloads are sealed to a per-device key with HPKE (RFC 9180, DHKEM-P256 + AES-256-GCM, authenticated mode), so a relay operator and Apple both see only opaque bytes and neither can forge a notification your device will accept. Payloads are also padded up to one of three fixed sizes: that does not hide length outright, but it reduces what length can reveal from a per-notification fingerprint to which of three buckets a notification fell into. Nothing is enabled by this change on its own; the relay, the registration flow, and the on-device decryption arrive in the phases that follow.

- New `notify-relay` service: a blind courier that self-hosted Custos instances enroll with over iroh (`ezpds/notify/0`) to obtain opaque push handles for their devices. Enrollment is closed by default and gated on operator-minted single-use codes (`notify-relay mint-code --ttl 60m`); `open_enrollment = true` admits any instance on a self-run relay. Handles are resolvable only by the instance that registered them, and per-instance rate limits apply. Sending pushes to Apple arrives in a following change.

- The notification relay can now actually deliver. It signs in to Apple with the operator's own push key, wraps each instance's sealed payload in the envelope Apple requires, and forwards it — carrying a fixed, content-free "Encrypted notification" placeholder that the real notification replaces once your device decrypts it. Everything that identifies the notification stays sealed: the relay copies the ciphertext through without reading it, and the only secret it holds is its own Apple credential. Two things travel back. When Apple reports that a device token is dead, the instance is told so it can drop that registration instead of pushing into the void forever. And every notification is checked against Apple's 4 KB limit before it is sent, so a payload that would have been rejected on the relay's credentials is reported to the sender as too large instead. Pushes are budgeted twice over — per instance, and per device at 60 an hour — so a bug in one instance cannot flood a phone, and one device's traffic cannot starve another's. A relay with no Apple key configured still enrolls instances and hands out push handles; it just says plainly that it cannot deliver yet. Nothing sends notifications through this yet — the Custos side that triggers them arrives next.

- Custos can now send push notifications, and the first one is live: when an agent asks to act on your behalf, your phone tells you instead of the request waiting silently until you next open the app. Point your instance at a relay with `[notifications] relay` and the feature switches on; leave it unset and none of it exists — no keys are generated, no registration endpoints answer, nothing is sent. Notifications are sealed on your instance to one specific device and opened only on that device, so neither the relay nor Apple ever sees what a notification says. They also prove where they came from: your instance signs each one with a key your devices have pinned, so a relay that turned hostile could drop or repeat notifications but could never write one that looks genuine. Length is padded to fixed sizes, because how long a notification is would otherwise reveal what kind it is; anything too large to pad is dropped rather than sent in a way that leaks. Devices register over the app's normal authenticated channel and can unregister at any time, and when Apple reports a device is gone, its registration is removed at once. Deleting an account or revoking an operator device also tells the relay to forget the devices involved. Operators rotate the signing keys with `pds notification-keys` — publish a new key alongside the old, retire the old once devices have re-pinned, or revoke it outright if it is compromised.

- A recovery key for identities hosted anywhere. Until now, the wallet's Shamir recovery seed came bundled with Custos escrow, so an identity you imported from bsky.social or any other spec-compliant PDS got a Secure-Enclave root key, monitoring, and backups — but no way back in if you lost the device. The new "Add a recovery key" flow on the identity screen is the same ceremony minus the escrow: the wallet generates the seed, splits it 2-of-3, and publishes a device-key-signed operation that inserts the derived recovery key straight after your device key. Nothing is removed, and no share — nor any part of the recovery key — is ever sent to your PDS; the only thing the wallet asks it is the public question of whether it offers recovery escrow at all. Share 1 goes to your Keychain to sync across your Apple devices; Shares 2 and 3 are both yours to save, and any two of the three restore the identity through the existing recovery ceremony. The flow is offered only where it is the right answer: on a server that advertises recovery escrow, the escrow-backed upgrade is offered instead, and on a server that could not be reached nothing is offered at all rather than guessing. If you later move to a host that does hold shares, the wallet offers escrow once — as an option, not a reminder.

- App passwords, handle changes, identity removal, and media restore now work on any server. Four features that are pure standard AT Protocol have been dark for identities hosted anywhere but Custos, for a single reason: each needs a full sign-in, and the only sign-in the wallet knew how to perform was the passwordless one that a Custos server offers. On bsky.social or the reference PDS there was no such option, so the buttons were there and the session behind them was not. The wallet now asks the identity's server which sign-in it supports and offers the right one: a Face ID unlock where the server accepts a device-key signature, and a prompt for your account password where it does not — with emailed two-factor codes handled, and the password sent once, to your own server, and never stored. From then on the session behaves identically either way: it refreshes on its own, and it is discarded if your identity moves to a different host. A server the wallet could not reach is never assumed to lack passwordless sign-in — it keeps offering the unlock it already used, because a network hiccup is not a fact about your server.

- Rescue and migration can now finish on any spec-compliant PDS, not just a Custos one. The final cutover step used to mint a passwordless sovereign session unconditionally, which only Custos serves — so a move to the reference PDS or bsky.social would fail at the last step, after the identity operation had already landed. Obsign now asks the destination what it supports and, where passwordless sessions are not on offer, durably keeps the session that destination already issued, in the same strict order (activate, store the credential, then stand the old server down). The destination picker also states plainly how you will sign in after the move.

- The wallet's background identity monitor now has a face you can look at. The home screen's status strip says when the public record was last checked and opens a new **Protection** surface: every identity's status in one list — reordered so anything under attack leads — plus the monitor's own history, showing when each check ran, what it covered, and when each identity was last verified. The check runs every 15 minutes as before; you can now see that it is happening, and run one yourself.

- The operator console now renders the blob-integrity readouts the server already reports: the Status screen's Storage panel names unowned blobs — stored bytes no account claims, an alarm that fires while blob collection is still running on schedule — account detail shows an account's uploaded blob figures beside its owned ones, and did:web accounts state in the accounts list whether this server serves their DID document. A server too old to report any of these reads as "not reported" rather than as zero.

- An account with no password can now be permanently removed: `com.atproto.server.deleteAccount` accepts a device-key-signed proof from one of the identity's current rotation keys in place of the password, alongside the emailed confirmation code as before. Custos advertises this as the `walletAccountDelete` capability, and Obsign drops the password field from the removal screen on a server that offers it.

- Operators can now let accounts be created without a password at all. With `[accounts] password_optional = true` (`EZPDS_ACCOUNTS_PASSWORD_OPTIONAL`) the server advertises a new `optionalPassword` capability, and a client may omit the password field when creating an account; the account then authenticates through its device key — wallet-confirmed OAuth consent and sovereign sessions — plus app passwords for standard AT Protocol clients. Obsign reads that capability and skips its password screen entirely against such a host, while continuing to ask for one everywhere else, so an older deployment is unaffected. Off by default: a passwordless account depends on device-key custody an operator cannot verify for the account holder. An empty password is rejected either way — an empty string is what an uninitialised form field sends, so omitting the field is the only way to ask for a passwordless account.

- Operators can now see how much push-notification work is waiting. The notification queue holds jobs in memory and never blocks a request, which is the right trade when a relay is slow — but it also meant that a relay being down for a maintenance window, or pointed at the wrong node id, showed up only as a rising count of warnings in the log. There is now a `notify_queue_depth` metric alongside the others at `/metrics`, and a `notifyQueueDepth` figure in the operator health readout that the console can show. It counts the jobs still outstanding, including the one currently being attempted, so a single push stuck against an unreachable relay is visible rather than reading as an empty queue. Expect zero; a number that climbs and stays there is a relay outage becoming a memory cost. Instances with no relay configured report nothing at all rather than a misleading zero.


### Changed

- Each identity in the wallet now opens as an instrument panel rather than a list of ten equal buttons: a status panel states whether the identity is secure, needs attention, or is under attack — with a security checkup you can expand — and the actions sit beneath it, sorted by how often you need them. Signing in to apps, Bluesky, and your agents are one tap away; "Move or rebuild" is its own visible door; and handle, backups, and the DID document live behind "Manage identity", with the protocol-level tools one further step down behind a screen that explains what they do. Every operation keeps the confirmations it already had.

- Obsign now opens straight onto the alarm when one of your identities is being changed without your authorization. Previously the alarm waited behind the home screen's protection strip, so the most time-critical thing the app can tell you was also the one thing it made you navigate to. Now, on launch or when you return to the app, a single affected identity opens on its own alarm surface and several open the Protection list, most urgent first. It is always an offer, never a lock-in: "Not now" returns you to a home screen that still shows the alarm as a banner and flags the affected identities, and once you have dismissed an alarm the app will not keep pulling you back to it. Interrupted key handling still comes first — a half-finished recovery, removal, or move resumes ahead of re-showing an alarm you have already been told about.

- Adding an identity now starts with one plain question — "Add an identity — what's your situation?" — instead of a row of doors named after the machinery behind them ("create", "import", "recover"). Pick the sentence that describes you: starting fresh, you already have an account somewhere, you lost access to your wallet, or your server is gone. Obsign works out which ceremony that means and takes you into it; the ceremonies themselves are unchanged. "My server is gone" is answered honestly rather than made into a fifth journey of its own: if the identity is already in this wallet, Obsign points you at that identity's "Move or rebuild" door, and if the wallet was lost too, it says so and takes you through recovering the wallet first — because rebuilding an account elsewhere is signed by the identity's own key, which the wallet has to hold before it can rebuild anything.

- The canonical base64url check that keeps a signed device-key proof from being re-spelled into a fresh nonce now lives in one shared module instead of being copied into each of the three routes that verify such proofs (passwordless session issuance, wallet-confirmed OAuth consent, and passwordless account deletion), so the three can no longer drift apart. Behaviour is unchanged.

- The iOS pull-request gate now runs clippy for both mobile apps, so lint findings in crates the Linux gate cannot compile no longer accumulate unchecked.


### Fixed

- A newly created identity could finish onboarding, show "You're all set", and then not appear on the home screen. The last step of the create flow records the identity in the wallet's own list — the home screen reads from that list alone — and if that one write failed, the flow reported success anyway, nothing retried it, and the state survived force-quitting the app. The identity, its master key, and its recovery shares were never at risk, but the only way to make it visible again was to run the recovery ceremony on an identity that had not actually been lost. That step now retries, and if it still fails the app says so plainly and offers to try again instead of claiming success. Obsign also re-checks this on every launch and re-registers an identity whose create flow left it out — so an install already stuck in this state repairs itself on the next open. Identities you removed from a device on purpose are remembered as removed and are never brought back.

- The wallet no longer claims custody of a rotation key it cannot sign with. Your identity's key lives in this device's Secure Enclave, and an encrypted device backup can restore the two small records that *name* that key but never the key itself — so a restored or replaced iPhone used to show a confident "Root key" badge while every action that needed a signature (changing your handle, migrating, repairing the hosting endpoint, removing the identity) failed with an error naming the symptom instead of the cause. The wallet now asks the enclave whether the key is really there before reporting it, and when it is not, says so plainly: the identity card reads "Can't sign", and both the card and the identity screen explain that the identity itself is intact — only this device's control of it is gone — and offer the recovery ceremony, which issues a fresh key on this device and installs it as the identity's top rotation key. The check is a lookup rather than a signature, so it adds no Face ID prompt. It deliberately does not quietly issue a replacement key instead: a new key is not in the identity's rotation list, so doing that would have replaced one false claim with another.

- The identity screen's "Sign in to an app" entry (wallet-confirmed OAuth consent — QR scan or typed code) now appears for did:web identities too. The server-side authority lookup became method-agnostic when did:web sovereign sessions shipped, but the wallet still offered the entry only for did:plc, leaving a passwordless did:web account with no way to reach the consent approval it was newly entitled to.

- Creating an identity in Obsign no longer ends by opening a sign-in page over the app. Account creation used to finish by handing off to the server's web sign-in, which a passwordless account could not get through: the page offers a password the account does not have, and its alternative is to "open Obsign and approve" — but Obsign was already the app hosting that page, and closing it cancelled the sign-in. Signing up therefore could not complete at all on a passwordless account. The hand-off is gone: creation now goes straight from "You're all set" to your identities. Nothing is lost by removing it — your account is already active when its identity is minted, and Obsign signs in to it with the device key it just created, asking for Face ID the first time something actually needs the account. Accounts created with a password are unaffected, and signing in to other apps — on this device or another — is unchanged.

- Approving a third-party app's sign-in from Obsign failed with "your server rejected the approval — the signature could not be verified against your identity's current keys" whenever the app passed along the handle you had typed. Custos compared that hint to your DID as plain text, so `alice.example.com` never matched `did:plc:…`, and the approval was refused two steps before your signature was ever examined — the message blamed your keys for something they had not done. Nothing was ever wrong with Obsign's signature or with any account's keys. Custos now binds a handle-shaped hint to the account it actually names, requiring both that the account claims the handle in its DID document and that the handle resolves back to that DID, so neither half alone lets one account approve a request named for another. Handles are matched without regard to case, as the AT Protocol intends. Typing your DID instead of your handle was the workaround and still works — and remains the way through if handle resolution for your domain is down.

- The wallet no longer asks the public did:plc directory about identities that were never in it. An identity held at your own domain (a did:web) is anchored by control of that domain, not by a record in the directory — but the background watch was checking every identity the same way, so for a did:web it made a request that could only fail, every fifteen minutes and again each time you opened the app or the identity. The failure was then reported as "we could not reach the public record", which was not true: there was no record to reach. The watch now covers only the identities that have one, which removes the repeated request on mobile data and leaves the did:web identity screen saying what is actually the case — that it is held at your domain and nothing is out of place.

- Text on buttons throughout the wallet — identity cards, navigation rows, status strips — was rendering in Arial instead of the app's own typeface, because browsers force their default font onto controls unless told otherwise. Every button now uses the same type as the rest of the app.


### Security

- Obsign's Keychain items now live in a stable access group that does not track the iOS bundle
  identifier, with the previous group still declared so anything written before this release stays
  readable. Until now the bundle identifier silently doubled as both the Keychain access group and
  the iCloud container id, so renaming it would have made every device key, recovery share, session,
  and backup unreachable with no error shown. The iCloud container id is now frozen permanently, and
  a CI gate refuses a bundle-identifier change that arrives without the migration (ADR-0030).

- A deletion proof is single-use (its nonce is spent before the confirmation code is checked, so a captured envelope cannot be replayed against a token obtained later), is bound to the account it names, and is verified against the identity's authoritative current rotation set read live from plc.directory rather than any cached document. Unknown accounts, wrong passwords, and bad proofs remain one indistinguishable response, and no credential failure consumes the emailed code.


## [0.8.5] - 2026-07-25

### Added

- The operator console's Status screen now surfaces sweep failures alongside staleness. Each background-sweep row reports the relay's `errors` count as a named `failed <n>` segment, so a sweep that ran but skipped part of its work — for blob GC, an account whose reconcile failed and whose blobs go uncollected until fixed — no longer reads as all-clear just because its timestamp is fresh. The two faults are named independently (`failed <n>` versus `stale`), since one means a single subject is broken and the other means the sweep is not completing at all. A relay predating the field reports no failures rather than failing the readout.

- Blob storage readouts can now tell lost ownership rows from reclaimed blobs. Every operator-reachable blob figure resolved through the per-account ownership table, so an account whose ownership rows vanished reported exactly the same zeroes as one whose blobs were collected — diagnosing the difference meant opening a SQLite shell on the running server. `GET /v1/accounts/:id/storage` now reports `uploadedBlobCount`/`uploadedBlobBytes` beside the ownership figures, counting the physical blob rows that record the account as uploader, and `GET /v1/admin/health` reports `blobUnownedCount`/`blobUnownedBytes` — stored blob rows that no account claims at all. Because garbage collection removes a physical row together with the file it points at, a surviving row means the blob was never reclaimed, which is the distinction the ownership figures alone cannot draw; confirming the files themselves are present and intact remains the blob-integrity scrub's job, reported separately on the health endpoint. Content-addressed blobs are shared between accounts, so a small per-account gap in either direction is normal. `GET /v1/admin/accounts` also now reports `didWebHosting` per account, stating whether Custos serves that account's did:web document — a flag that gates a serve path returning a plain 404 when off, indistinguishable from an unknown host, so an operator previously had no way to tell "not hosted" from "broken" without a database shell.

- Self-hosted `did:web` accounts can now use both passwordless auth paths. `POST /v1/sessions/sovereign` and `POST /oauth/authorize/approve` were hard-gated to `did:plc`, so a `did:web` account carrying no password — which every wallet-migrated account does, since the migration `createAccount` request has no password field and the server stores none by design — had no way to authenticate at all. That was more than a sign-in inconvenience: the wallet's own iCloud media restore runs through the same full-access session seam, so once the refresh chain from migration lapsed, the recovery path lapsed with it. Both routes now resolve the account's signing authority from its DID method's authoritative source: the current PLC rotation set for `did:plc`, and the published `#device` verification method for `did:web`, fetched live over HTTPS rather than from the local document cache. Signature verification was already method-agnostic, so P-256 and secp256k1 device keys work exactly as before, and every failure still collapses to the same opaque rejection.


### Security

- Passwordless authentication for a `did:web` account is restricted to identities Custos does not host the DID document for, enforced on the server. `POST /v1/did-web/document` lets an account rewrite its served document under ordinary session authentication, so for a Custos-hosted `did:web` a stolen session could install an attacker's `#device` key and mint sovereign sessions from it — a privilege escalation requiring no key compromise. Because that route already refuses unless managed hosting is enabled, "hosting is off" is exactly the condition "no session-authenticated rewrite is possible", with no gap in either direction. `did:plc` has no equivalent exposure: rewriting a rotation set requires an existing rotation key, and plc.directory is external to this server. The authority set for a `did:web` is exactly the `{did}#device` key and nothing else — notably not `#atproto`, whose private key Custos holds — and a document publishing more than one `#device` entry is treated as malformed and refused rather than resolved by document order. Obsign accordingly no longer offers the two Custos-hosted `did:web` options; the managed-hosting routes remain available for accounts that already opted in and for other clients.


## [0.8.4] - 2026-07-25

### Added

- A blob GC pass that skipped accounts now reports it: the new `blob_gc_errors_total` metric and an `errors` field on each sweep in `GET /v1/admin/health` distinguish a pass that ran but left work undone from one that is not completing at all (which still shows as a stale timestamp).


### Fixed

- Blob garbage collection no longer deletes the blobs of an account whose repo walk failed. Previously, when reconciling an account errored, that account's blobs were never pinned permanent and the sweep collected them once their upload grace expired — destroying the ownership row, the stored blob, and the file, and then propagating those deletions to the mirror bucket. The sweep now excludes any account that failed to reconcile in the same pass, so blobs whose references could not be computed are never collected; such an account retains its blobs until the underlying fault is fixed.

- Listing the records of a collection no longer fails, or risks returning another collection's records, when the repository holds record keys shorter than the requested collection name. The underlying repository library's prefix scan yields such keys even though they fall outside the requested range; every key is now re-checked against the collection prefix and the scan stops as soon as it passes the end of that range, which also makes listing a small collection cheaper. Because the leak previously surfaced as an error, listing a collection could fail permanently for an affected account and, in turn, block blob reconciliation for it.


## [0.8.3] - 2026-07-25

### Fixed

- Labels are visible again on posts and accounts for Custos-hosted identities. When a client asked the AppView for content, Custos dropped the `atproto-accept-labelers` header naming the labelers that account subscribes to — and the AppView applies only the labelers it is told about, falling back to its own default moderation service alone. Every label from every subscribed labeler was therefore stripped before it reached the client, with no way to tell the difference between "this content carries no labels" and "the labelers were never asked". Custos now forwards that header (along with `accept-language` and `x-bsky-topics`) upstream, and passes the AppView's `atproto-content-labelers`, `atproto-repo-rev`, and `retry-after` back to the client — on the streaming proxy path and on every fallback rung of the read-after-write path alike, matching the reference PDS.

- Backup Share 1 can now sync to your other Apple devices. Every wallet Keychain write omitted the iCloud sync attribute, so the share the "lost phone, iCloud intact" recovery path depends on never left the device that created it — recovery on a new device silently needed the escrowed Share 2 *plus* the Share 3 word phrase. Share 1 is now written to the iCloud-synchronizable Keychain, read from there first, and an existing share is copied across on the next app launch. Obsign can only confirm it wrote the share with the sync attribute set; whether iCloud delivers it is Apple's to do, and with iCloud Keychain switched off it stays put. The repair runs on-device, so it cannot help an identity whose only device is already lost — the backup and recovery screens now say which shares are actually in hand rather than assuming Share 1 will be waiting.

- `just set-version` now regenerates the version-stamped operator reference pages, so a release PR no longer fails `just docs-check` on its first CI run.


## [0.8.2] - 2026-07-24

### Added

- An existing did:web identity can now be brought into the wallet: the "bring an existing did:web" path resolves the domain's live DID document, registers the identity, and opens the migration flow — previously it failed with "DID is not managed by this wallet."

- The wallet's background backup task now refreshes your repo (posts) snapshot as well as your media mirror, so an opted-in identity's posts stay backed up to iCloud without opening the app — no longer only on the next launch. The two backups opt in independently: you can enable one mirror and not the other, and each pass runs off-foreground in the same scheduled wake-up.

- Custos now tells clients what it can do: `com.atproto.server.describeServer` carries a `custos` object with the running version and the capabilities that deployment actually offers (identity creation, recovery escrow, passwordless sessions, agents, wallet-confirmed consent, did:web hosting), derived from the live configuration rather than assumed. Obsign reads and caches it per host, so features are offered based on what a server supports instead of being attempted and failing — and a server that sends nothing, like the reference PDS or bsky.social, is handled as having no Custos capabilities rather than as an error. `GET /xrpc/_health` now identifies itself as `custos vX.Y.Z` instead of a bare version number, matching what third-party AT Protocol diagnostic tooling reads. Operators: see the new [Capabilities](https://docs.obsign.org/operator/capabilities/) page for what each capability means and how it is controlled.

- Custos can now run a public interest-signup waitlist (the `waitlist` capability, `[waitlist] enabled` / `EZPDS_WAITLIST_ENABLED`, off by default): an unauthenticated, CORS-open, rate-limited `POST /waitlist` accepts an email plus an optional atproto handle for a marketing page's signup form — idempotent per email, handle never resolved — and `GET /v1/admin/waitlist` reads the list back for the operator; the Obsign marketing site now carries the TestFlight signup form posting to it.


### Changed

- The wallet's welcome screen now says what its buttons actually do: "Create an identity" and "Import an identity". The second is a correction rather than a rewording — that button has always started the flow that puts your device's key in charge of an identity hosted somewhere else, which is the front door for anyone arriving from bsky.social or a self-hosted PDS; it was labelled "Move an identity to another PDS", which is a different feature and lives on the identity's own screen. Creating an identity also now checks up front whether the server you configured can actually do it: creation requires your device to author the identity's first record and hold its master key from that moment, which a standard ATProtocol server cannot accept, so a server that does not advertise the Custos create ceremony gets an honest explanation on the server screen — before you fill in a claim code, an email and a handle — with import one tap away on the server you already chose. A server the wallet simply could not reach is treated as a question it failed to ask, not as an answer: that shows a retryable error rather than telling you your server cannot create identities.


### Fixed

- Creating or migrating a did:web identity no longer fails verification of the published did.json: the wallet composed the document's `#device` key in a bare encoding the server could never match against the submitted device key (the server compares the multicodec-prefixed did:key form), so every live did:web ceremony was rejected with a generic "document does not match" error. Both the creation ceremony and the migration identity leg now publish the same did:key encoding the server verifies.

- Migrating a did:web identity no longer dead-ends at the start screen with "couldn't verify this identity's keys": the migration path detector asked plc.directory for the identity's PLC audit log, which a did:web identity does not have, so detection always failed. A did:web identity now takes the wallet-driven path directly — its identity leg is the domain's did.json edit, which the wallet composes and verifies.

- Migrating a did:web identity to another PDS no longer fails — the wallet now resolves the source DID from the domain's own did.json instead of plc.directory, and the final cutover persists the destination session directly since a did:web account has no PLC rotation keys.

- Resolving a did:web identity's hosting PDS no longer fails with a generic network error — the wallet now recognizes the absolute-form service ids ("did:web:host#atproto_pds") that did:web documents carry, alongside plc.directory's bare "#atproto_pds" form.

- Bluesky direct messages now work for Custos-hosted accounts — the service-auth tokens the server mints for chat-service proxying carry the jti nonce Bluesky's chat service requires for replay protection.

- The wallet now alternates which iCloud backup mirror runs first in each background wake-up, preventing posts or media from being repeatedly delayed when iOS limits background processing time.

- A did:web identity can now be removed from the wallet. The permanent-removal flow was did:plc-only: the entry point was hidden for a did:web, because behind it the removal always tried to publish a PLC tombstone — an operation a did:web has no directory log for, which would have deleted the account and then stranded the identity in a "retry" state that could never succeed. Removal is now method-aware: a did:web is deleted on its PDS and erased from the device with no PLC step, and the wallet says plainly that the last step — taking the DID's `did.json` off the domain — is yours, since it never had control of that domain.


## [0.8.1] - 2026-07-24

### Added

- The wallet can now repair a did:plc identity's hosting endpoint ("Repair hosting endpoint" on the identity screen): when the hosting server changes hostname underneath the account, the DID document still points at the dead host and every app misroutes. The wallet signs the `atproto_pds` repoint with the device key and submits it directly to plc.directory — no session and no contact with the old endpoint, and the new endpoint is probed to prove it actually hosts the account before anything is signed. A sixth strict pre-sign allowlist guarantees nothing but the endpoint string changes.


### Changed

- The Obsign marketing site now lives at the apex (`obsign.org`), completing the `pds.obsign.org` hostname migration: the PDS landing page, marketing Open Graph metadata and rendered cards, analytics domain gate, Bruno production environment, and deploy docs all reference the apex instead of the retired `about.obsign.org` subdomain. The `about` handle name stays reserved so the retired subdomain can never be claimed as a user handle.


## [0.8.0] - 2026-07-23

### Added

- A wallet-authorized migration whose source PDS can no longer serve the repository now falls back to the user's iCloud repo snapshot: `transfer_repo` imports the locally backed-up CAR instead of failing, provided the mirror holds a snapshot that re-validates against the account's DID. When no valid snapshot exists the original source failure is surfaced unchanged, so a source repo-read fault becomes a non-event for backed-up users — the repo twin of the existing blob-drain mirror fallback.

- The wallet can now rebuild an account on a new PDS entirely from its iCloud backups when the old PDS is gone or uncooperative ("Rebuild from backup" on the identity screen): it enrolls a self-controlled signing key via a device-key-signed PLC operation submitted directly to plc.directory, mints the migration `createAccount` service-auth token offline, imports the backed-up repo snapshot, restores media from the blob mirror, and re-points the DID — with strict guards preserving the wallet's rotation key at every step, and the new account staying inert until final activation.


### Changed

- The Custos mark on the PDS landing page and the Custos marketing page is now the "operator's prompt" glyph (a brass chevron and a filament cursor), matching the Brass Console app icon, replacing the earlier gold disc.


### Fixed

- The wallet's sign-in QR scanner is now visible: the camera preview (a native layer the barcode scanner renders behind the WebView) was staying hidden behind the app's opaque root background, so the scan screen appeared blank. The root and body grounds are now both dropped to transparent while scanning, letting the camera show through.

- Custos now serves its own `did:web` server identity at `/.well-known/did.json`, synthesized from the configured public URL and server DID. Previously the route only served opted-in account documents, so the server's own DID never resolved; it now survives a public-URL migration with no database row involved.


## [0.7.2] - 2026-07-22

### Added

- A periodic blob-integrity scrub sweep now re-hashes every stored blob against its recorded CID and size, and walks the blob directory for both orphan directions — a row whose file has gone missing and a file no row owns — surfacing bitrot, truncation, or a bad restore as an operator alarm (`blob_scrub_*` metrics, `GET /v1/admin/health`) months before a migration would trip over it. When a blob-mirror bucket is configured, a bad or missing file can be auto-healed from its verified-good copy (`[blob_scrub] auto_heal`, on by default).

- The migration blob-drain now degrades per-blob instead of parking the whole migration on a single dead blob: each blob is retried individually, and any that still can't be transferred are collected into a loss manifest the wallet shows you — which media, which post references it, and whether your previous server couldn't serve it or the new one refused it — so you can make an informed choice to continue without them rather than abandoning the run. Verification tolerates the accepted skips, and the progress screen surfaces the specific per-blob failure detail (fetch-from-source vs upload-to-destination) instead of a generic "couldn't transfer one or more blobs."

- Obsign can now keep a user-held backup of an account's media in the wallet's iCloud Drive folder ("Back up media" on the identity screen): an opt-in, incremental mirror of the account's blobs — every fetched file is verified against its content address before it is stored, the mirror size is always shown, and the copy is visible in the Files app. If the hosting server ever loses the originals, "Restore to server" uploads the mirrored files back byte-for-byte, so posts keep pointing at the same media — the one backup layer that survives the server itself failing.

- Brass Console operators can export a redacted, per-relay network-error log from Settings for troubleshooting.

- The user-held media backup now tops itself up in the background: on iOS, an opted-in identity's iCloud mirror is refreshed by a scheduled background task (BGProcessingTask), so media posted days ago no longer stays unprotected until the next time the app is opened. Each run is the same incremental, content-address-verified pass as "Back up now" and degrades per-identity, so one account's failure never stops the others. Settings gains a "Media backup" section to tune it: turn background backups off entirely, restrict them to while charging, or skip them on cellular data.

- If you've backed up your media to iCloud, migrating away from a server that has lost some of your blobs is no longer a loss: when your old server can't serve a piece of media during a migration, the wallet now falls back to your local backup copy, verifies it still matches its content hash, and uploads that copy to your new server. Because media is content-addressed the substitution is exact — nothing in your posts is rewritten — so a backed-up blob your old server dropped shrinks (ideally empties) the migration's loss manifest instead of forcing you to skip it.

- The identity wallet can now back up your posts. Alongside media backup, the Media Backup screen has a "Back up your posts" section that mirrors a full snapshot of your repository — every post, like, follow, and profile edit — into your iCloud Drive. Each snapshot is integrity-checked before it is saved (and the previous good copy is kept if a fetched one fails the check), so you hold a self-custodied, portable copy of the one part of your account that otherwise lives only on your server.

- The marketing site now runs self-hosted, cookieless, IP-anonymized page-view analytics (Umami), disclosed on a new privacy page linked from every footer. No cookies are set, no data leaves the self-hosted instance, and analytics stay scoped to the marketing site — the mobile apps, PDS backend, and any auth surface remain untouched.


### Changed

- The marketing site's copy now matches the shipped custody model: the three-rotation-key ordering (device, recovery, server), backup described as a device-created recovery secret split 2-of-3, the blob bucket mirror alongside Litestream, and identity-method jargon (did:plc) moved off the marketing pages into the docs site's new did:web coverage.

- Marketing FAQ now states the backup cadence precisely: the database streams off-box continuously, while photos replicate on a regular sweep.

- Restoring your iCloud media backup no longer stops at files iOS has offloaded to save space. When a backed-up file isn't on the device, the wallet now asks iCloud to download it, waits for it to arrive (with a time limit), verifies it still matches its content hash, and uploads it — so a restore on a device where most of the mirror has been evicted just works instead of handing you a long list of files to download by hand in the Files app. The restore summary shows how many files it pulled from iCloud first, so a slower restore explains itself. Files that are genuinely gone (no iCloud copy to download) are still reported per-file, and the run continues past them.

- The PDS instance landing page now carries a favicon and shows the Custos brand mark (a gold disc on a cool-slate square) in place of the Obsign seal, matching the marketing site.


### Fixed

- Blob uploads are now crash-durable: bytes are written to a temp file, fsynced, atomically renamed onto the final content-addressed path, and the directory fsynced, before the blob is recorded — closing a gap where a crash or power loss could leave truncated bytes at a valid path even though the database row was already durable.

- `getBlob` now re-hashes each blob's bytes against its CID before serving and returns a 404 (flagging the scrub-sweep alarm counter) on a mismatch, so a corrupted file is never handed to downstream caches; verified responses now carry the `Cache-Control: public, max-age=31536000, immutable` header the blob-handling spec recommends.

- Wallet diagnostics exports now include redacted connection and timeout failures from account creation, OAuth refresh, and authenticated requests.

- The marketing site's analytics embed now restricts itself to the production domain (`about.obsign.org`), so non-production deployments (Railway staging, local previews) no longer report page views into the production analytics dashboard.


## [0.7.1] - 2026-07-19

### Added

- Blob files are now replicated off the deployment volume: configuring an S3-compatible bucket (`EZPDS_BLOB_MIRROR_*`, the same shape as the Litestream variables) enables a periodic mirror sweep that uploads every stored blob after verifying its bytes against its CID, and a restore-on-boot pass that heals any blob file missing from the volume out of the bucket before the server takes traffic — so blobs lost with the volume can be recovered from the mirrored copy instead of being gone for good.

- Custos can now validate records against arbitrary resolved ATProto lexicons, including required and nullable fields, string formats, collection key rules, refs and unions, and array, byte, and blob constraints, with conformance pinned to the upstream record-data interop vectors.


### Changed

- The instance landing page and the OAuth consent and error pages now follow the viewer's system light/dark appearance, matching the identity wallet and the marketing and docs sites.

- Corrected the repo-engine lexicon module's own documentation to reflect that it now validates record data against a resolved lexicon, not only lexicon documents themselves.


### Fixed

- `com.atproto.server.getServiceAuth` now accepts app-password sessions for non-protected methods (and privileged app passwords for the `chat.bsky.*` surface), matching the reference PDS. Previously it required a full-access token and rejected every app-password session, which broke video upload from the Bluesky app (the app authenticates to a self-hosted PDS with an app password). Protected account-management methods remain blocked for all credentials.

- Migrating an account into this PDS now announces the identity change so the network re-resolves it: `activateAccount` force-refreshes the account's cached DID document from the authoritative PLC source and emits an `#identity` firehose frame, and `submitPlcOperation` emits `#identity` after a successful operation. Previously a migrated-in account could keep serving its pre-migration DID document (old PDS endpoint and signing key) in `getSession`/`describeRepo`, causing clients to route to the old PDS and fail service-auth verification ("Token could not be verified") on feeds and video upload.

- OAuth token responses now include the account DID in the `sub` field, as the AT Protocol OAuth profile requires. Third-party atproto clients (such as tangled.org) previously failed to complete sign-in because the token response omitted `sub`.


## [0.7.0] - 2026-07-18

### Added

- Obsign Settings now has an **Export diagnostics** action that shares a redacted log of the session's network errors — operation, server host, HTTP status, and short error code only, never tokens, request/response bodies, or account data — so a network problem can be handed to support without a device or simulator.

- The marketing site (about.obsign.org) now follows the visitor's system light or dark appearance, in the same warm "archive at night" palette as the wallet.

- Shared links to the marketing site now unfurl with branded Open Graph preview cards for both the Obsign and Custos pages.

- Added ATProto lexicon meta-schema and data-model validators (`repo-engine`), gated against the vendored `bluesky-social/atproto-interop-tests` `lexicon/` and `data-model/` acceptance/rejection vectors, so a malformed lexicon document or a non-conformant data-model value is caught against the same fixtures the reference implementation uses.

- Wallet-confirmed OAuth consent (Phase A): a sovereign or migrated account with no password can now sign in to third-party OAuth apps using only its wallet. The consent page shows a typed code and an "Open in Obsign" handoff link; the wallet previews the app, origin, and requested scopes, lets you reduce the granted scope, and approves with a biometric-gated device-key signature verified against your identity's authoritative PLC rotation keys. Approvals are single-use, expire in about five minutes, cannot be replayed onto a different request or a widened scope set, and both approvals and denials are audited.

- Signing in to an OAuth app across devices no longer needs typing: the sign-in page now shows a QR code beside the short code, and the Obsign wallet can scan it with the phone camera to approve the login with your device key. The wallet always re-fetches the app, origin, and requested permissions from your server by the request's id — never from the QR — before the biometric confirmation, and the typed code stays as the fallback when there's no camera.


### Changed

- The documentation sites' screen tours now cover the v0.6.0 screens — share recovery (including the escrow waiting period), app passwords, the "Add a recovery key" upgrade prompt, and the operator console's audit log — and the wallet's browser-harness fake now models the current three-key recovery rotation ([device, recovery, PDS]) so the pictured DID document shows the recovery key.

- Retired the legacy server-side recovery-share path from account creation: `POST /v1/dids` now requires the wallet-generated recovery key and escrow share for a did:plc identity (the server never generates or splits a recovery secret), and did:web identities are created without recovery escrow. The now-dead pending-share columns were dropped from the database.


### Fixed

- Permanent account deletion no longer fails on accounts with email-verification history or sovereign child agents: all account-keyed references are purged or safely unlinked (a schema tripwire test now enforces this), and deleting a parent schedules its children for deletion instead of stranding them.

- The wallet's "Add a recovery key" flow no longer reports every failure as a connection problem: a directory throttle now says to wait a moment, a directory or server problem is named as such, and only real transport failures say "check your connection".

- Exportable network diagnostics now capture connection failures (timeouts, DNS, refused connections, TLS), not only server-error responses — so a "Couldn't reach the server" error (such as when adding a recovery key) no longer produces an empty diagnostics log.

- "My agents" no longer fails with a misleading "check your connection" error when your session has expired. The agent-management surface is now per-identity (opened from an identity's detail screen) and runs through the same refreshable per-identity session as app passwords and change-handle: an expired session self-heals, or prompts a quick biometric unlock, instead of dead-ending on a never-refreshed login token.

- The sovereign-child mint tests no longer race wiremock's shared mock-server pool: the mock plc.directory guard is now held for each test's lifetime, fixing a CI-only flake where a parallel test could reset the pooled server mid-mint and surface as a spurious 502. No runtime behavior changed.

- Adding or recovering a recovery key no longer fails instantly with "Couldn't reach the server": the wallet's authenticated HTTP client sent PUT requests (used to deposit your recovery share) but its internal sender only handled GET and POST, so every deposit failed before any network call and was mislabelled as a connection problem. PUT requests are now sent correctly, and connection failures on the escrow and session-refresh paths are recorded in the exportable diagnostics log.

- The wallet's signing-key rotation, change-handle, and app-password flows no longer report every failure as a connection problem (matching the earlier re-key fix): a directory or server throttle now says to wait a moment, a directory or server problem is named as such, and only real transport failures say "check your connection".


## [0.6.0] - 2026-07-17

### Added

- Custos now watches labelers: configure `[labeler] watched` with any labeler DIDs (with optional per-labeler label watchlists) and a background pass polls each labeler's `com.atproto.label.queryLabels` for the hosted accounts, persisting the labels currently in force (honoring negations and expiry). Flagged accounts sort first on the operator account listing (`GET /v1/admin/accounts`, each row carrying its `flags` and the page a `flaggedTotal`), the health readout reports a `flagged` account count plus the watcher's last pass, and the Brass Console renders the triage view — a flagged-accounts notice on Home and per-row `⚑` flag lines (label value · labeler · date) on the Accounts screen.

- Operators can now see whether the upstream relay is actually crawling and indexing their server: a new admin readout (`GET /v1/admin/relay-status`) compares the PDS's exact sequencer head against what the relay reports for the host via `com.atproto.sync.getHostStatus`, surfacing the relay's lifecycle status, its cursor, the exact gap, and when it last consumed an event — plus a "Request crawl" action (`POST /v1/admin/request-crawl`) that re-invites the relay on demand. The admin-companion (Brass Console) Home screen renders it as a live federation-health block, polling every 15 seconds, with reachable / crawling / behind-by-N / not-seen states shown as text + icon (never color alone).

- Custos now keeps a server-wide admin audit log: every privileged operator action (takedowns, credential sweeps, code mints and revokes, device pairings and revocations, transfer cancels, account repairs, crawl requests) is durably recorded with the credential that signed it — master token or specific paired device — and served at `GET /v1/admin/audit` with filters and pagination. The Brass Console gains an Audit screen to browse it: reverse-chronological, filterable by action, with per-event drill-in by actor or subject.

- A wallet-custodied account can now rotate its repo signing key to a freshly generated one end-to-end: the wallet's new "Rotate signing key" flow stages a fresh key on the PDS (`POST /v1/repo-keys/rotation`), device-key-signs the DID-document key swap, and hands it back for submission (`POST /v1/repo-keys/rotation/complete`) — the PDS submits to plc.directory and cuts its commit signer over atomically under the account's repo write lock, so no commit is ever signed by a key absent from the DID document, and the retired key material is deleted after cutover (ADR-0025).

- Every natively-handled GET endpoint (`com.atproto.sync.*`, `com.atproto.repo.{getRecord,listRecords,describeRepo,listMissingBlobs}`, `com.atproto.identity.resolve*`, `com.atproto.server.getServiceAuth`) now validates its query parameters against the same vendored `com.atproto.*` lexicon schemas request bodies already use: a missing required parameter, a malformed value (DID, handle, NSID, CID, TID, …), or an out-of-range `limit` gets the reference PDS's 400 `InvalidRequest` envelope with byte-identical messages (e.g. `Params must have the property "repo"`, `Params/limit can not be greater than 100`), replacing axum's bare `Query`/`RawQuery` extractors and their plain-text rejections.

- Record writes (`createRecord`, `putRecord`, `applyWrites`) now run full lexicon-schema validation against a vendored set of `app.bsky.*` record types (posts, likes, reposts, follows, blocks, lists, profiles): an invalid record of a known type is rejected by default, the `validate` flag makes validation required (`true`) or skipped (`false`), the record's `$type` must match the write's collection, the record key must satisfy the lexicon's key rule (e.g. a TID for posts), and each write reports `validationStatus` (`valid` / `unknown`) — matching the reference PDS's `assertValidRecord` behavior. Records in collections Custos doesn't recognize stay writable and are reported as `unknown`.

- A parent account can now permanently delete a sovereign child agent it provisioned (`POST /agent/child/delete`): the call revokes the child's capability, deactivates it immediately so relays stop serving its repo, and schedules a permanent purge after a configurable grace window (`accounts.child_deletion_grace_secs`, default 24 hours) — after which the scheduled-deletion reaper removes the child's account, repo, handle, and blobs and emits an `#account status="deleted"` firehose frame, exactly like `deleteAccount`. Ownership is enforced like revoke (an unknown or foreign child DID returns a uniform 404 and agent-derived credentials are refused), the deletion is recorded in a durable tombstone that outlives the purged child, and the wallet-held recovery key and did:plc identity are left untouched for the wallet to retire.

- The Obsign wallet can now mint, list, and revoke Bluesky app passwords for a key-sovereign account. Sovereign accounts are deliberately passwordless, so the official Bluesky app — which signs into a third-party PDS with a password `createSession`, not OAuth — previously had no way to log in; the wallet's new App passwords screen (full-access, biometric-gated) creates a named scoped password to paste into the Bluesky app once, shows it exactly once at mint time, and revokes it per-name at any time.

- The PDS now stores its escrowed recovery share (Share 2 of the 2-of-3 split) in a dedicated `recovery_escrow` table, AES-256-GCM-wrapped under the master key from day one and covered by `pds rewrap-master-key`, with new account-owner endpoints to deposit/replace (`PUT /v1/recovery/escrow-share`) or opt out of (`DELETE /v1/recovery/escrow-share`) escrow, an append-only `recovery_audit_events` trail recording every escrow lifecycle action, and full cleanup on account deletion.

- Custos can now release a wallet's escrowed recovery share (Shamir Share 2) behind an email-OTP gate with a cancellable delay window — the server half of the escrow-assisted recovery ceremony. `POST /v1/recovery/initiate` (public, always-200, no enumeration) emails a single-use 1-hour OTP to the account address; `POST /v1/recovery/release` consumes the OTP to open a release that stays `pending` for a configurable delay (`[recovery] release_delay_secs` / `EZPDS_RECOVERY_RELEASE_DELAY_SECS`, default 24h) before the share becomes collectable by re-polling, with every step audited (`release_requested`/`released`) and notified to the account email; `POST /v1/recovery/release/cancel` (account-owner authed) kills a pending release, composing with `revoke-credentials` for a compromised-mailbox response. A wrong/expired/replayed OTP, an unknown handle, and an escrow-deleted account all fail identically (uniform 401, no oracle); initiate + release share one per-IP rate-limiter instance so alternating them can't double the OTP-guess budget. Operators see in-flight releases at `GET /v1/admin/recovery-releases`.

- The Obsign wallet gained the "Recover from backup shares" onboarding path: any two of the three Shamir shares recover an identity onto a new device. The escrow-assisted path auto-loads Share 1 from iCloud Keychain and releases Share 2 via the server's emailed-code escrow flow (honest pending-delay wait state, cancelled-release handling); the fully sovereign path takes Share 1 plus the Share 3 word phrase and touches only plc.directory until re-escrow. Reconstruction is verified against the DID's authoritative rotation keys before anything signs, corrupted shares and cross-generation shares fail with distinct human-legible errors, and a mandatory — and restart-resumable — rotation epilogue voids the lost device's entire share world (fresh share set, new recovery key, re-escrowed Share 2, rewritten iCloud share, new Share 3 walkthrough).

- Existing accounts created under the old server-generated recovery model can now migrate to the client-generated one: a calm "Add a recovery key" prompt on the wallet home surface (shown only for old-model did:plc identities) runs a per-DID re-key that generates a fresh recovery seed on-device, inserts the derived recovery key into the DID document's `rotationKeys` via a device-key-signed PLC operation, re-escrows the Share 2 envelope with the server — which voids the dead legacy server-held share in the same transaction — rewrites the iCloud-Keychain Share 1, and walks through the new Share 3 word phrase. Every step is additive and resumable: the device key never leaves `rotationKeys[0]`, so an interrupted migration never drops recovery below its pre-migration baseline.


### Changed

- Record writes (`createRecord`, `putRecord`, `applyWrites`) now reject a malformed top-level `createdAt` datetime or any malformed `at://` AT-URI in the record, matching the reference PDS's format checks for records it recognizes.


### Fixed

- Sovereign-session replay nonces are now pruned after their safe retention window instead of accumulating indefinitely.


### Security

- The DID ceremony now generates its recovery material client-side (the ceremony inversion): the wallet mints the recovery seed, derives a recovery rotation key placed in the genesis `rotationKeys` as `[device, recovery, PDS]` (ADR-0027), splits the seed 2-of-3 into versioned share envelopes, and deposits exactly one share — the Share 2 envelope — with the server, which stores it KEK-wrapped in `recovery_escrow` atomically with promotion. The server never sees the seed or the other shares, so no database backup can ever hold reconstruction material. Share 3 is now presented as a 42-word phrase (with a QR machine form), and the wallet stages the share set in a local Keychain slot until backup is confirmed so a mid-ceremony retry reuses the same set. Legacy-shaped requests from pre-inversion wallet builds (and all did:web ceremonies) keep working via the old server-side path for a transition window, flagged in logs for adoption tracking.


## [0.5.2] - 2026-07-16

### Fixed

- The V047 database migration no longer fails on servers with recorded agent activity: the `agent_identities` rebuild now carries `agent_audit_events` through the table swap (preserving audit pagination order) instead of tripping its foreign key.


## [0.5.1] - 2026-07-16

### Added

- Generate API, operator configuration, and mobile IPC reference pages from their source registries, with CI parity checks that reject drift.

- Account owners can mint sovereign child agent identities: the server provisions a reserved repo-signing key while recovery authority stays in the wallet-signed PLC genesis operation.

- Credential-forwarding Streamable-HTTP MCP sidecar (`tools/mcp-sidecar/`, deployable as `mcp.obsign.org`): serves the existing Custos MCP tool surface over HTTP to many callers, authenticates each via OAuth against Custos, and forwards the caller's token per request while holding nothing durable — no on-disk credential cache, nothing that survives a restart (ADR-0024).

- The parent of a sovereign child agent can now read the child's audit trail and revoke it through the `/v1/agents/{registration_id}` management API — previously a child's audit trail was readable by no one (the child's own tokens are agent-derived and refused by the owner guard). Validated end to end by the new hosted-sidecar `create_post` acceptance suite (`just mcp-sidecar-test`).

- Operators can rotate the master encryption key (`EZPDS_SIGNING_KEY_MASTER_KEY`) with the new offline `pds rewrap-master-key` subcommand: every stored secret is re-encrypted from the old key to the new one in a single atomic transaction, and a wrong old key aborts with no writes.


### Changed

- DIDs are now rejected up front unless they are syntactically valid (lowercase method, valid identifier characters, size-bounded), matching the reference PDS on record writes and identity resolution.

- XRPC request bodies are now validated against the vendored `com.atproto.*` lexicon schemas before handling, so malformed input gets the reference PDS's exact 400 `InvalidRequest` responses (previously some malformed bodies got a non-standard 422 or 415, and schema violations the reference rejects were silently accepted).

- Handle, collection, and record-key validation is now checked against upstream AT Protocol conformance vectors.


### Fixed

- A PDS-custodied handle change now submits its PLC directory operation before opening the local handle-swap transaction, so the single-connection database is no longer held across the network call — one custodied handle change can no longer stall other in-flight requests.

- A permanent identity removal that was interrupted after the account was deleted but before the identity was retired on the network (for example, iOS killing the wallet mid-flow) now resumes automatically on the next launch instead of stranding a non-removable identity.


### Security

- Account-owner surfaces (agent claim confirm, agent list/revoke/audit, child-agent minting, did:web hosting) now enforce DPoP token binding: a DPoP-bound OAuth access token presented as plain Bearer without its proof is rejected instead of accepted.

- The caller-influenced well-known handle-resolution fallback now uses the SSRF-hardened HTTP client, closing a reflected-SSRF sink reachable through unauthenticated `resolveHandle` requests.


## [0.5.0] - 2026-07-15

### Added

- Permanently remove an identity from the wallet — deletes the account on the PDS, tombstones the DID in the PLC directory, and wipes local key material.

- did:web identities on Custos: migrate an existing did:web account onto Custos, optionally let Custos host its `did.json`, and create a new did:web identity through a guided ceremony in the wallet.

- Change your handle from the wallet: for sovereign identities, a device-key-signed `alsoKnownAs` update is submitted directly to the PLC directory.

- Operators can repair account state through new maintenance operations.

- Per-DID sovereign sessions: the wallet now holds a device-key-controlled session for each identity and restores, refreshes, and renews it without re-entering a password. The PDS issues these sessions and guards them with a nonce replay store.

- Documentation sites for Obsign (users) and Custos (operators) now build with Astro Starlight — navigable, searchable, and deployed as an independent static service, each in its own design register.


### Changed

- Enum-valued server environment variables are now parsed case-insensitively.

- Account emails are normalized to lowercase on every read and write, so sign-in and account lookups are case-insensitive.

- Onboarding now leads with a single "Create identity" action (did:plc on Custos); the did:web own-domain path is tucked behind a lower-priority "Advanced" link for experienced users, and the entry screen shows a Back action when opened from a wallet that already holds identities.

- XRPC procedures that accept no input now reject a non-empty request body instead of silently ignoring it.

- The create-account flow prefills the chosen handle and accepts the login handle case-insensitively.


### Fixed

- Fixed the wallet blanking on resume and several viewport and scroll layout glitches on mobile.

- PDS-custodied handle changes now update the authoritative PLC document, while wallet-sovereign identities remain device-key controlled.

- Fixed the source-PDS login prefill in the wallet migration flow.

- The PDS no longer fails to start on IPv4-only hosts when binding its iroh socket.

- The wallet reconciles an ambiguous or lost PLC submission before retrying, avoiding duplicate directory operations.


### Security

- Repo-write authentication paths now enforce DPoP token binding.

- Identity resolution and atproto-proxy fetches share a single SSRF-hardened HTTP client.


## [0.4.7] - 2026-07-12

Release history before changelog fragments were introduced is preserved in Git tags.

[0.5.0]: https://github.com/malpercio-dev/ezpds/releases/tag/v0.5.0
[0.4.7]: https://github.com/malpercio-dev/ezpds/releases/tag/v0.4.7
