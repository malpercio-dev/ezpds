// The diagnostic trail behind the unverified notice.
//
// iOS will not let a Notification Service Extension suppress an alert push, so a payload the
// device cannot verify still produces a banner. The banner says so honestly — but on its own
// it is a mystery: a user seeing "couldn't verify" three days running has no way to tell a
// key desync from a relay sending junk. These breadcrumbs are what turns that into something
// Settings can state, and they are the *only* thing the extension leaves behind.
//
// They are written to the shared Keychain rather than an app-group container. The group the
// extension already needs (`org.obsign.shared`) requires no Apple Developer portal work,
// where an app group would be a second entitlement on both bundles; and the protection class
// is the same one the notification key already carries, so a breadcrumb is writable in
// exactly the moments a decryption is attemptable. The one case that buys: a push arriving
// before the first unlock after a reboot leaves no breadcrumb — but that state repairs itself
// the moment the user unlocks, and is the least diagnostic-worthy of the failures.

import Foundation

/// Why a payload could not be rendered as authentic. Shared vocabulary with
/// `notifications::NotificationFailureReason` on the Rust side — the app maps these onto the
/// sentences Settings shows, so a new case here needs one there.
enum NotifyFailureReason: String {
    /// No `ezpds` block, or one this version cannot parse. What a junk push from a
    /// misbehaving relay looks like — the relay holds the APNs key and can always send noise.
    case malformedPayload = "MALFORMED_PAYLOAD"
    /// The notification key or the pin document could not be read: either nothing is
    /// registered yet, or the Keychain is locked before the first unlock after a reboot.
    case keysUnavailable = "KEYS_UNAVAILABLE"
    /// No pinned sender key carries the envelope's `kid`. The key-desync signature: the
    /// instance rotated and this device has not re-pinned since.
    case unknownKid = "UNKNOWN_KID"
    /// Candidates existed and every one of them failed to open the payload. HPKE Auth mode
    /// failing closed — a forged or corrupted ciphertext, or a genuinely stale pin.
    case openFailed = "OPEN_FAILED"
    /// The payload opened — so it *was* authentic — but carried nothing renderable.
    case malformedPlaintext = "MALFORMED_PLAINTEXT"
}

/// One recorded failure.
struct NotifyFailure: Codable, Equatable {
    let at: String
    let reason: String
    /// The envelope's `kid`, where there was a parseable envelope to read one from.
    let kid: Int?
}

/// The stored log: newest first, bounded.
struct NotifyFailureLog: Codable {
    static let supportedVersion = 1
    /// Enough to show a pattern ("five in the last day"), small enough that the whole log
    /// stays a single modest Keychain item. Older entries answer no question the newer ones
    /// do not.
    static let capacity = 20

    var version: Int
    var failures: [NotifyFailure]

    static let empty = NotifyFailureLog(version: supportedVersion, failures: [])

    /// Read the log, treating anything unreadable as empty.
    ///
    /// Fail-open like the pin store: this is a diagnostic trail, and refusing to append to a
    /// damaged one would lose the very breadcrumb that is being recorded right now.
    static func parse(_ raw: Data?) -> NotifyFailureLog {
        guard let raw,
              let decoded = try? JSONDecoder().decode(NotifyFailureLog.self, from: raw),
              decoded.version == supportedVersion
        else { return .empty }
        return decoded
    }

    /// Prepend `failure`, dropping the oldest beyond [`capacity`]. Pure, so the trimming rule
    /// is testable without a Keychain.
    func appending(_ failure: NotifyFailure) -> NotifyFailureLog {
        NotifyFailureLog(
            version: Self.supportedVersion,
            failures: Array(([failure] + failures).prefix(Self.capacity))
        )
    }
}

enum NotifyBreadcrumbs {
    /// Record one failure, best effort.
    ///
    /// Every outcome is swallowed. The extension has one job left at this point — putting an
    /// honest notice on screen before iOS's timeout — and a Keychain that will not take a
    /// diagnostic must not be allowed to cost the user that. A lost breadcrumb is a lost
    /// breadcrumb; a lost `contentHandler` call is the placeholder text shown instead.
    static func record(_ reason: NotifyFailureReason, kid: Int?, now: Date = Date()) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let failure = NotifyFailure(
            at: formatter.string(from: now),
            reason: reason.rawValue,
            kid: kid
        )

        let log = NotifyFailureLog
            .parse(NotifyKeychain.read(account: NotifyKeychain.failureLogAccount))
            .appending(failure)

        guard let encoded = try? JSONEncoder().encode(log) else { return }
        NotifyKeychain.write(account: NotifyKeychain.failureLogAccount, data: encoded)
    }
}
