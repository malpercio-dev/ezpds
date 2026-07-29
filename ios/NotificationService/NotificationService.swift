// The Notification Service Extension: the only place a sealed push is ever plaintext.
//
// A Custos instance HPKE-seals a notification to this device's key and hands it to a relay
// that holds the APNs key but no decryption key. The relay and Apple both carry the payload
// as opaque bytes beside a placeholder alert ("Custos / Encrypted notification"), and
// `mutable-content: 1` routes it here for the ~30 seconds iOS allows before it gives up and
// shows the placeholder.
//
// # The constraint that shapes everything below
//
// **An NSE cannot suppress an alert push.** If this code fails, times out, or declines to
// attach content, iOS displays the original payload anyway. So "drop what we cannot verify"
// is not on the menu; the only thing under this extension's control is *what the user reads*.
// The rule is therefore absolute: content that opened under HPKE Auth mode renders as
// content, and everything else renders as the explicit unverified notice. Never a guess,
// never a partial render, never the placeholder passed through as though it were news.
//
// That is what keeps a relay's junk push from being an impersonation. The relay can always
// generate noise — it holds the APNs key — but noise arrives labelled as unverifiable, which
// is detectable spam and grounds for switching relays, not a forged message from your server.

import UserNotifications

/// The decision the extension makes about one payload, split out from the `UNNotification`
/// machinery so every branch is reachable from a test.
enum NotifyOutcome: Equatable {
    case rendered(NotifyPayload)
    case unverified(NotifyFailureReason, kid: Int?)
}

enum NotifyResolver {
    /// The user-visible copy for a payload this device cannot vouch for.
    ///
    /// Deliberately says what happened and nothing more. It names no sender ("from your
    /// Custos instance" is a category, not a claim about which one), states no cause the
    /// extension cannot know, and offers no action — the actionable version of this lives in
    /// Settings, where the breadcrumbs can say whether it happened once or twenty times.
    static let unverifiedTitle = "Unverified notification"
    static let unverifiedBody = "Couldn't verify a notification from your Custos instance."

    /// Resolve an APNs `userInfo` into what should be shown.
    ///
    /// Pure over its inputs — the Keychain reads happen in the caller — so the whole failure
    /// ladder is exercisable on a simulator with no push and no registered key.
    static func resolve(
        userInfo: [AnyHashable: Any],
        recipientPrivateKey: Data?,
        pins: PinnedSenderKeys
    ) -> NotifyOutcome {
        guard let envelope = NotifyEnvelope.parse(userInfo: userInfo) else {
            return .unverified(.malformedPayload, kid: nil)
        }
        guard let recipientPrivateKey else {
            return .unverified(.keysUnavailable, kid: envelope.kid)
        }

        let candidates = pins.candidates(for: envelope.kid)
        guard !candidates.isEmpty else {
            return .unverified(.unknownKid, kid: envelope.kid)
        }

        // Try every key pinned under this `kid`. See `PinnedSenderKeys.candidates` for why
        // there can be more than one; Auth mode makes a wrong guess free.
        for didKey in candidates {
            guard let senderBytes = DidKey.p256PublicKeyBytes(from: didKey) else { continue }
            guard let plaintext = NotifyCrypto.open(
                recipientPrivateKey: recipientPrivateKey,
                senderPublicKey: senderBytes,
                encapsulatedKey: envelope.enc,
                ciphertext: envelope.ct
            ) else { continue }

            // Past this point the payload is authenticated: only a holder of a pinned sender
            // private key could have produced it. A body we cannot parse is therefore our own
            // bug or a version skew, not an attack — but it still cannot be rendered as
            // content, because there is no content to render.
            guard let payload = NotifyPayload.decode(plaintext) else {
                return .unverified(.malformedPlaintext, kid: envelope.kid)
            }
            return .rendered(payload)
        }

        return .unverified(.openFailed, kid: envelope.kid)
    }
}

final class NotificationService: UNNotificationServiceExtension {
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var bestAttempt: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        guard let content = request.content.mutableCopy() as? UNMutableNotificationContent else {
            // `UNNotificationContent.mutableCopy()` is documented to return the mutable class, so
            // this is a platform-contract violation rather than a state a payload can produce.
            // It still cannot be allowed to deliver `request.content`: that content is immutable,
            // so the sealed block cannot be stripped from it, and its title/body are the relay's
            // placeholder — the one combination the extension's rule forbids. A fresh content
            // carrying only the notice is the sole way to honour both halves here.
            //
            // No breadcrumb: the failure vocabulary describes payloads, and reporting this as a
            // payload problem would send the user looking at their keys for a bug in ours.
            contentHandler(Self.unverifiedContent())
            return
        }
        bestAttempt = content

        let outcome = NotifyResolver.resolve(
            userInfo: request.content.userInfo,
            recipientPrivateKey: NotifyKeychain.read(
                account: NotifyKeychain.notificationKeyAccount
            ),
            pins: PinnedSenderKeys.parse(
                NotifyKeychain.read(account: NotifyKeychain.pinnedSenderKeysAccount)
            )
        )

        switch outcome {
        case let .rendered(payload):
            content.title = payload.title
            content.body = payload.body
            // Routing survives ONLY on the verified path: `ezpdsRoute`'s presence in a
            // delivered notification is the statement that HPKE Auth vouched for it, which
            // is what lets the app deep-link on a tap without re-deciding trust.
            if let route = NotifyRoute.userInfo(for: payload) {
                content.userInfo[NotifyRoute.userInfoKey] = route
            }
        case let .unverified(reason, kid):
            content.title = NotifyResolver.unverifiedTitle
            content.body = NotifyResolver.unverifiedBody
            NotifyBreadcrumbs.record(reason, kid: kid)
        }

        Self.finish(content)
        contentHandler(content)
    }

    /// iOS is about to give up on us.
    ///
    /// Whatever is in `bestAttempt` is delivered, so this path has to satisfy the same two
    /// obligations `didReceive` does — say "unverified" rather than let the relay's placeholder
    /// stand in for the server's words, and strip the sealed block. Neither gets an exception
    /// for running late: a timeout is the one route by which unstripped ciphertext, under a
    /// title the user reads as authentic, could reach the delivered-notification list.
    override func serviceExtensionTimeWillExpire() {
        guard let contentHandler, let bestAttempt else { return }
        // The presence of the sealed block IS the "we never finished" signal — `finish` strips it
        // and writes the notice in the same breath, so it can only still be here if resolution
        // was cut short. Testing that rather than the title keeps the two facts from drifting.
        if bestAttempt.userInfo[NotifyEnvelope.userInfoKey] != nil {
            bestAttempt.title = NotifyResolver.unverifiedTitle
            bestAttempt.body = NotifyResolver.unverifiedBody
        }
        Self.finish(bestAttempt)
        contentHandler(bestAttempt)
    }

    /// The last thing done to any content that leaves this extension.
    ///
    /// The sealed block has served its purpose and must not ride along into the delivered
    /// notification, where the app — and anything reading `UNUserNotificationCenter`'s delivered
    /// list — would see ciphertext it has no use for. Factored out because "every exit path"
    /// is the actual requirement, and inlining it at each one is how an exit path gets missed.
    private static func finish(_ content: UNMutableNotificationContent) {
        content.userInfo.removeValue(forKey: NotifyEnvelope.userInfoKey)
    }

    /// A fresh content carrying nothing but the unverified notice.
    ///
    /// For the exit where no mutable copy exists to strip, so substituting content is the only
    /// way to avoid delivering the sealed block.
    private static func unverifiedContent() -> UNMutableNotificationContent {
        let content = UNMutableNotificationContent()
        content.title = NotifyResolver.unverifiedTitle
        content.body = NotifyResolver.unverifiedBody
        return content
    }
}
