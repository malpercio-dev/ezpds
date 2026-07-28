// The extension's half of the shared Keychain contract the wallet's notification registration
// established.
//
// Every constant here is a copy of one in `apps/identity-wallet/src-tauri/src/keychain.rs`
// and `notifications.rs`, because the two processes are separate bundles that can only agree
// by both spelling the same strings. Nothing else may be added: the app writes, the
// extension reads, and the single exception (the breadcrumb log) is written by both.
//
// # Why no `kSecAttrAccessGroup` anywhere below
//
// Exactly the wallet's stance, and for the same reason. Naming a group means discovering the
// team's `AppIdentifierPrefix` at runtime, which adds a failure mode to the one code path
// that must work on a locked screen. Instead the entitlement's *shape* carries the contract:
// `$(AppIdentifierPrefix)org.obsign.shared` is listed FIRST in both bundles' entitlements, so
// an unqualified write lands there and an unqualified read searches every entitled group.
// `just bundle-identity-check` and `just ios-template-check` enforce the ordering.

import Foundation
import Security

enum NotifyKeychain {
    /// `keychain::SERVICE`. Changing it orphans every item the app ever wrote.
    static let service = "ezpds-identity-wallet"

    /// `notifications::NOTIFICATION_KEY_ACCOUNT` — the raw 32-byte P-256 scalar.
    static let notificationKeyAccount = "notification-key-priv"
    /// `notifications::PINNED_SENDER_KEYS_ACCOUNT` — the per-host pin document.
    static let pinnedSenderKeysAccount = "notification-sender-keys"
    /// `notifications::FAILURE_LOG_ACCOUNT` — the breadcrumbs Settings surfaces.
    static let failureLogAccount = "notification-failures"

    /// Read a device-local generic password.
    ///
    /// Returns `nil` for a missing item *and* for a locked Keychain (`errSecInteractionNotAllowed`,
    /// what a push arriving before the first unlock after a reboot sees). The caller renders both
    /// as the unverified notice, so the distinction would buy nothing here — it is drawn in the
    /// breadcrumb instead, where it is the difference between "reboot, this will fix itself" and
    /// "your keys and your server's disagree".
    static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    /// Write a device-local generic password under `kSecAttrAccessibleAfterFirstUnlock`.
    ///
    /// Delete-then-add, matching `keychain::store_item_after_first_unlock` exactly:
    /// `SecItemUpdate` cannot change an existing item's protection class, so an update would
    /// silently inherit whatever class the first writer set — and on this account the class is
    /// the whole contract, since a breadcrumb about a locked-screen failure is itself written
    /// on a locked screen.
    @discardableResult
    static func write(account: String, data: Data) -> Bool {
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(identity as CFDictionary)

        var attributes = identity
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
    }
}

/// One published sender key, mirroring `notifications::SenderKey`.
struct PinnedSenderKey: Decodable, Equatable {
    let kid: Int
    let publicKey: String
}

/// The pin document, mirroring `notifications::PinnedSenderKeys`.
struct PinnedSenderKeys: Decodable {
    static let supportedVersion = 1

    let version: Int
    /// Hosting server → that server's published set.
    let hosts: [String: [PinnedSenderKey]]

    /// Every key published under `kid`, across every host this device has pinned against.
    ///
    /// A flat list on purpose. `kid` is an autoincrement column on *one* instance, so a wallet
    /// holding identities on two servers will hold two unrelated keys under `kid: 1` — and the
    /// push that arrives carries no DID, no handle, and no host, because naming one would give
    /// the relay and Apple exactly the metadata this design exists to withhold. So the
    /// extension cannot know which host sent it, and tries all of them. That costs nothing and
    /// risks nothing: HPKE Auth mode either authenticates against a given sender key or it
    /// does not, so a wrong candidate fails closed and the next is tried.
    func candidates(for kid: Int) -> [String] {
        hosts.values.flatMap { $0 }.filter { $0.kid == kid }.map(\.publicKey)
    }

    /// Parse the stored document, treating an unreadable or foreign-version one as empty.
    ///
    /// **Fail-open**, exactly as `notifications::load_pins` is, and for the same reason: this
    /// holds public keys the server hands back on the next contact. Refusing to read it would
    /// forfeit nothing an attacker wants and cost the user the notification in front of them.
    /// The safety property lives in HPKE, not here — an empty candidate set renders the
    /// unverified notice, which is the correct outcome.
    static func parse(_ raw: Data?) -> PinnedSenderKeys {
        guard let raw,
              let decoded = try? JSONDecoder().decode(PinnedSenderKeys.self, from: raw),
              decoded.version == supportedVersion
        else { return PinnedSenderKeys(version: supportedVersion, hosts: [:]) }
        return decoded
    }
}
