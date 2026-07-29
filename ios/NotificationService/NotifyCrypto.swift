// The CryptoKit side of the HPKE envelope `crates/crypto/src/hpke.rs` seals.
//
// The ciphersuite is not chosen here, it is *forced*: CryptoKit ships exactly one P-256 HPKE
// suite, `P256_SHA256_AES_GCM_256`, and the Rust side is pinned to match it. That is why the
// wire format has no negotiation and no downgrade lattice — there is nothing to negotiate
// with. `HPKE.Recipient`'s auth-mode initializer is also why both apps deploy at iOS 17: the
// API does not exist before it.
//
// Cross-implementation agreement is verified by NotifyFixtureTests, which opens the golden
// vectors in `crates/crypto/tests/fixtures/notify/` — the whole reason those fixtures were
// generated, since RFC 9180's appendix carries no vector for this exact suite.

import CryptoKit
import Foundation

enum NotifyCrypto {
    /// RFC 9180 `info` for v1 — `crypto::NOTIFY_INFO`. Bound into the key schedule, so a
    /// payload sealed for a different protocol version cannot open here even with the right
    /// keys. This is the version binding; the envelope's `v` is a routing hint, not a trust
    /// decision.
    static let info = Data("ezpds/notify/1".utf8)
    /// RFC 9180 `aad` for v1 — `crypto::NOTIFY_AAD`. Empty: everything a receiver must trust
    /// already rides in `info`.
    static let aad = Data()

    static let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256

    /// Open a sealed payload, authenticated as `senderPublicKey`.
    ///
    /// `recipientPrivateKey` is the raw 32-byte scalar out of the Keychain;
    /// `senderPublicKey` is SEC1 bytes, compressed (33, what a `did:key` decodes to) or
    /// uncompressed (65, what the golden fixtures store).
    ///
    /// Returns `nil` on any failure — a malformed key, a wrong sender, a corrupted
    /// ciphertext. The caller does not act on the distinction: in Auth mode "this did not
    /// open" and "this was not sent by the key you pinned" are the same verdict, which is
    /// exactly the property that makes the relay a courier rather than an author.
    static func open(
        recipientPrivateKey: Data,
        senderPublicKey: Data,
        encapsulatedKey: Data,
        ciphertext: Data
    ) -> Data? {
        guard let privateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey),
              let publicKey = senderKey(from: senderPublicKey)
        else { return nil }

        // `var` because `HPKE.Recipient.open` is mutating — the recipient carries the AEAD
        // sequence number, even though a single-shot open never advances past the first message.
        guard var recipient = try? HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: ciphersuite,
            info: info,
            encapsulatedKey: encapsulatedKey,
            authenticatedBy: publicKey
        ) else { return nil }

        return try? recipient.open(ciphertext, authenticating: aad)
    }

    /// Accept either SEC1 encoding. `did:key` yields the compressed point; the Rust fixtures
    /// pin the uncompressed one, and both must reach the same key.
    private static func senderKey(from bytes: Data) -> P256.KeyAgreement.PublicKey? {
        if let compressed = try? P256.KeyAgreement.PublicKey(compressedRepresentation: bytes) {
            return compressed
        }
        return try? P256.KeyAgreement.PublicKey(x963Representation: bytes)
    }
}
