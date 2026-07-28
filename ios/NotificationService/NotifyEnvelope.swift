// The pure half of the Notification Service Extension: everything that turns bytes into
// other bytes, with no Keychain, no CryptoKit, and no UserNotifications.
//
// It lives apart from NotificationService.swift for the same reason the wallet's Rust keeps
// `_impl` cores away from Tauri commands — this is the part an XCTest can drive on a
// simulator, and the part the Rust↔CryptoKit fixture cross-check exercises.

import Foundation

/// The `ezpds` object a sealed push carries beside its placeholder `aps` alert.
///
/// Wire shape (see `crates/notify-relay/src/protocol.rs`):
/// `{ "v": 1, "kid": 3, "enc": "<b64url>", "ct": "<b64url>" }`
struct NotifyEnvelope: Equatable {
    /// Protocol version. Only `1` is understood; anything else is a payload sealed by a
    /// newer instance for a newer extension, and must render as unverified rather than be
    /// guessed at.
    static let supportedVersion = 1

    let version: Int
    /// The instance-scoped sender-key id. Not a global identifier: two Custos instances both
    /// start their `kid` sequence at 1, which is why the pin store is keyed by host and every
    /// candidate under this id is tried.
    let kid: Int
    /// HPKE encapsulated key — 65 raw bytes for DHKEM(P-256).
    let enc: Data
    /// AEAD ciphertext with the 16-byte AES-GCM tag appended.
    let ct: Data

    /// Read the envelope out of an APNs `userInfo` dictionary.
    ///
    /// Returns `nil` for anything that is not a well-formed v1 envelope — a junk push from a
    /// misbehaving relay, a `content-available` ping, or a future version. The caller renders
    /// all of those identically (the unverified notice), so this deliberately does not
    /// distinguish "absent" from "malformed": neither is content this device can vouch for.
    static func parse(userInfo: [AnyHashable: Any]) -> NotifyEnvelope? {
        guard let block = userInfo["ezpds"] as? [String: Any],
              let version = block["v"] as? Int,
              version == supportedVersion,
              let kid = block["kid"] as? Int,
              let encText = block["enc"] as? String,
              let ctText = block["ct"] as? String,
              let enc = Data(base64URLEncoded: encText),
              let ct = Data(base64URLEncoded: ctText),
              !enc.isEmpty, !ct.isEmpty
        else { return nil }

        return NotifyEnvelope(version: version, kid: kid, enc: enc, ct: ct)
    }
}

/// The decrypted plaintext a Custos instance seals.
///
/// Wire shape: `{ "type": …, "title": …, "body": …, "data": { … }, "pad": "…" }`. `pad` is
/// dropped on the floor here — its whole job was to make the *serialized APNs request* land
/// on a padding bucket, which is finished by the time these bytes exist.
struct NotifyPayload: Equatable, Decodable {
    let type: String
    let title: String
    let body: String

    /// Decode sealed plaintext, rejecting a payload with nothing to render.
    ///
    /// An empty title *and* body would produce a banner indistinguishable from a silent
    /// delivery failure, so it is treated as a malformed payload and rendered as the
    /// unverified notice instead — the extension's one rule is that it never shows something
    /// it cannot stand behind.
    static func decode(_ plaintext: Data) -> NotifyPayload? {
        guard let payload = try? JSONDecoder().decode(NotifyPayload.self, from: plaintext),
              !(payload.title.isEmpty && payload.body.isEmpty)
        else { return nil }
        return payload
    }
}

// MARK: - base64url

extension Data {
    /// Decode unpadded base64url — the encoding every binary field in the envelope uses
    /// (`URL_SAFE_NO_PAD` on the Rust side). Foundation only speaks standard base64 with
    /// padding, so translate the alphabet and re-pad.
    init?(base64URLEncoded input: String) {
        var text = input.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = text.count % 4
        if remainder == 1 {
            // 4n+1 is not a length any base64 encoding can produce; padding it would
            // manufacture a decodable string out of corrupt input.
            return nil
        }
        if remainder > 0 {
            text += String(repeating: "=", count: 4 - remainder)
        }
        guard let decoded = Data(base64Encoded: text) else { return nil }
        self = decoded
    }
}

// MARK: - did:key

/// Decode a P-256 `did:key` into its raw SEC1 public-key bytes.
///
/// The pinned sender keys arrive from Custos as `did:key:z…` strings and are stored verbatim
/// by the wallet (`notifications.rs`), so the extension has to undo the encoding itself:
/// multibase base58btc (`z` prefix) wrapping the multicodec varint `0x1200` — written
/// little-endian-base128 as `0x80 0x24` — followed by a 33-byte compressed point.
///
/// Returns `nil` for anything that is not exactly that. A sender key this device cannot
/// decode is simply not a candidate; HPKE Auth mode would fail closed on it anyway, so
/// skipping costs nothing and misreading could not gain anything.
enum DidKey {
    /// The multicodec prefix for `p256-pub`, varint-encoded.
    static let p256Prefix: [UInt8] = [0x80, 0x24]
    /// A compressed SEC1 P-256 point: 1 tag byte + 32-byte X.
    static let compressedPointLength = 33

    static func p256PublicKeyBytes(from didKey: String) -> Data? {
        guard didKey.hasPrefix("did:key:z") else { return nil }
        let multibase = String(didKey.dropFirst("did:key:z".count))
        guard let decoded = Base58.decode(multibase),
              decoded.count == p256Prefix.count + compressedPointLength,
              Array(decoded.prefix(p256Prefix.count)) == p256Prefix
        else { return nil }
        return Data(decoded.dropFirst(p256Prefix.count))
    }
}

/// base58btc, the one multibase alphabet `did:key` uses.
///
/// Hand-rolled because the extension links nothing but system frameworks: a Swift package
/// dependency in an NSE is a second supply chain in the one target that runs on a locked
/// screen, for ~30 lines of long division.
enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    static func decode(_ input: String) -> [UInt8]? {
        var bytes: [UInt8] = [0]
        for character in input.utf8 {
            guard let value = alphabet.firstIndex(of: character) else { return nil }
            var carry = value
            for index in bytes.indices.reversed() {
                carry += 58 * Int(bytes[index])
                bytes[index] = UInt8(carry & 0xff)
                carry >>= 8
            }
            while carry > 0 {
                bytes.insert(UInt8(carry & 0xff), at: 0)
                carry >>= 8
            }
        }
        // Every leading '1' encodes one leading zero byte, which the arithmetic above cannot
        // recover (it carries no magnitude).
        var leadingZeros = 0
        for character in input.utf8 {
            guard character == alphabet[0] else { break }
            leadingZeros += 1
        }
        // Drop the seed byte and any zeros the long division introduced, then restore the
        // encoded ones.
        let significant = Array(bytes.drop(while: { $0 == 0 }))
        return Array(repeating: 0, count: leadingZeros) + significant
    }
}
