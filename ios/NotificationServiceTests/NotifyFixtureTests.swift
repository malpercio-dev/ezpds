// The cross-implementation check the golden fixtures were generated for.
//
// `crates/crypto/tests/fixtures/notify/hpke-notify-v1.json` is sealed by the Rust `hpke`
// crate and opened, here, by CryptoKit. RFC 9180's appendix has no test vector for this exact
// suite (A.3 is AES-128; CryptoKit's only P-256 suite forces AES-256), so nothing else proves
// the two implementations agree on the pinned suite, the `info` string, the empty `aad`, and
// the key encodings. The Rust side asserts these same vectors round-trip in
// `notify_hpke_vectors.rs`; between them, a drift on either side fails a test instead of
// producing devices that silently stop decrypting.
//
// The fixture file is referenced IN PLACE by the XcodeGen template — there is no copy in this
// directory to fall out of date with the crate.
//
// Not run by CI: `ios-pr-check` stops short of xcodebuild (no simulator, no archive), so this
// is a `⌘U` in Xcode or `xcodebuild test`. That is the same footing as the on-device demo the
// issue's acceptance names, and the reason the pure logic below is also covered by tests that
// need no crypto at all.

import CryptoKit
import XCTest

private struct NotifyVector: Decodable {
    let comment: String
    let senderPublicKeyBase64: String
    let recipientPrivateKeyBytes: [UInt8]
    let recipientPublicKeyBase64: String
    let plaintextBase64: String
    let encBase64: String
    let ctBase64: String
}

final class NotifyFixtureTests: XCTestCase {
    private func vectors() throws -> [NotifyVector] {
        let bundle = Bundle(for: type(of: self))
        let url = try XCTUnwrap(
            bundle.url(forResource: "hpke-notify-v1", withExtension: "json"),
            "the crates/crypto fixture must be bundled as a test resource"
        )
        return try JSONDecoder().decode([NotifyVector].self, from: Data(contentsOf: url))
    }

    private func b64(_ text: String) throws -> Data {
        try XCTUnwrap(Data(base64URLEncoded: text), "fixture value must be base64url")
    }

    /// The interop assertion: every payload Rust sealed, CryptoKit opens to the same bytes.
    func testCryptoKitOpensTheRustGoldenVectors() throws {
        let vectors = try vectors()
        XCTAssertFalse(vectors.isEmpty, "an empty fixture file would pass vacuously")

        for vector in vectors {
            let opened = NotifyCrypto.open(
                recipientPrivateKey: Data(vector.recipientPrivateKeyBytes),
                senderPublicKey: try b64(vector.senderPublicKeyBase64),
                encapsulatedKey: try b64(vector.encBase64),
                ciphertext: try b64(vector.ctBase64)
            )
            XCTAssertEqual(try b64(vector.plaintextBase64), opened, vector.comment)
        }
    }

    /// Auth mode's whole point: a payload opened with the wrong sender key does not open at
    /// all. This is what makes a relay a courier — it can drop and duplicate, but nothing it
    /// fabricates ever renders as content from the user's own instance.
    func testAWrongSenderKeyFailsClosed() throws {
        for vector in try vectors() {
            // Any other valid P-256 public key. The recipient's own is guaranteed to be one,
            // and guaranteed not to be the sender's.
            let wrongSender = try b64(vector.recipientPublicKeyBase64)
            XCTAssertNil(
                NotifyCrypto.open(
                    recipientPrivateKey: Data(vector.recipientPrivateKeyBytes),
                    senderPublicKey: wrongSender,
                    encapsulatedKey: try b64(vector.encBase64),
                    ciphertext: try b64(vector.ctBase64)
                ),
                vector.comment
            )
        }
    }

    /// A flipped ciphertext byte is an AEAD failure, not a partial plaintext.
    func testATamperedCiphertextDoesNotOpen() throws {
        for vector in try vectors() {
            var ciphertext = try b64(vector.ctBase64)
            ciphertext[0] ^= 0x01
            XCTAssertNil(
                NotifyCrypto.open(
                    recipientPrivateKey: Data(vector.recipientPrivateKeyBytes),
                    senderPublicKey: try b64(vector.senderPublicKeyBase64),
                    encapsulatedKey: try b64(vector.encBase64),
                    ciphertext: ciphertext
                ),
                vector.comment
            )
        }
    }

    /// The fixtures' plaintext is the wire payload the extension renders, not opaque bytes —
    /// so the decode step is part of what interop means.
    func testOpenedFixturesDecodeAsRenderablePayloads() throws {
        for vector in try vectors() {
            let plaintext = try b64(vector.plaintextBase64)
            let payload = try XCTUnwrap(NotifyPayload.decode(plaintext), vector.comment)
            XCTAssertFalse(payload.title.isEmpty && payload.body.isEmpty)
        }
    }

    /// `info` carries the version binding, so a payload sealed for another protocol version
    /// cannot open here even with every key correct.
    func testTheInfoStringIsTheVersionBinding() throws {
        XCTAssertEqual(NotifyCrypto.info, Data("ezpds/notify/1".utf8))
        XCTAssertTrue(NotifyCrypto.aad.isEmpty)
    }
}

/// The two resolver outcomes that need a *genuinely sealed* payload to reach, so they cannot
/// live with the rest of the failure ladder in `NotifyResolverTests`.
///
/// Sealed here with `HPKE.Sender` rather than pinned as another Rust fixture: what these
/// exercise is the resolver's behaviour on either side of a successful open, not the wire
/// format — the fixtures already own that, and adding a vector for "authentic but unrenderable"
/// would pin a shape Custos should never emit.
final class NotifySealedResolverTests: XCTestCase {
    /// Seal `plaintext` and hand back the `userInfo` an APNs delivery would carry, plus the
    /// sender's `did:key` as the pin store would hold it.
    private func sealed(
        _ plaintext: Data,
        kid: Int = 1
    ) throws -> (userInfo: [AnyHashable: Any], recipientKey: Data, senderDidKey: String) {
        let recipient = P256.KeyAgreement.PrivateKey()
        let sender = P256.KeyAgreement.PrivateKey()

        var hpke = try HPKE.Sender(
            recipientKey: recipient.publicKey,
            ciphersuite: NotifyCrypto.ciphersuite,
            info: NotifyCrypto.info,
            authenticatedBy: sender
        )
        let ciphertext = try hpke.seal(plaintext, authenticating: NotifyCrypto.aad)

        let b64 = { (data: Data) in
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let userInfo: [AnyHashable: Any] = [
            "aps": ["alert": ["title": "Custos", "body": "Encrypted notification"]],
            NotifyEnvelope.userInfoKey: [
                "v": 1, "kid": kid,
                "enc": b64(hpke.encapsulatedKey), "ct": b64(ciphertext),
            ],
        ]
        return (
            userInfo,
            recipient.rawRepresentation,
            TestDidKey.encode(sender.publicKey.compressedRepresentation)
        )
    }

    private func pins(kid: Int, _ didKey: String) -> PinnedSenderKeys {
        PinnedSenderKeys(
            version: 1,
            hosts: ["https://pds.example.com": [PinnedSenderKey(kid: kid, publicKey: didKey)]]
        )
    }

    /// The happy path, end to end through the resolver — proof that a correctly pinned sender
    /// key actually renders, so the failure cases below mean something.
    func testAnAuthenticSealedPayloadRenders() throws {
        let payload = Data(#"{"type":"agent_claim_pending","title":"Custos","body":"An agent is waiting"}"#.utf8)
        let (userInfo, key, didKey) = try sealed(payload)

        let outcome = NotifyResolver.resolve(
            userInfo: userInfo,
            recipientPrivateKey: key,
            pins: pins(kid: 1, didKey)
        )
        guard case let .rendered(rendered) = outcome else {
            return XCTFail("expected a render, got \(outcome)")
        }
        XCTAssertEqual(rendered.title, "Custos")
        XCTAssertEqual(rendered.body, "An agent is waiting")
    }

    /// The one outcome where the payload IS authenticated and still cannot be shown. Only a
    /// holder of the pinned sender key could have produced it, so this is our own bug or a
    /// version skew — but there is no content to render, and the rule admits no exception for
    /// a payload whose provenance is fine.
    func testAnAuthenticButUnrenderablePayloadIsUnverified() throws {
        let (userInfo, key, didKey) = try sealed(Data("not json at all".utf8), kid: 7)

        XCTAssertEqual(
            NotifyResolver.resolve(
                userInfo: userInfo,
                recipientPrivateKey: key,
                pins: pins(kid: 7, didKey)
            ),
            .unverified(.malformedPlaintext, kid: 7)
        )
    }

    /// A payload that opens but carries nothing to say. Rejected for the same reason: a blank
    /// banner is indistinguishable from a delivery failure.
    func testAnEmptySealedPayloadIsUnverified() throws {
        let (userInfo, key, didKey) = try sealed(Data(#"{"type":"x","title":"","body":""}"#.utf8))

        XCTAssertEqual(
            NotifyResolver.resolve(
                userInfo: userInfo,
                recipientPrivateKey: key,
                pins: pins(kid: 1, didKey)
            ),
            .unverified(.malformedPlaintext, kid: 1)
        )
    }

    /// The right key under the wrong `kid` is not a candidate at all — which is what makes
    /// `UNKNOWN_KID` a re-pin signal rather than a generic decryption failure.
    func testAPinUnderAnotherKidIsNotTried() throws {
        let (userInfo, key, didKey) = try sealed(Data(#"{"type":"x","title":"t","body":"b"}"#.utf8), kid: 2)

        XCTAssertEqual(
            NotifyResolver.resolve(
                userInfo: userInfo,
                recipientPrivateKey: key,
                pins: pins(kid: 99, didKey)
            ),
            .unverified(.unknownKid, kid: 2)
        )
    }
}

/// A `did:key` **encoder**, test-only.
///
/// The extension ships only the decoder — it never mints a sender key, it just reads the ones
/// Custos published. Encoding here lets these tests build a pin store around a keypair they
/// generated, and doubles as a round-trip check on `DidKey`.
enum TestDidKey {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func encode(_ compressedPoint: Data) -> String {
        let bytes = DidKey.p256Prefix + [UInt8](compressedPoint)

        // Base-256 → base-58 by repeated division, least-significant digit first.
        var digits: [Int] = []
        for byte in bytes {
            var carry = Int(byte)
            for index in digits.indices {
                carry += digits[index] << 8
                digits[index] = carry % 58
                carry /= 58
            }
            while carry > 0 {
                digits.append(carry % 58)
                carry /= 58
            }
        }

        // Leading zero BYTES carry no magnitude, so the arithmetic above cannot represent them;
        // base58 spells each as one '1'. (A P-256 did:key never has any — the multicodec prefix
        // starts 0x80 — but an encoder that only works for its one caller is not one the
        // round-trip test can vouch for.)
        let leadingZeros = bytes.prefix { $0 == 0 }.count
        let body = digits.reversed().map { alphabet[$0] }
        return "did:key:z" + String(repeating: alphabet[0], count: leadingZeros) + String(body)
    }
}

final class TestDidKeyRoundTripTests: XCTestCase {
    /// If the encoder and the shipped decoder disagree, every test above would be exercising a
    /// candidate set the real extension could never build.
    func testTheEncoderRoundTripsThroughTheShippedDecoder() throws {
        for _ in 0..<8 {
            let point = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
            let decoded = try XCTUnwrap(
                DidKey.p256PublicKeyBytes(from: TestDidKey.encode(point))
            )
            XCTAssertEqual(decoded, point)
        }
    }
}
