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
