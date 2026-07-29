// The failure ladder, with no crypto and no Keychain.
//
// Every branch here ends in a banner the user reads, so each one is worth pinning: the
// extension's single rule is that authenticated content renders as content and everything
// else renders as the unverified notice, and these are the cases where that rule could quietly
// erode into "render whatever we managed to parse".

import XCTest

private func envelope(v: Int = 1, kid: Int = 1, enc: String = "AQID", ct: String = "BAUG") -> [AnyHashable: Any] {
    ["aps": ["alert": ["title": "Custos", "body": "Encrypted notification"]],
     "ezpds": ["v": v, "kid": kid, "enc": enc, "ct": ct]]
}

final class NotifyEnvelopeTests: XCTestCase {
    func testAWellFormedEnvelopeParses() throws {
        let parsed = try XCTUnwrap(NotifyEnvelope.parse(userInfo: envelope()))
        XCTAssertEqual(parsed.kid, 1)
        XCTAssertEqual(parsed.enc, Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(parsed.ct, Data([0x04, 0x05, 0x06]))
    }

    /// A push with no `ezpds` block at all — what a relay sending junk, or a future
    /// content-free ping, looks like.
    func testAPushWithoutTheEnvelopeIsRejected() {
        XCTAssertNil(NotifyEnvelope.parse(userInfo: ["aps": ["alert": "hello"]]))
    }

    /// A newer instance sealing for a newer extension. Guessing at it would be the one way
    /// unverifiable bytes could reach the screen as content.
    func testAFutureVersionIsRejectedRatherThanGuessed() {
        XCTAssertNil(NotifyEnvelope.parse(userInfo: envelope(v: 2)))
    }

    func testEmptyOrUndecodableFieldsAreRejected() {
        XCTAssertNil(NotifyEnvelope.parse(userInfo: envelope(enc: "")))
        XCTAssertNil(NotifyEnvelope.parse(userInfo: envelope(ct: "!!!not base64!!!")))
        // 4n+1 is a length no base64 encoding can produce; re-padding it would manufacture a
        // decodable string out of corrupt input.
        XCTAssertNil(NotifyEnvelope.parse(userInfo: envelope(enc: "AAAAA")))
    }

    func testBase64UrlDecodesTheAlphabetTheRustSideEmits() {
        // URL_SAFE_NO_PAD: '-' and '_' for '+' and '/', and no '=' padding.
        XCTAssertEqual(Data(base64URLEncoded: "-_8"), Data([0xfb, 0xff]))
        XCTAssertEqual(Data(base64URLEncoded: "AQ"), Data([0x01]))
    }
}

final class DidKeyTests: XCTestCase {
    /// A real P-256 did:key. The pinned sender keys arrive in exactly this form, so a
    /// regression here silently empties every candidate set and turns every push into the
    /// unverified notice.
    private let sample = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"

    func testAP256DidKeyDecodesToACompressedPoint() throws {
        let bytes = try XCTUnwrap(DidKey.p256PublicKeyBytes(from: sample))
        XCTAssertEqual(bytes.count, DidKey.compressedPointLength)
        XCTAssertTrue(bytes[0] == 0x02 || bytes[0] == 0x03, "compressed SEC1 parity tag")
    }

    func testNonP256AndMalformedKeysAreRejected() {
        // An Ed25519 did:key — right shape, wrong multicodec.
        XCTAssertNil(DidKey.p256PublicKeyBytes(
            from: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ))
        XCTAssertNil(DidKey.p256PublicKeyBytes(from: "did:key:zNOTBASE58!!!"))
        XCTAssertNil(DidKey.p256PublicKeyBytes(from: "did:plc:abc123"))
        XCTAssertNil(DidKey.p256PublicKeyBytes(from: ""))
    }

    func testBase58PreservesLeadingZeroBytes() {
        // '1' is base58's zero digit; the long division carries no magnitude for it, so the
        // leading zeros have to be restored explicitly or every multicodec prefix shifts.
        XCTAssertEqual(Base58.decode("11"), [0x00, 0x00])
        XCTAssertEqual(Base58.decode("12"), [0x00, 0x01])
    }
}

final class NotifyResolverTests: XCTestCase {
    private let key = Data(repeating: 0x01, count: 32)

    private func pins(_ entries: [(Int, String)]) -> PinnedSenderKeys {
        PinnedSenderKeys(
            version: 1,
            hosts: ["https://pds.example.com": entries.map { PinnedSenderKey(kid: $0.0, publicKey: $0.1) }]
        )
    }

    func testAJunkPushIsUnverifiedRatherThanRendered() {
        let outcome = NotifyResolver.resolve(
            userInfo: ["aps": ["alert": "Buy crypto now"]],
            recipientPrivateKey: key,
            pins: pins([])
        )
        XCTAssertEqual(outcome, .unverified(.malformedPayload, kid: nil))
    }

    /// The post-reboot locked Keychain, and the never-registered device, reach the same
    /// place — the extension cannot tell them apart and must not pretend to.
    func testAnUnreadableKeyIsUnverified() {
        let outcome = NotifyResolver.resolve(
            userInfo: envelope(kid: 3),
            recipientPrivateKey: nil,
            pins: pins([(3, "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169")])
        )
        XCTAssertEqual(outcome, .unverified(.keysUnavailable, kid: 3))
    }

    /// The key-desync signature: the instance rotated and this device has not re-pinned. It
    /// is recorded distinctly because it is the one failure Settings can give real advice
    /// about — open the app so it re-pins.
    func testAnUnpinnedKidIsRecordedAsItsOwnFailure() {
        let outcome = NotifyResolver.resolve(
            userInfo: envelope(kid: 9),
            recipientPrivateKey: key,
            pins: pins([(1, "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169")])
        )
        XCTAssertEqual(outcome, .unverified(.unknownKid, kid: 9))
    }

    /// Candidates existed and none opened it. Reached here with junk ciphertext, which is
    /// precisely the replayed-junk payload the acceptance criteria name.
    func testCandidatesThatAllFailToOpenAreUnverified() {
        let outcome = NotifyResolver.resolve(
            userInfo: envelope(kid: 1),
            recipientPrivateKey: key,
            pins: pins([(1, "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169")])
        )
        XCTAssertEqual(outcome, .unverified(.openFailed, kid: 1))
    }

    /// An undecodable `did:key` is skipped, not fatal — but with nothing left to try the
    /// verdict is still "did not open", never a render.
    func testAnUndecodableCandidateIsSkipped() {
        let outcome = NotifyResolver.resolve(
            userInfo: envelope(kid: 1),
            recipientPrivateKey: key,
            pins: pins([(1, "did:key:zGARBAGE"), (1, "did:key:zAlsoGarbage")])
        )
        XCTAssertEqual(outcome, .unverified(.openFailed, kid: 1))
    }

    func testTheUnverifiedNoticeNeverImpersonatesContent() {
        XCTAssertTrue(NotifyResolver.unverifiedBody.contains("Couldn't verify"))
        XCTAssertNotEqual(NotifyResolver.unverifiedTitle, "Custos")
    }
}

final class NotifyPayloadRouteTests: XCTestCase {
    private func decode(_ json: String) -> NotifyPayload? {
        NotifyPayload.decode(Data(json.utf8))
    }

    /// The `login-approval` payload the consent push seals: the routing identifiers decode
    /// and become the delivered notification's route block, alongside the payload `type`.
    func testALoginApprovalPayloadYieldsARouteBlock() throws {
        let payload = try XCTUnwrap(decode(
            #"{"type":"login-approval","title":"Sign-in request","body":"b","data":{"requestId":"poauth_x","did":"did:plc:abc","clientName":"App","origin":"https://a"},"pad":"  "}"#
        ))
        let route = try XCTUnwrap(NotifyRoute.userInfo(for: payload))
        XCTAssertEqual(route, ["type": "login-approval", "requestId": "poauth_x", "did": "did:plc:abc"])
        // Allowlist, not passthrough: clientName/origin render in the banner but never route.
        XCTAssertNil(route["clientName"])
        XCTAssertNil(route["origin"])
    }

    /// A payload without routing data — every pre-Phase-C payload — still renders, and
    /// contributes no route block at all.
    func testAPayloadWithoutDataRendersWithNoRoute() throws {
        let payload = try XCTUnwrap(decode(
            #"{"type":"ops_alert","title":"t","body":"b","pad":""}"#
        ))
        XCTAssertNil(payload.data)
        XCTAssertNil(NotifyRoute.userInfo(for: payload))
    }

    /// A `data` block this build doesn't understand degrades to "no route", never to a
    /// decode failure that would turn an authenticated banner into the unverified notice.
    func testUnrecognizedOrMalformedDataNeverFailsThePayload() throws {
        let unknownFields = try XCTUnwrap(decode(
            #"{"type":"x","title":"t","body":"b","data":{"claimAttemptId":"clm_1"},"pad":""}"#
        ))
        XCTAssertNil(NotifyRoute.userInfo(for: unknownFields))

        let wrongTypes = try XCTUnwrap(decode(
            #"{"type":"x","title":"t","body":"b","data":{"requestId":7,"did":["a"]},"pad":""}"#
        ))
        XCTAssertNil(NotifyRoute.userInfo(for: wrongTypes))

        let notAnObject = try XCTUnwrap(decode(
            #"{"type":"x","title":"t","body":"b","data":"nope","pad":""}"#
        ))
        XCTAssertNil(NotifyRoute.userInfo(for: notAnObject))
    }
}

final class NotifyBreadcrumbTests: XCTestCase {
    func testTheLogIsNewestFirstAndBounded() {
        var log = NotifyFailureLog.empty
        for index in 0..<(NotifyFailureLog.capacity + 5) {
            log = log.appending(NotifyFailure(at: "t\(index)", reason: "OPEN_FAILED", kid: index))
        }
        XCTAssertEqual(log.failures.count, NotifyFailureLog.capacity)
        XCTAssertEqual(log.failures.first?.kid, NotifyFailureLog.capacity + 4, "newest first")
        XCTAssertEqual(log.failures.last?.kid, 5, "the oldest entries are the ones dropped")
    }

    /// Fail-open, like the pin store: a damaged log must not cost the user the breadcrumb
    /// being recorded right now.
    func testACorruptOrForeignVersionLogReadsAsEmpty() {
        XCTAssertTrue(NotifyFailureLog.parse(Data("{not json".utf8)).failures.isEmpty)
        XCTAssertTrue(NotifyFailureLog.parse(nil).failures.isEmpty)
        let foreign = Data(#"{"version":99,"failures":[{"at":"t","reason":"OPEN_FAILED","kid":1}]}"#.utf8)
        XCTAssertTrue(NotifyFailureLog.parse(foreign).failures.isEmpty)
    }
}

final class PinnedSenderKeysTests: XCTestCase {
    /// Two instances both start their `kid` sequence at 1, and the push names no host — so
    /// every key under the incoming `kid` is a candidate, across every pinned host.
    func testCandidatesSpanEveryHost() {
        let pins = PinnedSenderKeys(version: 1, hosts: [
            "https://a.example.com": [PinnedSenderKey(kid: 1, publicKey: "did:key:zA")],
            "https://b.example.com": [PinnedSenderKey(kid: 1, publicKey: "did:key:zB"),
                                      PinnedSenderKey(kid: 2, publicKey: "did:key:zC")],
        ])
        XCTAssertEqual(Set(pins.candidates(for: 1)), ["did:key:zA", "did:key:zB"])
        XCTAssertEqual(pins.candidates(for: 2), ["did:key:zC"])
        XCTAssertTrue(pins.candidates(for: 3).isEmpty)
    }

    func testACorruptPinDocumentReadsAsEmpty() {
        XCTAssertTrue(PinnedSenderKeys.parse(Data("{nope".utf8)).hosts.isEmpty)
        XCTAssertTrue(PinnedSenderKeys.parse(nil).hosts.isEmpty)
    }
}
