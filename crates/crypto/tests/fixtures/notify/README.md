# Notification-relay HPKE fixtures

`hpke-notify-v1.json` pins the wire format of the v1 sealed notification envelope
(`crates/crypto/src/hpke.rs`, exercised by `tests/notify_hpke_vectors.rs`).

**Provenance: self-generated, not an external standard.** RFC 9180's appendix has no test
vector for the pinned suite — A.3 is DHKEM(P-256, HKDF-SHA256) + AES-**128**-GCM, whereas
CryptoKit's only P-256 suite (`P256_SHA256_AES_GCM_256`) forces AES-**256**-GCM. RFC
conformance of the primitive is covered by the `hpke` crate's own known-answer tests; these
fixtures exist to freeze *our* envelope: suite, `info` (`ezpds/notify/1`), empty `aad`, and
the SEC1 key/encapsulated-key encodings.

Keys are derived deterministically from fixed IKM via `DhP256HkdfSha256::derive_keypair`, so
they are test-only material and reproducible. `enc`/`ct` are not reproducible — HPKE
encapsulation is randomized — so the vectors are pinned as captured and verified by opening
them, never by re-sealing and comparing bytes.

Every value is unpadded base64url, matching the encoding used in the APNs envelope — except the
two private keys per vector, which are byte arrays. That is deliberate: a base64-encoded 32-byte
scalar is indistinguishable to a secret scanner from a real leaked credential, and the array form
avoids the finding without adding a scanner suppression that would also hide a genuine leak here
later.

Regenerating these vectors is a **wire-format change**: it invalidates any device or
CryptoKit test pinned to them, so do it only alongside a deliberate `info`-string/version
bump, never to make a failing test pass.

The wallet phase reads this same file from an on-device XCTest that opens each vector with
CryptoKit's `HPKE.Recipient`, cross-verifying the Rust and Apple implementations.
