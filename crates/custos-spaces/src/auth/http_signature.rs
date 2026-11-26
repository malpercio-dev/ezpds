// pattern: Functional Core

//! RFC 9421 HTTP Message Signatures as Atproto Spaces profiles them for a space credential: the
//! signature tagged `atproto-space-credential` that proves possession of the key a credential is
//! bound to (`cnf.kid`).
//!
//! It covers `("authorization" "atproto-space-audience")`, in that order, and verifies against
//! the credential's `cnf.kid`. The audience pins the request to one recipient, so replay against
//! that same audience until the credential expires is allowed by spec — there is no nonce,
//! timestamp, or per-request `jti`.
//!
//! The signature is selected by its `tag`, never by its label: labels carry no meaning (RFC 9421
//! §7.2.5), and clients sign under whatever label they like (the reference uses `sig`). Finding
//! it, the structured-field parse, and the signature base are `crypto::http_signature`'s, shared
//! with the MAC profiles. The key is always a P-256 `did:key`, the signature a raw 64-byte
//! `r‖s`, and either S is accepted (unlike commit and PLC signatures, which are low-S only).
//!
//! Behaviour follows the reference (`packages/space/src/http-signature.ts`, atproto
//! `permissioned-data` branch), whose test cases are ported below.

use axum::http::HeaderMap;
use common::{ApiError, ErrorCode};
use crypto::http_signature::{find_signature, signature_base, SignatureRequirements};
use crypto::sf::{BareItem, Item};

/// The `tag` a credential-use signature carries.
pub const SIGNATURE_TAG: &str = "atproto-space-credential";
/// The only `alg` a space signature may declare (the parameter itself is optional).
pub const SIGNATURE_ALG: &str = "ecdsa-p256-sha256";
/// The header naming the DID a credential-authed request is addressed to.
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";

/// The components a credential use covers, in order.
fn covered_components() -> Vec<Item> {
    ["authorization", AUDIENCE_HEADER]
        .map(|name| Item::new(BareItem::String(name.to_string())))
        .to_vec()
}

/// Verify the request's credential signature: tagged [`SIGNATURE_TAG`], made by `key_id` (the
/// credential's `cnf.kid`), over the request's `Authorization` and `Atproto-Space-Audience`.
/// Returns the audience it signed, for [`require_audience`] to compare.
///
/// Every failure is `BadSpaceSignature` (401), the reference's name.
pub(super) fn verify_credential_signature<'h>(
    headers: &'h HeaderMap,
    key_id: &str,
) -> Result<&'h str, ApiError> {
    let invalid = |msg: String| ApiError::new(ErrorCode::BadSpaceSignature, msg);

    let authorization = single_field(headers, "authorization")
        .ok_or_else(|| invalid("missing or malformed \"authorization\" field".into()))?;
    let presented = single_field(headers, AUDIENCE_HEADER)
        .filter(|value| common::is_valid_did(value))
        .ok_or_else(|| invalid(format!("missing or malformed \"{AUDIENCE_HEADER}\" field")))?;

    let components = covered_components();
    let found = find_signature(
        combined_field(headers, "signature-input").as_deref(),
        combined_field(headers, "signature").as_deref(),
        &SignatureRequirements {
            tag: SIGNATURE_TAG,
            components: components.clone(),
            alg: SIGNATURE_ALG,
            key_id,
        },
    )
    .map_err(|e| invalid(signature_error_message(e)))?;

    let signing_key = crypto::DidKeyUri(key_id.to_string());
    if !matches!(
        crypto::did_key_curve(&signing_key),
        Ok(crypto::DidKeyCurve::P256)
    ) {
        return Err(invalid("signature key must be a P-256 did:key".into()));
    }

    let base = signature_base(
        &components,
        &[authorization, presented],
        &found.signature_params,
    )
    .map_err(|e| invalid(signature_error_message(e)))?;
    let verified = <&[u8; 64]>::try_from(found.signature.as_slice())
        .ok()
        .is_some_and(|sig| {
            crypto::verify_p256_signature_any_s(&signing_key, base.as_bytes(), sig).is_ok()
        });
    if !verified {
        return Err(invalid("invalid HTTP message signature".into()));
    }
    Ok(presented)
}

/// The signed audience must be `audience`, the DID this request is for: `BadSpaceAudience`
/// (401) otherwise. Compared only once the signature verifies (and, in the seam, after the
/// revocation check), as the reference's handlers do, so a bad signature names the signature
/// whatever audience it claims.
pub(super) fn require_audience(presented: &str, audience: &str) -> Result<(), ApiError> {
    if presented != audience {
        return Err(ApiError::new(
            ErrorCode::BadSpaceAudience,
            "space audience does not match the request",
        ));
    }
    Ok(())
}

/// The codec's message without its error-kind prefix.
fn signature_error_message(e: crypto::CryptoError) -> String {
    match e {
        crypto::CryptoError::Space(msg) => msg,
        other => other.to_string(),
    }
}

/// The value of a field that must appear exactly once, non-empty.
fn single_field<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    (values.next().is_none() && !value.trim_matches([' ', '\t']).is_empty()).then_some(value)
}

/// A structured field's lines combined per RFC 9110 §5.3, so a dictionary split across
/// several header lines parses as one.
fn combined_field(headers: &HeaderMap, name: &str) -> Option<String> {
    let lines = headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().ok())
        .collect::<Option<Vec<_>>>()?;
    (!lines.is_empty()).then(|| lines.join(", "))
}

/// Sign a credential use the way a space client does: the `Signature-Input` and `Signature`
/// header values for `authorization` addressed to `audience`, signed by `sign` (a 64-byte
/// `r‖s` P-256 signer) under the reference's `sig` label.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn sign_credential_request(
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
    authorization: &str,
    audience: &str,
) -> (String, String) {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let input = format!("(\"authorization\" \"{AUDIENCE_HEADER}\");tag=\"{SIGNATURE_TAG}\"");
    let base = signature_base(&covered_components(), &[authorization, audience], &input)
        .unwrap_or_default();
    let signature = sign(base.as_bytes());
    (
        format!("sig={input}"),
        format!("sig=:{}:", STANDARD.encode(signature)),
    )
}

#[cfg(test)]
mod tests {
    //! Ported from the reference's `packages/space/src/http-signature.test.ts`.

    use super::*;
    use axum::http::{HeaderName, HeaderValue};
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const AUTHORIZATION: &str = "Atproto-Space-Credential credential";
    const AUDIENCE: &str = "did:example:repo";
    const SIGNATURE_INPUT: &str =
        "(\"authorization\" \"atproto-space-audience\");tag=\"atproto-space-credential\"";
    const SECP256K1_KEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

    struct Key {
        signer: repo_engine::CommitSigner,
        id: String,
    }

    impl Key {
        fn new() -> Self {
            let kp = crypto::generate_p256_keypair().unwrap();
            Self {
                signer: repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap(),
                id: kp.key_id.0,
            }
        }
        fn sign(&self, bytes: &[u8]) -> Vec<u8> {
            self.signer.sign(bytes)
        }
        fn headers(&self) -> HeaderMap {
            let (input, signature) =
                sign_credential_request(|b| self.sign(b), AUTHORIZATION, AUDIENCE);
            headers(&[
                ("authorization", AUTHORIZATION),
                (AUDIENCE_HEADER, AUDIENCE),
                ("signature-input", &input),
                ("signature", &signature),
            ])
        }
        fn verify(&self, h: &HeaderMap) -> Result<(), ApiError> {
            verify_for(h, &self.id, AUDIENCE)
        }
    }

    /// The seam's two steps together: the signature, then the audience it signed.
    fn verify_for(h: &HeaderMap, key_id: &str, audience: &str) -> Result<(), ApiError> {
        require_audience(verify_credential_signature(h, key_id)?, audience)
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        h
    }

    fn set(h: &mut HeaderMap, name: &str, value: &str) {
        h.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    fn get(h: &HeaderMap, name: &str) -> String {
        h.get(name).unwrap().to_str().unwrap().to_string()
    }

    fn signature_bytes(h: &HeaderMap) -> Vec<u8> {
        let field = get(h, "signature");
        let b64 = field
            .strip_prefix("sig=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        STANDARD.decode(b64).unwrap()
    }

    fn set_signature(h: &mut HeaderMap, sig: &[u8]) {
        set(h, "signature", &format!("sig=:{}:", STANDARD.encode(sig)));
    }

    /// A signed request whose `Signature-Input` is `params` under `label`.
    fn signed_with(key: &Key, label: &str, params: &str) -> HeaderMap {
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {params}"
        );
        let sig = key.sign(base.as_bytes());
        headers(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            ("signature-input", &format!("{label}={params}")),
            ("signature", &format!("{label}=:{}:", STANDARD.encode(sig))),
        ])
    }

    fn message(result: Result<(), ApiError>) -> String {
        let err = result.unwrap_err();
        assert_eq!(*err.code(), ErrorCode::BadSpaceSignature);
        assert_eq!(err.status_code(), 401);
        err.message().to_string()
    }

    #[test]
    fn signs_the_rfc_9421_base_with_a_compact_p256_signature() {
        let key = Key::new();
        let h = key.headers();
        assert_eq!(get(&h, "signature-input"), format!("sig={SIGNATURE_INPUT}"));
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {SIGNATURE_INPUT}"
        );
        let sig: [u8; 64] = signature_bytes(&h).try_into().unwrap();
        crypto::verify_p256_signature(&crypto::DidKeyUri(key.id.clone()), base.as_bytes(), &sig)
            .unwrap();
        key.verify(&h).unwrap();
    }

    #[test]
    fn accepts_a_high_s_signature() {
        // P-256 group order n, big-endian.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let key = Key::new();
        let mut h = key.headers();
        let mut sig = signature_bytes(&h);
        assert!(sig[32] < 0x80, "the signer emits low-S");
        // s' = n − s, big-endian subtraction with borrow.
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
            borrow = (d < 0) as i16;
            sig[32 + i] = d.rem_euclid(256) as u8;
        }
        set_signature(&mut h, &sig);
        key.verify(&h).unwrap();
    }

    #[test]
    fn finds_the_signature_by_its_tag_under_any_label_with_extra_parameters() {
        let key = Key::new();
        let params = format!(
            "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";created=1618884473;keyid=\"{}\";tag=\"atproto-space-credential\"",
            key.id
        );
        let mut h = signed_with(&key, "custom", &params);
        let (input, sig) = (get(&h, "signature-input"), get(&h, "signature"));
        set(
            &mut h,
            "signature-input",
            &format!("other=(\"authorization\");keyid=\"other\", {input}"),
        );
        set(&mut h, "signature", &format!("other=:YWJj:, {sig}"));
        key.verify(&h).unwrap();
        // The pre-tag label alone, with no tag, no longer identifies the signature.
        let untagged = signed_with(
            &key,
            "atproto-space",
            "(\"authorization\" \"atproto-space-audience\")",
        );
        assert!(message(key.verify(&untagged)).contains("with tag"));
    }

    #[test]
    fn ignores_whitespace_around_covered_values() {
        let key = Key::new();
        let mut h = key.headers();
        set(&mut h, "authorization", &format!(" {AUTHORIZATION}  "));
        key.verify(&h).unwrap();
    }

    #[test]
    fn a_dictionary_split_across_header_lines_is_one_field() {
        let key = Key::new();
        let mut h = key.headers();
        let input = get(&h, "signature-input");
        set(&mut h, "signature-input", "other=(\"authorization\")");
        h.append("signature-input", HeaderValue::from_str(&input).unwrap());
        key.verify(&h).unwrap();
    }

    #[test]
    fn rejects_a_changed_covered_field() {
        let key = Key::new();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = key.headers();
            let changed = format!("{}-changed", get(&h, name));
            set(&mut h, name, &changed);
            // The audience the request is checked against moves with the header, so this case
            // reaches the signature rather than the audience comparison.
            let audience = if name == AUDIENCE_HEADER {
                changed.as_str()
            } else {
                AUDIENCE
            };
            let err = message(verify_for(&h, &key.id, audience));
            assert_eq!(err, "invalid HTTP message signature", "{name}");
        }
    }

    #[test]
    fn rejects_an_audience_other_than_the_one_the_request_is_for() {
        let key = Key::new();
        let err = verify_for(&key.headers(), &key.id, "did:example:someone-else").unwrap_err();
        assert_eq!(*err.code(), ErrorCode::BadSpaceAudience);
        assert_eq!(err.status_code(), 401);
        assert_eq!(err.message(), "space audience does not match the request");
        // A signature that does not verify names the signature, whatever audience it claims.
        let other = Key::new();
        assert_eq!(
            message(verify_for(
                &other.headers(),
                &key.id,
                "did:example:someone-else",
            )),
            "invalid HTTP message signature"
        );
    }

    #[test]
    fn rejects_an_audience_that_is_not_one_did() {
        let key = Key::new();
        for audience in ["not-a-did", &format!("{AUDIENCE}, {AUDIENCE}")] {
            let mut h = key.headers();
            set(&mut h, AUDIENCE_HEADER, audience);
            assert_eq!(
                message(verify_for(&h, &key.id, AUDIENCE)),
                "missing or malformed \"atproto-space-audience\" field",
                "{audience}"
            );
        }
    }

    #[test]
    fn rejects_missing_or_multi_valued_fields() {
        let key = Key::new();
        for (name, expected) in [
            (
                "authorization",
                "missing or malformed \"authorization\" field",
            ),
            (
                AUDIENCE_HEADER,
                "missing or malformed \"atproto-space-audience\" field",
            ),
            ("signature-input", "missing or malformed signature headers"),
            ("signature", "missing or malformed signature headers"),
        ] {
            let mut h = key.headers();
            h.remove(name);
            assert_eq!(message(key.verify(&h)), expected, "{name} missing");
        }
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = key.headers();
            let value = get(&h, name);
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(&value).unwrap(),
            );
            assert!(
                message(key.verify(&h)).contains("missing or malformed"),
                "{name} repeated"
            );
        }
    }

    #[test]
    fn rejects_no_tag_or_another_tag() {
        let key = Key::new();
        for params in ["", ";tag=\"other\""] {
            let mut h = key.headers();
            set(
                &mut h,
                "signature-input",
                &format!(
                    "sig={}",
                    SIGNATURE_INPUT.replace(";tag=\"atproto-space-credential\"", params)
                ),
            );
            assert_eq!(
                message(key.verify(&h)),
                "missing or malformed signature with tag \"atproto-space-credential\""
            );
        }
    }

    #[test]
    fn rejects_more_than_one_signature_with_the_tag() {
        let key = Key::new();
        let mut h = key.headers();
        for name in ["signature-input", "signature"] {
            let value = get(&h, name);
            let other = value.replacen("sig=", "other=", 1);
            set(&mut h, name, &format!("{value}, {other}"));
        }
        assert_eq!(
            message(key.verify(&h)),
            "more than one signature with tag \"atproto-space-credential\""
        );
    }

    #[test]
    fn rejects_any_other_set_of_covered_components() {
        let key = Key::new();
        for components in [
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
        ] {
            let mut h = key.headers();
            set(
                &mut h,
                "signature-input",
                &format!("sig={components};tag=\"atproto-space-credential\""),
            );
            assert!(
                message(key.verify(&h)).contains("must cover exactly"),
                "{components}"
            );
        }
    }

    #[test]
    fn rejects_signature_input_that_does_not_parse() {
        let key = Key::new();
        let mut h = key.headers();
        set(&mut h, "signature-input", "sig=(\"authorization\"");
        assert_eq!(
            message(key.verify(&h)),
            "missing or malformed signature headers"
        );
    }

    #[test]
    fn rejects_changed_signature_parameters() {
        let key = Key::new();
        let mut h = key.headers();
        let input = format!("{};alg=\"ecdsa-p256-sha256\"", get(&h, "signature-input"));
        set(&mut h, "signature-input", &input);
        assert_eq!(message(key.verify(&h)), "invalid HTTP message signature");
    }

    #[test]
    fn rejects_another_algorithm() {
        let key = Key::new();
        let mut h = key.headers();
        let input = format!("{};alg=\"ecdsa-p384-sha384\"", get(&h, "signature-input"));
        set(&mut h, "signature-input", &input);
        assert!(message(key.verify(&h)).contains("algorithm"));
    }

    #[test]
    fn rejects_a_keyid_other_than_the_credential_key() {
        let key = Key::new();
        let other = Key::new();
        let mut h = key.headers();
        let input = format!("{};keyid=\"{}\"", get(&h, "signature-input"), other.id);
        set(&mut h, "signature-input", &input);
        assert!(message(key.verify(&h)).contains("keyid does not match"));
    }

    #[test]
    fn rejects_another_signing_key() {
        let key = Key::new();
        let other = Key::new();
        assert_eq!(
            message(key.verify(&other.headers())),
            "invalid HTTP message signature"
        );
    }

    #[test]
    fn rejects_a_credential_key_that_is_not_p256() {
        let key = Key::new();
        let err = message(verify_for(&key.headers(), SECP256K1_KEY, AUDIENCE));
        assert!(err.contains("P-256"), "{err}");
    }

    #[test]
    fn rejects_a_signature_that_is_not_a_byte_sequence() {
        let key = Key::new();
        for signature in ["not-a-byte-sequence", ":!!!:"] {
            let mut h = key.headers();
            set(&mut h, "signature", &format!("sig={signature}"));
            message(key.verify(&h));
        }
        let mut h = key.headers();
        set(&mut h, "signature", "sig=:YWJj:");
        assert_eq!(message(key.verify(&h)), "invalid HTTP message signature");
    }

    #[test]
    fn rejects_a_der_encoded_signature() {
        let key = Key::new();
        let mut h = key.headers();
        let compact = signature_bytes(&h);
        let mut der_body = Vec::new();
        for half in [&compact[..32], &compact[32..]] {
            let mut int = half.to_vec();
            if int[0] & 0x80 != 0 {
                int.insert(0, 0);
            }
            der_body.extend([0x02, int.len() as u8]);
            der_body.extend(int);
        }
        let mut der = vec![0x30, der_body.len() as u8];
        der.extend(der_body);
        set_signature(&mut h, &der);
        message(key.verify(&h));
    }
}
