// pattern: Functional Core

//! RFC 9421 HTTP Message Signatures as Atproto Spaces profiles them: the one `atproto-space`
//! signature that proves possession of the key a space credential is bound to (`cnf.kid`).
//!
//! Two shapes, nothing else:
//!
//! * **Delegation exchange** (`getSpaceCredential`): covers `("authorization")` and names its
//!   key in `keyid`. That keyid becomes the minted credential's `cnf.kid`.
//! * **Credential use** (every credential-authed read): covers
//!   `("authorization" "atproto-space-audience")`, in that order, and verifies against the
//!   credential's `cnf.kid`. The audience pins the request to one recipient, so replay against
//!   that same audience until the credential expires is allowed by spec — there is no nonce,
//!   timestamp, or per-request `jti`.
//!
//! The key is always a P-256 `did:key`, the signature a raw 64-byte `r‖s`, and either S is
//! accepted (unlike commit and PLC signatures, which are low-S only).
//!
//! The `Signature-Input` and `Signature` fields are parsed as full RFC 8941 structured fields
//! because the signature base embeds the *re-serialized* inner list: a lenient parse would
//! verify a different string than the client signed. Behaviour follows the reference
//! (`packages/space/src/http-signature.ts`, atproto `permissioned-data` branch), whose test
//! cases are ported below.

use axum::http::HeaderMap;
use base64::{
    alphabet,
    engine::{general_purpose::STANDARD, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine as _,
};
use common::{ApiError, ErrorCode};

/// The one signature label a space request carries.
pub const SIGNATURE_LABEL: &str = "atproto-space";
/// The only `alg` a space signature may declare (the parameter itself is optional).
pub const SIGNATURE_ALG: &str = "ecdsa-p256-sha256";
/// The header naming the DID a credential-authed request is addressed to.
pub const AUDIENCE_HEADER: &str = "atproto-space-audience";

/// Which of the two profile shapes a request must carry.
#[derive(Debug, Clone, Copy)]
pub(super) enum SignedFor<'a> {
    /// The delegation-token exchange: covers `authorization` alone, key named by `keyid`.
    Delegation,
    /// A credential-authed request: covers `authorization` then the audience, signed by
    /// `key_id` (the credential's `cnf.kid`), addressed to `audience`.
    Credential { key_id: &'a str, audience: &'a str },
}

/// Verify a delegation exchange's `atproto-space` signature and return the `did:key` that made
/// it. The one shape a route may check itself; a credential-use signature is checked only
/// inside `auth::space`, against the credential it is bound to.
pub fn verify_delegation_signature(headers: &HeaderMap) -> Result<String, ApiError> {
    verify_space_signature(headers, SignedFor::Delegation)
}

/// Verify the request's `atproto-space` signature and return the `did:key` that made it.
///
/// Every failure is `InvalidToken` (401): the caller has not proven possession of the key.
pub(super) fn verify_space_signature(
    headers: &HeaderMap,
    signed_for: SignedFor<'_>,
) -> Result<String, ApiError> {
    let invalid = |msg: &str| ApiError::new(ErrorCode::InvalidToken, msg.to_string());

    let (Some(input_field), Some(signature_field)) = (
        combined_field(headers, "signature-input"),
        combined_field(headers, "signature"),
    ) else {
        return Err(invalid("missing or malformed signature headers"));
    };
    let (Some(inputs), Some(signatures)) = (
        parse_dictionary(&input_field),
        parse_dictionary(&signature_field),
    ) else {
        return Err(invalid("missing or malformed signature headers"));
    };
    let (Some(Member::InnerList(components, params)), Some(Member::Item(signature))) = (
        lookup(&inputs, SIGNATURE_LABEL),
        lookup(&signatures, SIGNATURE_LABEL),
    ) else {
        return Err(invalid("missing or malformed atproto-space signature"));
    };
    let Bare::Bytes(signature_bytes) = &signature.bare else {
        return Err(invalid("missing or malformed atproto-space signature"));
    };
    if !signature.params.is_empty() {
        return Err(invalid("missing or malformed atproto-space signature"));
    }

    let expected: &[&str] = match signed_for {
        SignedFor::Delegation => &["authorization"],
        SignedFor::Credential { .. } => &["authorization", AUDIENCE_HEADER],
    };
    let covers_exactly = components.len() == expected.len()
        && components.iter().zip(expected).all(|(item, name)| {
            item.params.is_empty() && matches!(&item.bare, Bare::Str(s) if s == name)
        });
    if !covers_exactly {
        return Err(invalid(&format!(
            "signature must cover exactly {}, in order",
            expected
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(" ")
        )));
    }
    if let Some(alg) = param(params, "alg") {
        if !matches!(alg, Bare::Str(s) if s == SIGNATURE_ALG) {
            return Err(invalid("signature algorithm must be ecdsa-p256-sha256"));
        }
    }

    let keyid = param(params, "keyid");
    let signing_key = match signed_for {
        SignedFor::Delegation => match keyid {
            Some(Bare::Str(k)) => k.as_str(),
            _ => return Err(invalid("signature key must be a P-256 did:key")),
        },
        SignedFor::Credential { key_id, .. } => key_id,
    };
    let signing_key = crypto::DidKeyUri(signing_key.to_string());
    if !matches!(
        crypto::did_key_curve(&signing_key),
        Ok(crypto::DidKeyCurve::P256)
    ) {
        return Err(invalid("signature key must be a P-256 did:key"));
    }
    if let (SignedFor::Credential { key_id, .. }, Some(keyid)) = (signed_for, keyid) {
        if !matches!(keyid, Bare::Str(k) if k == key_id) {
            return Err(invalid("signature keyid does not match the credential key"));
        }
    }

    let authorization = single_field(headers, "authorization")
        .ok_or_else(|| invalid("request requires exactly one \"authorization\" field"))?;
    let audience = match signed_for {
        SignedFor::Delegation => None,
        SignedFor::Credential { audience, .. } => {
            let presented = single_field(headers, AUDIENCE_HEADER).ok_or_else(|| {
                invalid("request requires exactly one \"atproto-space-audience\" field")
            })?;
            if presented != audience {
                return Err(invalid("space audience does not match the request"));
            }
            Some(presented)
        }
    };

    let base = signature_base(
        authorization,
        audience,
        &serialize_inner_list(components, params),
    );
    let verified = <&[u8; 64]>::try_from(signature_bytes.as_slice())
        .ok()
        .is_some_and(|sig| {
            crypto::verify_p256_signature_any_s(&signing_key, base.as_bytes(), sig).is_ok()
        });
    if !verified {
        return Err(invalid("invalid HTTP message signature"));
    }
    Ok(signing_key.0)
}

/// The RFC 9421 §2.5 signature base for the profile's covered components.
fn signature_base(authorization: &str, audience: Option<&str>, signature_params: &str) -> String {
    let mut base = format!("\"authorization\": {authorization}\n");
    if let Some(audience) = audience {
        base.push_str(&format!("\"{AUDIENCE_HEADER}\": {audience}\n"));
    }
    base.push_str(&format!("\"@signature-params\": {signature_params}"));
    base
}

/// The value of a field that must appear exactly once, trimmed, non-empty.
fn single_field<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim_matches([' ', '\t']);
    (values.next().is_none() && !value.is_empty()).then_some(value)
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

// ── RFC 8941 structured fields (the subset the two fields need) ──────────────

#[derive(Debug, Clone, PartialEq)]
enum Bare {
    Integer(i64),
    /// Kept in its canonical serialized form (no leading/trailing zeros).
    Decimal(String),
    Str(String),
    Token(String),
    Bytes(Vec<u8>),
    Bool(bool),
}

type Params = Vec<(String, Bare)>;

#[derive(Debug, Clone, PartialEq)]
struct Item {
    bare: Bare,
    params: Params,
}

#[derive(Debug, Clone, PartialEq)]
enum Member {
    Item(Item),
    InnerList(Vec<Item>, Params),
}

fn lookup<'d>(dict: &'d [(String, Member)], key: &str) -> Option<&'d Member> {
    dict.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn param<'p>(params: &'p Params, key: &str) -> Option<&'p Bare> {
    params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Insert or overwrite in place — RFC 8941's ordered-map semantics for a repeated key.
fn upsert<V>(map: &mut Vec<(String, V)>, key: String, value: V) {
    match map.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = value,
        None => map.push((key, value)),
    }
}

/// RFC 8941 §4.2 (top level) + §4.2.2: a dictionary, or `None` if the field is malformed.
fn parse_dictionary(field: &str) -> Option<Vec<(String, Member)>> {
    let mut p = Parser {
        s: field.trim_matches(' ').as_bytes(),
        i: 0,
    };
    let mut dict = Vec::new();
    while !p.at_end() {
        let key = p.key()?;
        let member = if p.eat(b'=') {
            p.member()?
        } else {
            Member::Item(Item {
                bare: Bare::Bool(true),
                params: p.params()?,
            })
        };
        upsert(&mut dict, key, member);
        p.skip_ows();
        if p.at_end() {
            break;
        }
        if !p.eat(b',') {
            return None;
        }
        p.skip_ows();
        if p.at_end() {
            return None;
        }
    }
    Some(dict)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn at_end(&self) -> bool {
        self.i >= self.s.len()
    }
    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }
    fn eat(&mut self, c: u8) -> bool {
        let hit = self.peek() == Some(c);
        if hit {
            self.i += 1;
        }
        hit
    }
    fn skip_sp(&mut self) {
        while self.eat(b' ') {}
    }
    fn skip_ows(&mut self) {
        while self.eat(b' ') || self.eat(b'\t') {}
    }

    fn member(&mut self) -> Option<Member> {
        if self.peek() == Some(b'(') {
            self.inner_list()
        } else {
            self.item().map(Member::Item)
        }
    }

    fn inner_list(&mut self) -> Option<Member> {
        self.eat(b'(');
        let mut items = Vec::new();
        loop {
            self.skip_sp();
            if self.eat(b')') {
                return Some(Member::InnerList(items, self.params()?));
            }
            items.push(self.item()?);
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return None;
            }
        }
    }

    fn item(&mut self) -> Option<Item> {
        Some(Item {
            bare: self.bare()?,
            params: self.params()?,
        })
    }

    fn params(&mut self) -> Option<Params> {
        let mut params = Vec::new();
        while self.eat(b';') {
            self.skip_sp();
            let key = self.key()?;
            let value = if self.eat(b'=') {
                self.bare()?
            } else {
                Bare::Bool(true)
            };
            upsert(&mut params, key, value);
        }
        Some(params)
    }

    fn key(&mut self) -> Option<String> {
        let start = self.i;
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'*')) {
            return None;
        }
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')
        ) {
            self.i += 1;
        }
        Some(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn bare(&mut self) -> Option<Bare> {
        match self.peek()? {
            b'-' | b'0'..=b'9' => self.number(),
            b'"' => self.string(),
            b':' => self.bytes(),
            b'?' => {
                self.i += 1;
                match self.next()? {
                    b'0' => Some(Bare::Bool(false)),
                    b'1' => Some(Bare::Bool(true)),
                    _ => None,
                }
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'*' => self.token(),
            _ => None,
        }
    }

    /// RFC 8941 §4.2.4: an integer of ≤15 digits, or a decimal of ≤12.≤3 digits.
    fn number(&mut self) -> Option<Bare> {
        let negative = self.eat(b'-');
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let int = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if int.is_empty() {
            return None;
        }
        if !self.eat(b'.') {
            if int.len() > 15 {
                return None;
            }
            let n: i64 = int.parse().ok()?;
            return Some(Bare::Integer(if negative { -n } else { n }));
        }
        let frac_start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let frac = std::str::from_utf8(&self.s[frac_start..self.i]).ok()?;
        if int.len() > 12 || frac.is_empty() || frac.len() > 3 {
            return None;
        }
        let int = match int.trim_start_matches('0') {
            "" => "0",
            trimmed => trimmed,
        };
        let frac = match frac.trim_end_matches('0') {
            "" => "0",
            trimmed => trimmed,
        };
        let sign = if negative { "-" } else { "" };
        Some(Bare::Decimal(format!("{sign}{int}.{frac}")))
    }

    fn string(&mut self) -> Option<Bare> {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            match self.next()? {
                b'\\' => match self.next()? {
                    c @ (b'"' | b'\\') => out.push(c as char),
                    _ => return None,
                },
                b'"' => return Some(Bare::Str(out)),
                c @ 0x20..=0x7e => out.push(c as char),
                _ => return None,
            }
        }
    }

    fn token(&mut self) -> Option<Bare> {
        let start = self.i;
        self.i += 1;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c))
        {
            self.i += 1;
        }
        Some(Bare::Token(
            String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
        ))
    }

    fn bytes(&mut self) -> Option<Bare> {
        self.eat(b':');
        let start = self.i;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='))
        {
            self.i += 1;
        }
        let encoded = &self.s[start..self.i];
        if !self.eat(b':') {
            return None;
        }
        const LENIENT: GeneralPurpose = GeneralPurpose::new(
            &alphabet::STANDARD,
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
        );
        LENIENT.decode(encoded).ok().map(Bare::Bytes)
    }
}

/// RFC 8941 §4.1.1.1: the canonical serialization the signature base embeds.
fn serialize_inner_list(items: &[Item], params: &Params) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|item| serialize_bare(&item.bare) + &serialize_params(&item.params))
        .collect();
    format!("({}){}", items.join(" "), serialize_params(params))
}

fn serialize_params(params: &Params) -> String {
    params
        .iter()
        .map(|(key, value)| match value {
            Bare::Bool(true) => format!(";{key}"),
            other => format!(";{key}={}", serialize_bare(other)),
        })
        .collect()
}

fn serialize_bare(bare: &Bare) -> String {
    match bare {
        Bare::Integer(n) => n.to_string(),
        Bare::Decimal(d) => d.clone(),
        Bare::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Bare::Token(t) => t.clone(),
        Bare::Bytes(b) => format!(":{}:", STANDARD.encode(b)),
        Bare::Bool(b) => if *b { "?1" } else { "?0" }.to_string(),
    }
}

/// Sign a request the way a space client does: the `Signature-Input` and `Signature` header
/// values for `authorization` (and, for credential use, `audience`), signed by `sign` (a
/// 64-byte `r‖s` P-256 signer) under `key_id`.
#[cfg(test)]
pub(crate) fn sign_space_request(
    sign: impl FnOnce(&[u8]) -> Vec<u8>,
    key_id: &str,
    authorization: &str,
    audience: Option<&str>,
) -> (String, String) {
    let input = match audience {
        None => format!("(\"authorization\");keyid=\"{key_id}\""),
        Some(_) => format!("(\"authorization\" \"{AUDIENCE_HEADER}\")"),
    };
    let signature = sign(signature_base(authorization, audience, &input).as_bytes());
    (
        format!("{SIGNATURE_LABEL}={input}"),
        format!("{SIGNATURE_LABEL}=:{}:", STANDARD.encode(signature)),
    )
}

#[cfg(test)]
mod tests {
    //! Ported from the reference's `packages/space/src/http-signature.test.ts`.

    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    const AUTHORIZATION: &str = "Atproto-Space credential";
    const AUDIENCE: &str = "did:example:repo";
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
        /// Headers for a request signed under this key.
        fn headers(&self, authorization: &str, audience: Option<&str>) -> HeaderMap {
            let (input, signature) =
                sign_space_request(|b| self.sign(b), &self.id, authorization, audience);
            let mut h = headers(&[
                ("authorization", authorization),
                ("signature-input", &input),
                ("signature", &signature),
            ]);
            if let Some(audience) = audience {
                set(&mut h, AUDIENCE_HEADER, audience);
            }
            h
        }
        fn credential_headers(&self) -> HeaderMap {
            self.headers(AUTHORIZATION, Some(AUDIENCE))
        }
        fn as_credential(&self) -> SignedFor<'_> {
            SignedFor::Credential {
                key_id: &self.id,
                audience: AUDIENCE,
            }
        }
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
            .strip_prefix("atproto-space=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        STANDARD.decode(b64).unwrap()
    }

    fn set_signature(h: &mut HeaderMap, sig: &[u8]) {
        set(
            h,
            "signature",
            &format!("atproto-space=:{}:", STANDARD.encode(sig)),
        );
    }

    fn message(result: Result<String, ApiError>) -> String {
        let err = result.unwrap_err();
        assert_eq!(*err.code(), ErrorCode::InvalidToken);
        err.message().to_string()
    }

    #[test]
    fn signs_the_rfc_9421_signature_base_with_a_compact_p256_signature() {
        let key = Key::new();
        let (input, _) =
            sign_space_request(|b| key.sign(b), &key.id, AUTHORIZATION, Some(AUDIENCE));
        assert_eq!(
            input,
            "atproto-space=(\"authorization\" \"atproto-space-audience\")"
        );
        let h = key.credential_headers();
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": (\"authorization\" \"atproto-space-audience\")"
        );
        let sig: [u8; 64] = signature_bytes(&h).try_into().unwrap();
        crypto::verify_p256_signature(&crypto::DidKeyUri(key.id.clone()), base.as_bytes(), &sig)
            .unwrap();
        assert_eq!(
            verify_space_signature(&h, key.as_credential()).unwrap(),
            key.id
        );
    }

    #[test]
    fn signs_a_delegation_token_without_an_audience() {
        let key = Key::new();
        let h = key.headers("Bearer delegation", None);
        assert_eq!(
            get(&h, "signature-input"),
            format!("atproto-space=(\"authorization\");keyid=\"{}\"", key.id)
        );
        assert_eq!(
            verify_space_signature(&h, SignedFor::Delegation).unwrap(),
            key.id
        );
        let err = message(verify_space_signature(
            &h,
            SignedFor::Credential {
                key_id: &key.id,
                audience: AUDIENCE,
            },
        ));
        assert!(err.contains("atproto-space-audience"), "{err}");
    }

    #[test]
    fn accepts_high_s_as_well_as_low_s_signatures() {
        // P-256 group order n, big-endian.
        const N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let key = Key::new();
        let mut h = key.credential_headers();
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
        assert_eq!(
            verify_space_signature(&h, key.as_credential()).unwrap(),
            key.id
        );
    }

    #[test]
    fn accepts_delegation_signatures_with_an_optional_alg() {
        let key = Key::new();
        let input = format!(
            "(\"authorization\");keyid=\"{}\";alg=\"ecdsa-p256-sha256\"",
            key.id
        );
        let base = format!("\"authorization\": Bearer delegation\n\"@signature-params\": {input}");
        let sig = key.sign(base.as_bytes());
        let h = headers(&[
            ("authorization", "Bearer delegation"),
            ("signature-input", &format!("atproto-space={input}")),
            (
                "signature",
                &format!("atproto-space=:{}:", STANDARD.encode(sig)),
            ),
        ]);
        assert_eq!(
            verify_space_signature(&h, SignedFor::Delegation).unwrap(),
            key.id
        );
    }

    #[test]
    fn accepts_optional_credential_parameters_and_other_signature_labels() {
        let key = Key::new();
        let input = format!(
            "(\"authorization\" \"atproto-space-audience\");alg=\"ecdsa-p256-sha256\";keyid=\"{}\"",
            key.id
        );
        let base = format!(
            "\"authorization\": {AUTHORIZATION}\n\"atproto-space-audience\": {AUDIENCE}\n\"@signature-params\": {input}"
        );
        let sig = key.sign(base.as_bytes());
        let h = headers(&[
            ("authorization", AUTHORIZATION),
            (AUDIENCE_HEADER, AUDIENCE),
            (
                "signature-input",
                &format!("other=(\"authorization\");keyid=\"other\", atproto-space={input}"),
            ),
            (
                "signature",
                &format!("other=:YWJj:, atproto-space=:{}:", STANDARD.encode(sig)),
            ),
        ]);
        assert_eq!(
            verify_space_signature(&h, key.as_credential()).unwrap(),
            key.id
        );
    }

    #[test]
    fn a_dictionary_split_across_header_lines_is_one_field() {
        let key = Key::new();
        let mut h = key.credential_headers();
        let input = get(&h, "signature-input");
        set(&mut h, "signature-input", "other=(\"authorization\")");
        h.append("signature-input", HeaderValue::from_str(&input).unwrap());
        assert_eq!(
            verify_space_signature(&h, key.as_credential()).unwrap(),
            key.id
        );
    }

    #[test]
    fn rejects_a_changed_covered_field() {
        let key = Key::new();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = key.credential_headers();
            let changed = format!("{}-changed", get(&h, name));
            set(&mut h, name, &changed);
            let err = message(verify_space_signature(
                &h,
                SignedFor::Credential {
                    key_id: &key.id,
                    // The audience the request is checked against moves with the header, so
                    // this case reaches the signature rather than the audience comparison.
                    audience: if name == AUDIENCE_HEADER {
                        &changed
                    } else {
                        AUDIENCE
                    },
                },
            ));
            assert_eq!(err, "invalid HTTP message signature", "{name}");
        }
    }

    #[test]
    fn rejects_an_audience_other_than_the_one_the_request_is_for() {
        let key = Key::new();
        let h = key.credential_headers();
        let err = message(verify_space_signature(
            &h,
            SignedFor::Credential {
                key_id: &key.id,
                audience: "did:example:someone-else",
            },
        ));
        assert_eq!(err, "space audience does not match the request");
    }

    #[test]
    fn rejects_duplicate_covered_fields() {
        let key = Key::new();
        for name in ["authorization", AUDIENCE_HEADER] {
            let mut h = key.credential_headers();
            let value = get(&h, name);
            h.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(&value).unwrap(),
            );
            let err = message(verify_space_signature(&h, key.as_credential()));
            assert!(err.contains("exactly one"), "{name}: {err}");
        }
    }

    #[test]
    fn rejects_a_missing_field() {
        let key = Key::new();
        for name in [
            "authorization",
            AUDIENCE_HEADER,
            "signature-input",
            "signature",
        ] {
            let mut h = key.credential_headers();
            h.remove(name);
            message(verify_space_signature(&h, key.as_credential()));
        }
    }

    #[test]
    fn requires_the_audience_to_be_covered_by_the_signature() {
        let key = Key::new();
        let mut h = key.headers(AUTHORIZATION, None);
        set(&mut h, AUDIENCE_HEADER, AUDIENCE);
        let err = message(verify_space_signature(&h, key.as_credential()));
        assert!(err.contains("must cover"), "{err}");
    }

    #[test]
    fn rejects_another_signing_key() {
        let key = Key::new();
        let other = Key::new();
        let h = other.credential_headers();
        assert_eq!(
            message(verify_space_signature(&h, key.as_credential())),
            "invalid HTTP message signature"
        );
    }

    #[test]
    fn rejects_an_optional_keyid_that_differs_from_the_credential_key() {
        let key = Key::new();
        let other = Key::new();
        let mut h = key.credential_headers();
        let input = format!("{};keyid=\"{}\"", get(&h, "signature-input"), other.id);
        set(&mut h, "signature-input", &input);
        let err = message(verify_space_signature(&h, key.as_credential()));
        assert!(
            err.contains("keyid does not match the credential key"),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_missing_or_invalid_delegation_keyid() {
        let key = Key::new();
        for params in ["", ";keyid", ";keyid=123", ";keyid=\"not-a-key\""] {
            let mut h = key.headers("Bearer delegation", None);
            set(
                &mut h,
                "signature-input",
                &format!("atproto-space=(\"authorization\"){params}"),
            );
            message(verify_space_signature(&h, SignedFor::Delegation));
        }
    }

    #[test]
    fn rejects_any_other_set_of_covered_components() {
        let key = Key::new();
        for components in [
            "(\"atproto-space-audience\")",
            "(\"atproto-space-audience\" \"authorization\")",
            "(\"authorization\" \"atproto-space-audience\" \"content-type\")",
            "(\"authorization\" \"authorization\" \"atproto-space-audience\")",
            "(\"authorization\";sf \"atproto-space-audience\")",
            "not-a-list",
        ] {
            let mut h = key.credential_headers();
            set(
                &mut h,
                "signature-input",
                &format!("atproto-space={components}"),
            );
            let err = message(verify_space_signature(&h, key.as_credential()));
            assert!(
                err.contains("must cover exactly") || err.contains("missing or malformed"),
                "{components}: {err}"
            );
        }
    }

    #[test]
    fn rejects_credential_signatures_on_the_delegation_exchange() {
        let key = Key::new();
        let err = message(verify_space_signature(
            &key.credential_headers(),
            SignedFor::Delegation,
        ));
        assert!(err.contains("must cover exactly"), "{err}");
    }

    #[test]
    fn rejects_changed_signature_parameters() {
        let key = Key::new();
        let mut h = key.credential_headers();
        let input = format!("{};alg=\"ecdsa-p256-sha256\"", get(&h, "signature-input"));
        set(&mut h, "signature-input", &input);
        assert_eq!(
            message(verify_space_signature(&h, key.as_credential())),
            "invalid HTTP message signature"
        );
    }

    #[test]
    fn rejects_other_algorithms() {
        let key = Key::new();
        for (mut h, signed_for) in [
            (key.headers(AUTHORIZATION, None), SignedFor::Delegation),
            (key.credential_headers(), key.as_credential()),
        ] {
            let input = format!("{};alg=\"ecdsa-p384-sha384\"", get(&h, "signature-input"));
            set(&mut h, "signature-input", &input);
            let err = message(verify_space_signature(&h, signed_for));
            assert!(err.contains("algorithm"), "{err}");
        }
    }

    #[test]
    fn rejects_other_key_types() {
        let key = Key::new();
        let h = key.credential_headers();
        let err = message(verify_space_signature(
            &h,
            SignedFor::Credential {
                key_id: SECP256K1_KEY,
                audience: AUDIENCE,
            },
        ));
        assert!(err.contains("P-256"), "{err}");

        let mut h = key.headers(AUTHORIZATION, None);
        set(
            &mut h,
            "signature-input",
            &format!("atproto-space=(\"authorization\");keyid=\"{SECP256K1_KEY}\""),
        );
        let err = message(verify_space_signature(&h, SignedFor::Delegation));
        assert!(err.contains("P-256"), "{err}");
    }

    #[test]
    fn rejects_an_invalid_signature() {
        let key = Key::new();
        for signature in ["not-a-byte-sequence", ":YWJj:", ":!!!:"] {
            let mut h = key.credential_headers();
            set(&mut h, "signature", &format!("atproto-space={signature}"));
            message(verify_space_signature(&h, key.as_credential()));
        }
    }

    #[test]
    fn rejects_a_der_encoded_signature() {
        let key = Key::new();
        let mut h = key.credential_headers();
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
        message(verify_space_signature(&h, key.as_credential()));
    }

    #[test]
    fn structured_fields_reserialize_canonically() {
        // The signature base embeds the re-serialized inner list, so these must round-trip
        // to RFC 8941's canonical form, not to whatever spacing the client sent.
        let dict = parse_dictionary(
            "sig=(  \"a\"   \"b\";x=?0 );created=0012;d=1.50;t=tok/en;b=:YWJj:;f;s=\"q\\\"\\\\\"",
        )
        .unwrap();
        let Some(Member::InnerList(items, params)) = lookup(&dict, "sig") else {
            panic!("inner list expected");
        };
        assert_eq!(
            serialize_inner_list(items, params),
            "(\"a\" \"b\";x=?0);created=12;d=1.5;t=tok/en;b=:YWJj:;f;s=\"q\\\"\\\\\""
        );
        for malformed in [
            "sig=(\"a\"",
            "sig=(\"a\")x",
            "sig=1,",
            "Sig=1",
            "sig=1.2345",
            "sig=1234567890123456",
            "sig=\"\u{7f}\"",
        ] {
            assert!(parse_dictionary(malformed).is_none(), "{malformed}");
        }
    }
}
