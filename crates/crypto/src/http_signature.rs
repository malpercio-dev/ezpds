// pattern: Functional Core

//! RFC 9421 HTTP message signatures as Atproto Spaces uses them: the signature base, finding a
//! signature by its `tag`, and the two MAC profiles a repo host answers a syncer's
//! `Accept-Signature` with.
//!
//! A Spaces MAC is an RFC 9421 signature with `alg = hmac-sha256`, keyed by the per-request
//! secret from [`crate::hpke::space_mac_secret`]. It covers one header, flagged `sf`, that
//! describes what the response returned: `Atproto-Space-Commit` (the commit's fields) or
//! `Atproto-Space-Record` (a record's uri and cid). Because the key is shared, a leaked
//! response proves nothing to a third party.
//!
//! Labels carry no meaning (RFC 9421 §7.2.5): a verifier always selects the signature by its
//! `tag`, never by label, and a host answers under whichever label was requested.
//!
//! This mirrors the reference `packages/space/src/{http-signature,mac}.ts`; the reference
//! wins where it and the proposal text disagree.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CryptoError;
use crate::sf::{
    param, parse_dictionary, serialize_dictionary, serialize_inner_list, serialize_item, BareItem,
    Dictionary, InnerList, Item, Member,
};

/// RFC 9421 algorithm name of a Spaces MAC.
pub const MAC_ALG: &str = "hmac-sha256";

/// The label this crate requests a MAC under. Only a request default: verification finds the
/// MAC by its tag.
pub const MAC_LABEL: &str = "mac";

/// The two MAC profiles. Each profile's tag is also the name of the header its MAC covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacProfile {
    Commit,
    Record,
}

impl MacProfile {
    /// The `tag` parameter naming this profile, and the covered header's (lowercase) name.
    pub fn tag(self) -> &'static str {
        match self {
            MacProfile::Commit => "atproto-space-commit",
            MacProfile::Record => "atproto-space-record",
        }
    }

    /// The one component a MAC under this profile covers: its header, flagged `sf`.
    fn components(self) -> Vec<Item> {
        vec![Item {
            bare: BareItem::String(self.tag().to_string()),
            params: vec![("sf".to_string(), BareItem::Boolean(true))],
        }]
    }
}

// The parameters a host fulfills. A syncer uses a fresh key share per request, so `created`,
// `expires` and `nonce` would add nothing.
const MAC_REQUEST_PARAMS: [&str; 3] = ["keyid", "tag", "alg"];

fn mac_err(msg: impl Into<String>) -> CryptoError {
    CryptoError::Space(msg.into())
}

// ── RFC 9421 core ─────────────────────────────────────────────────────────────────────

/// The signature base (RFC 9421 §2.5) for a signature covering `components`, whose values are
/// given in order, under the serialized `signature_params`. Values are trimmed of surrounding
/// whitespace, as RFC 9421 §2.1 requires of a field value.
pub fn signature_base(
    components: &[Item],
    values: &[&str],
    signature_params: &str,
) -> Result<String, CryptoError> {
    if components.len() != values.len() {
        return Err(mac_err("one value is required per covered component"));
    }
    let mut lines = Vec::with_capacity(components.len() + 1);
    for (component, value) in components.iter().zip(values) {
        lines.push(format!("{}: {}", serialize_item(component)?, value.trim()));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    Ok(lines.join("\n"))
}

/// A covered-component list without parameters, e.g. `("authorization" "atproto-space-audience")`.
pub fn format_components(components: &[Item]) -> Result<String, CryptoError> {
    serialize_inner_list(&InnerList {
        items: components.to_vec(),
        params: Vec::new(),
    })
}

/// The members of a `Signature-Input` or `Accept-Signature` dictionary whose `tag` is `tag`.
pub fn members_with_tag<'a>(dict: &'a Dictionary, tag: &str) -> Vec<(&'a str, &'a InnerList)> {
    dict.iter()
        .filter_map(|(label, member)| match member {
            Member::InnerList(list)
                if param(&list.params, "tag") == Some(&BareItem::String(tag.to_string())) =>
            {
                Some((label.as_str(), list))
            }
            _ => None,
        })
        .collect()
}

/// What an application requires of the signature it verifies (RFC 9421 §3.2.1).
#[derive(Debug, Clone)]
pub struct SignatureRequirements<'a> {
    /// Identifies the signature among any others on the message.
    pub tag: &'a str,
    /// Exactly the components it must cover, in order.
    pub components: Vec<Item>,
    /// The algorithm it must use, if its `alg` parameter names one.
    pub alg: &'a str,
    /// The key it must use, if its `keyid` parameter names one.
    pub key_id: &'a str,
}

/// A signature found by [`find_signature`]: its serialized parameters (what the base's
/// `@signature-params` line carries) and its raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSignature {
    pub signature_params: String,
    pub signature: Vec<u8>,
}

/// Find the one signature tagged `required.tag` in a message's `Signature-Input` and
/// `Signature` field values, and check it meets `required`. Other parameters, like
/// `created`, are covered by the signature but not interpreted.
pub fn find_signature(
    input_field: Option<&str>,
    signature_field: Option<&str>,
    required: &SignatureRequirements<'_>,
) -> Result<FoundSignature, CryptoError> {
    let malformed = || mac_err("missing or malformed signature headers");
    let (Some(input_field), Some(signature_field)) = (input_field, signature_field) else {
        return Err(malformed());
    };
    let inputs = parse_dictionary(input_field).map_err(|_| malformed())?;
    let signatures = parse_dictionary(signature_field).map_err(|_| malformed())?;

    let tag = required.tag;
    let tagged = members_with_tag(&inputs, tag);
    if tagged.len() > 1 {
        return Err(mac_err(format!(
            "more than one signature with tag \"{tag}\""
        )));
    }
    let missing = || mac_err(format!("missing or malformed signature with tag \"{tag}\""));
    let (label, params) = *tagged.first().ok_or_else(missing)?;
    let signature = signature_bytes(&signatures, label).ok_or_else(missing)?;

    let expected = format_components(&required.components)?;
    if format_components(&params.items)? != expected {
        return Err(mac_err(format!(
            "signature must cover exactly {expected}, in order"
        )));
    }
    let string_param = |name, want: &str| match param(&params.params, name) {
        None => true,
        Some(v) => *v == BareItem::String(want.to_string()),
    };
    if !string_param("alg", required.alg) {
        return Err(mac_err(format!(
            "signature algorithm must be {}",
            required.alg
        )));
    }
    if !string_param("keyid", required.key_id) {
        return Err(mac_err("signature keyid does not match the expected key"));
    }
    Ok(FoundSignature {
        signature_params: serialize_inner_list(params)?,
        signature,
    })
}

// The signature bytes under `label` in a `Signature` dictionary, if well formed: a bare byte
// sequence with no parameters.
fn signature_bytes(signatures: &Dictionary, label: &str) -> Option<Vec<u8>> {
    match signatures.iter().find(|(k, _)| k == label).map(|(_, m)| m) {
        Some(Member::Item(Item {
            bare: BareItem::Bytes(b),
            params,
        })) if params.is_empty() => Some(b.clone()),
        _ => None,
    }
}

// ── MAC requests ──────────────────────────────────────────────────────────────────────

fn request_params(profile: MacProfile, key_share: &str) -> InnerList {
    InnerList {
        items: profile.components(),
        params: vec![
            ("keyid".to_string(), BareItem::String(key_share.to_string())),
            (
                "tag".to_string(),
                BareItem::String(profile.tag().to_string()),
            ),
        ],
    }
}

/// The syncer's `Accept-Signature` value asking for a MAC keyed by the secret for
/// `key_share` (its ephemeral `did:key`), e.g.
/// `mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-commit"`.
pub fn format_mac_request(profile: MacProfile, key_share: &str) -> Result<String, CryptoError> {
    Ok(format!(
        "{MAC_LABEL}={}",
        serialize_inner_list(&request_params(profile, key_share))?
    ))
}

/// A MAC request as the host reads it from `Accept-Signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacRequest {
    /// The label the syncer requested; the host answers under it.
    pub label: String,
    /// The syncer's ephemeral key share (HPKE `enc`) as a `did:key`.
    pub key_share: String,
    /// The requested parameters, serialized. The host's MAC uses them exactly as given.
    pub signature_params: String,
}

/// Find the MAC requested for `profile` in an `Accept-Signature` value, checking the host can
/// fulfill it. Members with other tags are ignored, so this is `Ok(None)` when none is for
/// `profile` (or the header is absent).
pub fn parse_mac_request(
    value: Option<&str>,
    profile: MacProfile,
) -> Result<Option<MacRequest>, CryptoError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let requests =
        parse_dictionary(value).map_err(|_| mac_err("malformed Accept-Signature header"))?;
    let tag = profile.tag();
    let tagged = members_with_tag(&requests, tag);
    let (label, params) = match tagged.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        _ => {
            return Err(mac_err(format!(
                "more than one MAC requested with tag \"{tag}\""
            )))
        }
    };

    let expected = format_components(&profile.components())?;
    if format_components(&params.items)? != expected {
        return Err(mac_err(format!("MAC must cover exactly {expected}")));
    }
    if let Some((name, _)) = params
        .params
        .iter()
        .find(|(name, _)| !MAC_REQUEST_PARAMS.contains(&name.as_str()))
    {
        return Err(mac_err(format!("unsupported MAC parameter: {name}")));
    }
    match param(&params.params, "alg") {
        None => {}
        Some(BareItem::String(alg)) if alg == MAC_ALG => {}
        Some(_) => return Err(mac_err(format!("MAC algorithm must be {MAC_ALG}"))),
    }
    let key_share = match param(&params.params, "keyid") {
        Some(BareItem::String(k)) if is_valid_did(k) => k.clone(),
        _ => return Err(mac_err("missing or malformed keyid")),
    };
    Ok(Some(MacRequest {
        label: label.to_string(),
        key_share,
        signature_params: serialize_inner_list(params)?,
    }))
}

// The atproto DID syntax check the reference applies to `keyid` (`isValidDid`).
fn is_valid_did(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    did.len() <= 2048
        && !method.is_empty()
        && method.bytes().all(|c| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:%-".contains(&c))
        && id
            .bytes()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

// ── MAC responses ─────────────────────────────────────────────────────────────────────

/// The fields of an `Atproto-Space-Commit` header, in the order the reference emits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitMacFields<'a> {
    pub ver: i64,
    pub repo: &'a str,
    pub space: &'a str,
    pub rev: &'a str,
    pub data: &'a [u8],
}

/// The response headers a MAC adds: the covered header (named by the profile's tag) and the
/// `Signature-Input` / `Signature` pair over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacHeaders {
    pub covered_name: &'static str,
    pub covered: String,
    pub signature_input: String,
    pub signature: String,
}

fn string_member(key: &str, value: &str) -> (String, Member) {
    (
        key.to_string(),
        Member::Item(Item::new(BareItem::String(value.to_string()))),
    )
}

fn commit_header(commit: &CommitMacFields<'_>) -> Dictionary {
    vec![
        (
            "ver".to_string(),
            Member::Item(Item::new(BareItem::Integer(commit.ver))),
        ),
        string_member("repo", commit.repo),
        string_member("space", commit.space),
        string_member("rev", commit.rev),
        (
            "data".to_string(),
            Member::Item(Item::new(BareItem::Bytes(commit.data.to_vec()))),
        ),
    ]
}

fn record_header(uri: &str, cid: &str) -> Dictionary {
    vec![string_member("uri", uri), string_member("cid", cid)]
}

fn hmac_sha256(secret: &[u8; 32], base: &str) -> Result<Hmac<Sha256>, CryptoError> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| mac_err("invalid MAC key"))?;
    mac.update(base.as_bytes());
    Ok(mac)
}

fn mac_headers(
    profile: MacProfile,
    covered: Dictionary,
    request: &MacRequest,
    secret: &[u8; 32],
) -> Result<MacHeaders, CryptoError> {
    let covered = serialize_dictionary(&covered)?;
    let base = signature_base(
        &profile.components(),
        &[&covered],
        &request.signature_params,
    )?;
    let tag = hmac_sha256(secret, &base)?.finalize().into_bytes();
    let signature = serialize_dictionary(&vec![(
        request.label.clone(),
        Member::Item(Item::new(BareItem::Bytes(tag.to_vec()))),
    )])?;
    Ok(MacHeaders {
        covered_name: profile.tag(),
        covered,
        signature_input: format!("{}={}", request.label, request.signature_params),
        signature,
    })
}

/// The headers answering a commit MAC request.
pub fn commit_mac_headers(
    commit: &CommitMacFields<'_>,
    request: &MacRequest,
    secret: &[u8; 32],
) -> Result<MacHeaders, CryptoError> {
    mac_headers(MacProfile::Commit, commit_header(commit), request, secret)
}

/// The headers answering a record MAC request for the record at `uri` with `cid`.
pub fn record_mac_headers(
    uri: &str,
    cid: &str,
    request: &MacRequest,
    secret: &[u8; 32],
) -> Result<MacHeaders, CryptoError> {
    mac_headers(MacProfile::Record, record_header(uri, cid), request, secret)
}

// ── MAC verification (syncer side) ────────────────────────────────────────────────────

/// The response header values a MAC is checked against.
#[derive(Debug, Clone, Copy)]
pub struct MacResponse<'a> {
    pub covered: Option<&'a str>,
    pub signature_input: Option<&'a str>,
    pub signature: Option<&'a str>,
}

// Check the MAC for `profile`, returning the covered header's parsed fields.
fn verify_mac(
    profile: MacProfile,
    key_share: &str,
    secret: &[u8; 32],
    response: &MacResponse<'_>,
) -> Result<Dictionary, CryptoError> {
    let components = profile.components();
    let found = find_signature(
        response.signature_input,
        response.signature,
        &SignatureRequirements {
            tag: profile.tag(),
            components: components.clone(),
            alg: MAC_ALG,
            key_id: key_share,
        },
    )?;
    let name = profile.tag();
    let fields = response
        .covered
        .ok_or_else(|| mac_err(format!("missing or malformed {name} header")))
        .and_then(|v| {
            parse_dictionary(v).map_err(|_| mac_err(format!("malformed {name} header")))
        })?;
    // The `sf` flag covers the header as re-serialized from its parsed form.
    let base = signature_base(
        &components,
        &[&serialize_dictionary(&fields)?],
        &found.signature_params,
    )?;
    hmac_sha256(secret, &base)?
        .verify_slice(&found.signature)
        .map_err(|_| mac_err("MAC does not match"))?;
    Ok(fields)
}

/// Verify a commit MAC, and that the `Atproto-Space-Commit` header it covers describes
/// `commit`.
pub fn verify_commit_mac(
    commit: &CommitMacFields<'_>,
    key_share: &str,
    secret: &[u8; 32],
    response: &MacResponse<'_>,
) -> Result<(), CryptoError> {
    let fields = verify_mac(MacProfile::Commit, key_share, secret, response)?;
    if !same_bare_items(&fields, &commit_header(commit)) {
        return Err(mac_err("commit does not match its MAC"));
    }
    Ok(())
}

/// Verify a record MAC, and that the `Atproto-Space-Record` header it covers names `uri` and
/// `cid`.
pub fn verify_record_mac(
    uri: &str,
    cid: &str,
    key_share: &str,
    secret: &[u8; 32],
    response: &MacResponse<'_>,
) -> Result<(), CryptoError> {
    let fields = verify_mac(MacProfile::Record, key_share, secret, response)?;
    if !same_bare_items(&fields, &record_header(uri, cid)) {
        return Err(mac_err("record does not match its MAC"));
    }
    Ok(())
}

// Every expected member is present in `fields` with the same bare value, ignoring
// parameters and any extra members — the reference compares field by field the same way.
fn same_bare_items(fields: &Dictionary, expected: &Dictionary) -> bool {
    expected.iter().all(|(key, want)| {
        let got = fields.iter().find(|(k, _)| k == key).map(|(_, m)| m);
        matches!((got, want), (Some(Member::Item(a)), Member::Item(b)) if a.bare == b.bare)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_SHARE: &str = "did:key:zDnaExample";
    const SPACE: &str = "at:space/did:example:space/app.bsky.group/test";
    const CID_A: &str = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244";
    const SECRET: [u8; 32] = [7u8; 32];

    fn uri() -> String {
        format!("{SPACE}/did:example:alice/app.bsky.feed.post/1")
    }

    const DATA: [u8; 32] = [1u8; 32];
    const COMMIT: CommitMacFields<'static> = CommitMacFields {
        ver: 1,
        repo: "did:example:alice",
        space: SPACE,
        rev: "3kbcq3p7ad400",
        data: &DATA,
    };

    fn commit_params() -> String {
        format_mac_request(MacProfile::Commit, KEY_SHARE)
            .unwrap()
            .trim_start_matches("mac=")
            .to_string()
    }

    fn request(profile: MacProfile) -> MacRequest {
        let header = format_mac_request(profile, KEY_SHARE).unwrap();
        parse_mac_request(Some(&header), profile).unwrap().unwrap()
    }

    fn response(h: &MacHeaders) -> MacResponse<'_> {
        MacResponse {
            covered: Some(&h.covered),
            signature_input: Some(&h.signature_input),
            signature: Some(&h.signature),
        }
    }

    #[test]
    fn formats_the_accept_signature_header_for_each_profile() {
        assert_eq!(
            format_mac_request(MacProfile::Commit, KEY_SHARE).unwrap(),
            r#"mac=("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit""#
        );
        assert_eq!(
            format_mac_request(MacProfile::Record, KEY_SHARE).unwrap(),
            r#"mac=("atproto-space-record";sf);keyid="did:key:zDnaExample";tag="atproto-space-record""#
        );
    }

    #[test]
    fn finds_the_request_by_tag_under_any_label() {
        let header = format!(
            r#"other=("content-digest");tag="other", m={}"#,
            commit_params()
        );
        let req = parse_mac_request(Some(&header), MacProfile::Commit)
            .unwrap()
            .unwrap();
        assert_eq!(req.label, "m");
        assert_eq!(req.key_share, KEY_SHARE);
        assert_eq!(req.signature_params, commit_params());

        assert_eq!(
            parse_mac_request(Some(&header), MacProfile::Record).unwrap(),
            None
        );
        assert_eq!(parse_mac_request(None, MacProfile::Commit).unwrap(), None);
    }

    #[test]
    fn accepts_an_explicit_hmac_alg() {
        let header = format!(
            r#"{};alg="hmac-sha256""#,
            format_mac_request(MacProfile::Commit, KEY_SHARE).unwrap()
        );
        assert!(parse_mac_request(Some(&header), MacProfile::Commit)
            .unwrap()
            .is_some());
    }

    #[test]
    fn rejects_requests_the_host_cannot_fulfill() {
        let p = commit_params();
        for (header, message) in [
            (format!("a={p}, b={p}"), "more than one MAC"),
            (
                format!(
                    r#"mac=("atproto-space-commit");keyid="{KEY_SHARE}";tag="atproto-space-commit""#
                ),
                "must cover exactly",
            ),
            (
                format!(
                    r#"mac=("atproto-space-commit";sf "authorization");keyid="{KEY_SHARE}";tag="atproto-space-commit""#
                ),
                "must cover exactly",
            ),
            (
                r#"mac=("atproto-space-commit";sf);tag="atproto-space-commit""#.to_string(),
                "keyid",
            ),
            (
                r#"mac=("atproto-space-commit";sf);keyid="key-1";tag="atproto-space-commit""#
                    .to_string(),
                "keyid",
            ),
            (
                format!("{p};created=1"),
                "unsupported MAC parameter: created",
            ),
            (format!(r#"mac={p};alg="hmac-sha512""#), "algorithm"),
            ("mac=(".to_string(), "malformed"),
        ] {
            let header = if header.starts_with("mac=") || header.starts_with("a=") {
                header
            } else {
                format!("mac={header}")
            };
            let err = parse_mac_request(Some(&header), MacProfile::Commit)
                .unwrap_err()
                .to_string();
            assert!(err.contains(message), "{header}: {err}");
        }
    }

    #[test]
    fn covers_the_commit_header_under_the_requested_parameters() {
        let req = parse_mac_request(
            Some(&format!("sig1={}", commit_params())),
            MacProfile::Commit,
        )
        .unwrap()
        .unwrap();
        let h = commit_mac_headers(&COMMIT, &req, &SECRET).unwrap();
        let covered = format!(
            r#"ver=1, repo="did:example:alice", space="{SPACE}", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:"#
        );
        assert_eq!(h.covered_name, "atproto-space-commit");
        assert_eq!(h.covered, covered);
        assert_eq!(h.signature_input, format!("sig1={}", commit_params()));

        let base = format!(
            "\"atproto-space-commit\";sf: {covered}\n\"@signature-params\": {}",
            commit_params()
        );
        let tag = hmac_sha256(&SECRET, &base).unwrap().finalize().into_bytes();
        assert_eq!(
            h.signature,
            serialize_dictionary(&vec![(
                "sig1".into(),
                Member::Item(Item::new(BareItem::Bytes(tag.to_vec())))
            )])
            .unwrap()
        );
    }

    #[test]
    fn verifies_under_the_same_secret_only() {
        let h = commit_mac_headers(&COMMIT, &request(MacProfile::Commit), &SECRET).unwrap();
        verify_commit_mac(&COMMIT, KEY_SHARE, &SECRET, &response(&h)).unwrap();
        let err = verify_commit_mac(&COMMIT, KEY_SHARE, &[8u8; 32], &response(&h)).unwrap_err();
        assert!(err.to_string().contains("MAC does not match"));
    }

    #[test]
    fn rejects_a_commit_with_another_field() {
        let h = commit_mac_headers(&COMMIT, &request(MacProfile::Commit), &SECRET).unwrap();
        let other_data = [2u8; 32];
        for other in [
            CommitMacFields { ver: 2, ..COMMIT },
            CommitMacFields {
                repo: "did:example:bob",
                ..COMMIT
            },
            CommitMacFields {
                space: "at://other",
                ..COMMIT
            },
            CommitMacFields {
                rev: "3kbcq3p7ad401",
                ..COMMIT
            },
            CommitMacFields {
                data: &other_data,
                ..COMMIT
            },
        ] {
            let err = verify_commit_mac(&other, KEY_SHARE, &SECRET, &response(&h)).unwrap_err();
            assert!(err.to_string().contains("commit does not match its MAC"));
        }
    }

    #[test]
    fn rejects_a_tampered_header_and_ignores_insignificant_whitespace() {
        let h = commit_mac_headers(&COMMIT, &request(MacProfile::Commit), &SECRET).unwrap();
        let tampered = h.covered.replace("3kbcq3p7ad400", "3kbcq3p7ad401");
        let err = verify_commit_mac(
            &CommitMacFields {
                rev: "3kbcq3p7ad401",
                ..COMMIT
            },
            KEY_SHARE,
            &SECRET,
            &MacResponse {
                covered: Some(&tampered),
                ..response(&h)
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("MAC does not match"));

        let spaced = h.covered.replace(", ", ",   ");
        verify_commit_mac(
            &COMMIT,
            KEY_SHARE,
            &SECRET,
            &MacResponse {
                covered: Some(&spaced),
                ..response(&h)
            },
        )
        .unwrap();
    }

    #[test]
    fn accepts_a_host_mac_with_parameters_added_and_reordered() {
        let params = format!(
            r#"("atproto-space-commit";sf);tag="atproto-space-commit";created=1700000000;keyid="{KEY_SHARE}""#
        );
        let req = MacRequest {
            label: "mac".into(),
            key_share: KEY_SHARE.into(),
            signature_params: params,
        };
        let h = commit_mac_headers(&COMMIT, &req, &SECRET).unwrap();
        verify_commit_mac(&COMMIT, KEY_SHARE, &SECRET, &response(&h)).unwrap();

        // A keyid naming another key is refused even with a valid MAC.
        let err =
            verify_commit_mac(&COMMIT, "did:key:zDnaOther", &SECRET, &response(&h)).unwrap_err();
        assert!(err.to_string().contains("keyid does not match"));
    }

    #[test]
    fn record_mac_covers_uri_and_cid_and_is_not_a_commit_mac() {
        let uri = uri();
        let h = record_mac_headers(&uri, CID_A, &request(MacProfile::Record), &SECRET).unwrap();
        assert_eq!(h.covered, format!(r#"uri="{uri}", cid="{CID_A}""#));
        verify_record_mac(&uri, CID_A, KEY_SHARE, &SECRET, &response(&h)).unwrap();
        assert!(
            verify_record_mac(&format!("{uri}2"), CID_A, KEY_SHARE, &SECRET, &response(&h))
                .is_err()
        );
        assert!(verify_record_mac(&uri, "bafyother", KEY_SHARE, &SECRET, &response(&h)).is_err());
        assert!(verify_commit_mac(&COMMIT, KEY_SHARE, &SECRET, &response(&h)).is_err());
    }

    #[test]
    fn find_signature_rejects_ambiguous_or_malformed_signatures() {
        let h = commit_mac_headers(&COMMIT, &request(MacProfile::Commit), &SECRET).unwrap();
        let req = SignatureRequirements {
            tag: "atproto-space-commit",
            components: MacProfile::Commit.components(),
            alg: MAC_ALG,
            key_id: KEY_SHARE,
        };
        let twice_in = format!(
            "{}, {}",
            h.signature_input,
            h.signature_input.replacen("mac=", "other=", 1)
        );
        let twice_sig = format!(
            "{}, {}",
            h.signature,
            h.signature.replacen("mac=", "other=", 1)
        );
        assert!(find_signature(Some(&twice_in), Some(&twice_sig), &req)
            .unwrap_err()
            .to_string()
            .contains("more than one"));
        assert!(find_signature(Some(&h.signature_input), Some("mac=not-bytes"), &req).is_err());
        assert!(find_signature(Some(&h.signature_input), Some("mac=:YWJj:;p"), &req).is_err());
        assert!(find_signature(None, Some(&h.signature), &req).is_err());
        assert!(find_signature(Some("mac=(\"x\""), Some(&h.signature), &req).is_err());
    }

    #[test]
    fn did_syntax() {
        for ok in [
            "did:key:zDnaExample",
            "did:plc:abc",
            "did:web:example.com%3A8080",
        ] {
            assert!(is_valid_did(ok), "{ok}");
        }
        for bad in [
            "key-1",
            "did:",
            "did::x",
            "did:Key:x",
            "did:key:",
            "did:key:x%",
            "did:key:a b",
        ] {
            assert!(!is_valid_did(bad), "{bad}");
        }
    }
}
