//! Self-minted Spaces MAC vectors, **unconfirmed against the reference** — see the fixture's
//! `status`/`comment`. They freeze this crate's RFC 9421 MAC output end to end (HPKE export →
//! request parsing → signature base → HMAC) so drift surfaces as a failing test; the interop
//! scenario against a running reference host is what confirms them.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code: a panic is the failure signal

use crypto::http_signature::{
    commit_mac_headers, parse_mac_request, record_mac_headers, signature_base, verify_commit_mac,
    verify_record_mac, CommitMacFields, MacProfile, MacResponse,
};
use crypto::sf::{parse_dictionary, Member};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    status: String,
    kem: Kem,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kem {
    enc_hex: String,
    kem_private_key_bytes: Vec<u8>,
    key_share: String,
    shared_secret_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Commit {
    ver: i64,
    repo: String,
    space: String,
    rev: String,
    data_hex: String,
}

#[derive(Deserialize)]
struct Record {
    uri: String,
    cid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    name: String,
    profile: String,
    commit: Option<Commit>,
    record: Option<Record>,
    accept_signature: String,
    covered_header: String,
    signature_base: String,
    signature_input: String,
    signature: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/space/mac-vectors-unconfirmed.json")).unwrap()
}

#[test]
fn fixture_is_marked_unconfirmed() {
    assert!(fixture().status.starts_with("UNCONFIRMED"));
}

#[test]
fn the_secret_chains_from_the_reference_kem_vector() {
    let kem = fixture().kem;
    let sk: [u8; 32] = kem.kem_private_key_bytes.as_slice().try_into().unwrap();
    let secret = crypto::space_mac_secret(&unhex(&kem.enc_hex), &sk).unwrap();
    assert_eq!(secret.to_vec(), unhex(&kem.shared_secret_hex));

    // The key share a syncer sends is that same `enc`, as a did:key.
    let compressed = crypto::p256_public_key_from_did_key(&kem.key_share).unwrap();
    assert_eq!(crypto::space_mac_secret(&compressed, &sk).unwrap(), secret);
}

#[test]
fn every_vector_reproduces_and_verifies() {
    let f = fixture();
    let secret: [u8; 32] = unhex(&f.kem.shared_secret_hex).try_into().unwrap();
    for v in &f.vectors {
        let profile = match v.profile.as_str() {
            "commit" => MacProfile::Commit,
            _ => MacProfile::Record,
        };
        let request = parse_mac_request(Some(&v.accept_signature), profile)
            .unwrap()
            .expect("request for the profile");
        assert_eq!(request.key_share, f.kem.key_share, "{}", v.name);

        let data;
        let headers = match (&v.commit, &v.record) {
            (Some(c), _) => {
                data = unhex(&c.data_hex);
                let fields = CommitMacFields {
                    ver: c.ver,
                    repo: &c.repo,
                    space: &c.space,
                    rev: &c.rev,
                    data: &data,
                };
                let h = commit_mac_headers(&fields, &request, &secret).unwrap();
                let response = MacResponse {
                    covered: Some(&h.covered),
                    signature_input: Some(&h.signature_input),
                    signature: Some(&h.signature),
                };
                verify_commit_mac(&fields, &request.key_share, &secret, &response).unwrap();
                h
            }
            (None, Some(r)) => {
                let h = record_mac_headers(&r.uri, &r.cid, &request, &secret).unwrap();
                let response = MacResponse {
                    covered: Some(&h.covered),
                    signature_input: Some(&h.signature_input),
                    signature: Some(&h.signature),
                };
                verify_record_mac(&r.uri, &r.cid, &request.key_share, &secret, &response).unwrap();
                h
            }
            (None, None) => panic!("{}: vector has neither commit nor record", v.name),
        };

        assert_eq!(headers.covered, v.covered_header, "{}", v.name);
        assert_eq!(headers.signature_input, v.signature_input, "{}", v.name);
        assert_eq!(headers.signature, v.signature, "{}", v.name);

        // The fixture's signature base is the exact string the MAC is computed over.
        let Member::InnerList(params) = &parse_dictionary(&v.signature_input).unwrap()[0].1 else {
            panic!("{}: signature input is an inner list", v.name);
        };
        let base = signature_base(
            &params.items,
            &[&v.covered_header],
            &request.signature_params,
        )
        .unwrap();
        assert_eq!(base, v.signature_base, "{}", v.name);
    }
}
