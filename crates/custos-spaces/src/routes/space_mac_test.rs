// pattern: Imperative Shell
//
// End-to-end coverage of the MACs on the four space reads (`space_mac`): a test syncer holding a
// space credential asks each read for a MAC with a throwaway key and verifies it using only
// public material (the writer's `#atproto_kem` key from its DID document); the crypto crate's
// minted vectors run through the real handlers; and the refusals and the unpublished-key rule.
// Driven through the real router (the `space_routes_test.rs` convention).

use axum::body::Body;
use axum::http::{self, HeaderMap, Request, StatusCode};
use axum::response::Response;
use crypto::http_signature::{
    format_mac_request, verify_commit_mac, verify_record_mac, CommitMacFields, MacProfile,
    MacResponse,
};
use custos_core::CoreState;
use tower::ServiceExt;

use crate::auth::space::{mint_space_credential, unix_now};
use crate::space_record_write::{
    apply_space_writes, SpaceWriteAction, SpaceWriteAdmission, SpaceWriteOp,
};
use crate::test_support::{access_jwt, body_json, state_with_master_key, test_app, SpaceSigKey};
use custos_core::space_uri::parse_space_ref;

const ALICE: &str = "did:plc:alicemacaaaaaaaaaaaaaaaa";
const AUTHORITY: &str = "did:plc:macauthorityaaaaaaaaaaa";
const SPACE: &str = "at://did:plc:macauthorityaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

/// Alice, with a published KEM key, has written one record into a space whose authority is
/// elsewhere; a syncer holds that authority's credential for the space.
struct Fixture {
    state: CoreState,
    key: SpaceSigKey,
    credential: String,
}

async fn setup() -> Fixture {
    let state = state_with_master_key().await;
    crate::test_support::seed_account_with_repo(&state.db, ALICE).await;
    write(&state).await;

    let authority = crypto::generate_p256_keypair().unwrap();
    let multibase = authority.key_id.0.strip_prefix("did:key:").unwrap();
    custos_db::dids::seed_did_document(
        &state.db,
        AUTHORITY,
        serde_json::json!({
            "id": AUTHORITY,
            "verificationMethod": [{
                "id": format!("{AUTHORITY}#atproto"),
                "type": "Multikey",
                "controller": AUTHORITY,
                "publicKeyMultibase": multibase,
            }],
        }),
    )
    .await;
    let signer = repo_engine::CommitSigner::from_bytes(&authority.private_key_bytes).unwrap();
    let key = SpaceSigKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        AUTHORITY,
        &parse_space_ref(SPACE).unwrap(),
        key.key_id(),
        unix_now().unwrap(),
    );
    Fixture {
        state,
        key,
        credential,
    }
}

async fn write(state: &CoreState) {
    apply_space_writes(
        state,
        &parse_space_ref(SPACE).unwrap(),
        ALICE,
        &[SpaceWriteOp {
            action: SpaceWriteAction::Create,
            collection: COLLECTION.to_string(),
            rkey: "aaa".to_string(),
            value: Some(serde_json::json!({ "text": "hello" })),
        }],
        SpaceWriteAdmission::Active,
    )
    .await
    .unwrap();
}

/// What a syncer can learn without this host's help: the `#atproto_kem` key Alice's DID
/// document publishes.
async fn published_kem_key(state: &CoreState) -> String {
    let doc = custos_db::dids::get_did_document(&state.db, ALICE)
        .await
        .unwrap()
        .unwrap();
    custos_core::kem::published_kem_key(&doc).unwrap().0
}

/// The four reads, with the profile each answers under.
fn reads() -> [(&'static str, MacProfile); 4] {
    [
        ("getLatestCommit", MacProfile::Commit),
        ("listRepoOps", MacProfile::Commit),
        ("getRepo", MacProfile::Commit),
        ("getRecord", MacProfile::Record),
    ]
}

fn read_path(method: &str) -> String {
    let mut path = format!("/xrpc/com.atproto.space.{method}?space={SPACE}&repo={ALICE}");
    if method == "getRecord" {
        path.push_str(&format!("&collection={COLLECTION}&rkey=aaa"));
    }
    path
}

fn syncer_read(f: &Fixture, method: &str, accept: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(http::Method::GET)
        .uri(read_path(method));
    let headers = b.headers_mut().unwrap();
    headers.extend(f.key.credential_headers(&f.credential, ALICE));
    if let Some(accept) = accept {
        headers.insert("accept-signature", accept.parse().unwrap());
    }
    b.body(Body::empty()).unwrap()
}

fn owner_read(state: &CoreState, method: &str, accept: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(read_path(method))
        .header(
            "Authorization",
            format!("Bearer {}", access_jwt(&state.jwt_secret, ALICE)),
        )
        .header("accept-signature", accept)
        .body(Body::empty())
        .unwrap()
}

async fn send(state: &CoreState, request: Request<Body>) -> Response {
    test_app(state.clone()).oneshot(request).await.unwrap()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).map(|v| v.to_str().unwrap())
}

fn mac_response<'a>(headers: &'a HeaderMap, profile: MacProfile) -> MacResponse<'a> {
    MacResponse {
        covered: header(headers, profile.tag()),
        signature_input: header(headers, "signature-input"),
        signature: header(headers, "signature"),
    }
}

fn lex_bytes(value: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value["$bytes"].as_str().unwrap())
        .unwrap()
}

/// The commit a read returned, as the syncer reads it from the body.
#[derive(serde::Deserialize)]
struct Commit {
    ver: i64,
    repo: String,
    space: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

impl Commit {
    fn from_json(commit: &serde_json::Value) -> Self {
        Commit {
            ver: commit["ver"].as_i64().unwrap(),
            repo: commit["repo"].as_str().unwrap().to_string(),
            space: commit["space"].as_str().unwrap().to_string(),
            rev: commit["rev"].as_str().unwrap().to_string(),
            data: lex_bytes(&commit["data"]),
        }
    }

    fn fields(&self) -> CommitMacFields<'_> {
        CommitMacFields {
            ver: self.ver,
            repo: &self.repo,
            space: &self.space,
            rev: &self.rev,
            data: &self.data,
        }
    }
}

/// Verify the MAC `response` carries for `method` under `key_share` and `secret`, against what
/// its body says it returned.
async fn verify(method: &str, response: Response, key_share: &str, secret: &[u8; 32]) {
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    if method == "getRecord" {
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        verify_record_mac(
            body["uri"].as_str().unwrap(),
            body["cid"].as_str().unwrap(),
            key_share,
            secret,
            &mac_response(&headers, MacProfile::Record),
        )
        .unwrap_or_else(|e| panic!("{method}: {e}"));
        return;
    }
    let commit = if method == "getRepo" {
        let car = repo_engine::import_space_car(&bytes).await.unwrap();
        serde_ipld_dagcbor::from_slice::<Commit>(&car.commit).unwrap()
    } else {
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        Commit::from_json(&body["commit"])
    };
    assert_eq!(commit.repo, ALICE);
    assert_eq!(commit.space, SPACE);
    verify_commit_mac(
        &commit.fields(),
        key_share,
        secret,
        &mac_response(&headers, MacProfile::Commit),
    )
    .unwrap_or_else(|e| panic!("{method}: {e}"));
}

/// The syncer's journey on each read: a fresh throwaway key against the published KEM key, an
/// `Accept-Signature` naming it, and a MAC that verifies over what the body returned.
#[tokio::test]
async fn a_syncer_verifies_the_mac_on_each_read() {
    let f = setup().await;
    let kem_key = published_kem_key(&f.state).await;

    for (method, profile) in reads() {
        let (key_share, secret) = crypto::space_mac_encapsulate(&kem_key).unwrap();
        let accept = format_mac_request(profile, &key_share).unwrap();
        let response = send(&f.state, syncer_read(&f, method, Some(&accept))).await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        let headers = response.headers();
        assert_eq!(
            header(headers, "vary"),
            Some("Accept-Signature"),
            "{method}"
        );

        verify(method, response, &key_share, &secret).await;
    }
}

/// A MAC keyed for one throwaway key does not verify under another's secret: the MAC is bound
/// to the request that asked for it.
#[tokio::test]
async fn a_mac_verifies_only_for_the_key_share_that_requested_it() {
    let f = setup().await;
    let kem_key = published_kem_key(&f.state).await;
    let (key_share, _) = crypto::space_mac_encapsulate(&kem_key).unwrap();
    let (_, other_secret) = crypto::space_mac_encapsulate(&kem_key).unwrap();

    let accept = format_mac_request(MacProfile::Commit, &key_share).unwrap();
    let response = send(&f.state, syncer_read(&f, "getLatestCommit", Some(&accept))).await;
    let headers = response.headers().clone();
    let body = body_json(response).await;
    let commit = Commit::from_json(&body["commit"]);
    assert!(verify_commit_mac(
        &commit.fields(),
        &key_share,
        &other_secret,
        &mac_response(&headers, MacProfile::Commit),
    )
    .is_err());
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    kem: VectorKem,
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorKem {
    kem_private_key_bytes: Vec<u8>,
    key_share: String,
    shared_secret_hex: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    name: String,
    profile: String,
    accept_signature: String,
    signature_input: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The crypto crate's minted vectors through the real handlers: with the vectors' KEM key as
/// Alice's published key, each vector's `Accept-Signature` is answered under exactly its
/// signature parameters, and the MAC verifies under the vectors' shared secret. An owner may ask
/// for a MAC too.
#[tokio::test]
async fn the_minted_vectors_pass_through_the_handlers() {
    let v: Vectors = serde_json::from_str(include_str!(
        "../../../crypto/tests/fixtures/space/mac-vectors-unconfirmed.json"
    ))
    .unwrap();
    let sk: [u8; 32] = v.kem.kem_private_key_bytes.as_slice().try_into().unwrap();
    let secret: [u8; 32] = unhex(&v.kem.shared_secret_hex).try_into().unwrap();

    let state = state_with_master_key().await;
    custos_core::test_support::seed_account_with_repo(&state.db, ALICE).await;
    let kp = crypto::p256_keypair_from_secret(&sk).unwrap();
    let kem_key = custos_db::kem_keys::KemKey {
        key_id: kp.key_id.to_string(),
        public_key: kp.public_key.clone(),
        private_key_encrypted: crypto::encrypt_private_key(
            &sk,
            &custos_core::test_support::test_master_key(),
        )
        .unwrap(),
    };
    custos_db::kem_keys::insert_active_kem_key(&state.db, ALICE, &kem_key)
        .await
        .unwrap();
    let mut doc = serde_json::json!({ "id": ALICE });
    custos_core::test_support::with_kem_method(&mut doc, ALICE, &kem_key.key_id);
    custos_db::dids::upsert_did_document(&state.db, ALICE, &doc)
        .await
        .unwrap();
    write(&state).await;

    for vector in &v.vectors {
        let method = match vector.profile.as_str() {
            "commit" => "getLatestCommit",
            _ => "getRecord",
        };
        let response = send(&state, owner_read(&state, method, &vector.accept_signature)).await;
        assert_eq!(response.status(), StatusCode::OK, "{}", vector.name);
        assert_eq!(
            header(response.headers(), "signature-input"),
            Some(vector.signature_input.as_str()),
            "{}",
            vector.name
        );
        verify(method, response, &v.kem.key_share, &secret).await;
    }
}

/// A space-credential read must ask for a MAC, and a request the host cannot answer is
/// `InvalidSpaceMac` whoever sends it; the refusal still varies on `Accept-Signature`.
#[tokio::test]
async fn missing_or_malformed_mac_requests_are_invalid_space_mac() {
    let f = setup().await;
    let not_p256 = format_mac_request(MacProfile::Commit, "did:web:example.com").unwrap();
    let wrong_alg = "mac=(\"atproto-space-commit\";sf);keyid=\"did:key:zDnaexCXCyeFWXGnCUesVu6KucACKmUDm6i3M5fghGuy1jnch\";tag=\"atproto-space-commit\";alg=\"ed25519\"";

    for (method, _) in reads() {
        let response = send(&f.state, syncer_read(&f, method, None)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method}");
        assert_eq!(header(response.headers(), "vary"), Some("Accept-Signature"));
        assert_eq!(
            body_json(response).await["error"],
            "InvalidSpaceMac",
            "{method}"
        );
    }
    for accept in ["mac=(", not_p256.as_str(), wrong_alg] {
        let response = send(&f.state, syncer_read(&f, "getLatestCommit", Some(accept))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{accept}");
        assert_eq!(
            body_json(response).await["error"],
            "InvalidSpaceMac",
            "{accept}"
        );

        let response = send(&f.state, owner_read(&f.state, "getLatestCommit", accept)).await;
        assert_eq!(
            body_json(response).await["error"],
            "InvalidSpaceMac",
            "{accept}"
        );
    }

    // A request for the other profile is not a request for this one.
    let record_only = format_mac_request(
        MacProfile::Record,
        &crypto::space_mac_encapsulate(&published_kem_key(&f.state).await)
            .unwrap()
            .0,
    )
    .unwrap();
    let response = send(
        &f.state,
        syncer_read(&f, "getLatestCommit", Some(&record_only)),
    )
    .await;
    assert_eq!(body_json(response).await["error"], "InvalidSpaceMac");
}

/// An account whose DID document does not publish its KEM key is read without a MAC: no
/// syncer could verify one.
#[tokio::test]
async fn an_unpublished_kem_key_serves_reads_without_a_mac() {
    let f = setup().await;
    let kem_key = published_kem_key(&f.state).await;
    custos_db::dids::upsert_did_document(&f.state.db, ALICE, &serde_json::json!({ "id": ALICE }))
        .await
        .unwrap();

    for (method, profile) in reads() {
        let (key_share, _) = crypto::space_mac_encapsulate(&kem_key).unwrap();
        let accept = format_mac_request(profile, &key_share).unwrap();
        let response = send(&f.state, syncer_read(&f, method, Some(&accept))).await;
        assert_eq!(response.status(), StatusCode::OK, "{method}");
        for name in [profile.tag(), "signature-input", "signature"] {
            assert!(
                response.headers().get(name).is_none(),
                "{method}: {name} without a published KEM key"
            );
        }
    }
}
