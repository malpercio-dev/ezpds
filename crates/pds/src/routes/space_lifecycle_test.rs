// pattern: Imperative Shell
//
// Account-lifecycle and migration coverage for the permissioned-space surface, driven through
// the real router. Two halves that share one fixture set, because they share one question —
// which account states may touch a space repo:
//
//   * lifecycle — a moderation state (suspension/takedown) closes the whole space surface;
//     self-service deactivation closes only writes, keeping the migration window open;
//     the space *host* stops answering a syncer's credential the moment its authority stops
//     being an active account.
//   * migration — `com.atproto.space.getRepo` on the source feeds `/v1/space/import-repo` on
//     the destination, and the imported repo has to hash to the digest the source published.
//
// Routes may not import one another, so these cross-route journeys live here.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use tower::ServiceExt;

use crate::app::AppState;
use crate::auth::space::{mint_space_credential, unix_now};
use crate::db::dids::seed_did_document;
use crate::routes::test_utils::{
    access_jwt, body_json, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
    DpopProofKey,
};
use crate::space_uri::parse_space_ref;

const DID: &str = "did:plc:spacelifecycleaaaaaaaaa";
const SPACE: &str = "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

/// A grant covering exactly this space and collection, for every record verb plus `read_self`.
const GRANT: &str =
    "atproto space:org.example.bucket?authority=did:plc:authorityaaaaaaaaaaaaaaa&skey=main\
&collection=org.example.note&action=create&action=update&action=delete&action=read_self";

async fn setup() -> AppState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, DID).await;
    state
}

fn post(uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(http::Method::POST)
        .uri(format!("/xrpc/{uri}"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/{uri}"))
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn create_body(rkey: &str, text: &str) -> serde_json::Value {
    serde_json::json!({
        "space": SPACE,
        "repo": DID,
        "collection": COLLECTION,
        "rkey": rkey,
        "record": {"text": text},
    })
}

async fn send(state: &AppState, request: Request<Body>) -> StatusCode {
    crate::app::app(state.clone())
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// Put `did` into one lifecycle state by setting the column that derives it.
async fn set_lifecycle(state: &AppState, did: &str, column: &str) {
    sqlx::query(&format!(
        "UPDATE accounts SET {column} = datetime('now') WHERE did = ?"
    ))
    .bind(did)
    .execute(&state.db)
    .await
    .unwrap();
}

// ── lifecycle ────────────────────────────────────────────────────────────────

/// A moderation state closes the whole space surface — reads and writes alike — for the
/// account's own credential, exactly as it closes the public one. Every account-credential
/// space route funnels through one seam, so a write, a repo read, and the delegation-token mint
/// stand for the rest — the last of which reaches the gate by its own call, not through the seam.
#[tokio::test]
async fn a_moderation_state_closes_the_account_credential_space_surface() {
    for column in ["taken_down_at", "suspended_at"] {
        let state = setup().await;
        let token = scoped_access_jwt(&state.jwt_secret, DID, GRANT);

        // Baseline: the surface works before the flag lands.
        assert_eq!(
            send(
                &state,
                post(
                    "com.atproto.space.createRecord",
                    &token,
                    create_body("a", "x")
                )
            )
            .await,
            StatusCode::OK,
            "{column}: precondition"
        );

        set_lifecycle(&state, DID, column).await;

        assert_eq!(
            send(
                &state,
                post(
                    "com.atproto.space.createRecord",
                    &token,
                    create_body("b", "y")
                )
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "{column}: write"
        );
        assert_eq!(
            send(
                &state,
                get(
                    &format!("com.atproto.space.listRecords?space={SPACE}&repo={DID}&collection={COLLECTION}"),
                    &token,
                ),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "{column}: repo read"
        );
        assert_eq!(
            send(
                &state,
                get(
                    &format!("com.atproto.space.getDelegationToken?space={SPACE}"),
                    &token
                ),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "{column}: delegation token"
        );
    }
}

/// Self-service deactivation is the migration window, not a moderation state: the account keeps
/// reading its own space repos (migration tooling enumerates them with `listSpaces`) and loses
/// only the ability to write new records through the ordinary routes.
#[tokio::test]
async fn deactivation_keeps_reads_open_and_closes_ordinary_writes() {
    let state = setup().await;
    // A legacy full session, so every assertion below is about lifecycle alone — an OAuth grant
    // narrow enough to name one space cannot satisfy an unfiltered `listSpaces` anyway, and that
    // is a scope question with its own coverage.
    let token = access_jwt(&state.jwt_secret, DID);
    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.space.createRecord",
                &token,
                create_body("a", "x")
            )
        )
        .await,
        StatusCode::OK
    );

    set_lifecycle(&state, DID, "deactivated_at").await;

    assert_eq!(
        send(&state, get("com.atproto.space.listSpaces", &token)).await,
        StatusCode::OK,
        "a deactivated account must still be able to enumerate what it has to migrate"
    );
    assert_eq!(
        send(
            &state,
            get(
                &format!("com.atproto.space.listRecords?space={SPACE}&repo={DID}&collection={COLLECTION}"),
                &token,
            ),
        )
        .await,
        StatusCode::OK,
        "and to read the records it is migrating"
    );
    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.space.createRecord",
                &token,
                create_body("b", "y")
            )
        )
        .await,
        StatusCode::FORBIDDEN,
        "but an ordinary write must still be refused"
    );
}

/// The space-host arm is one notch stricter than the owner's own: a syncer holding a valid,
/// correctly-proofed credential stops being served the moment the space's authority is no
/// longer an active account. `SpaceNotFound`, never `SpaceDeleted` — the deletion signal is
/// durable and a suspension is not.
#[tokio::test]
async fn a_credential_stops_being_served_when_the_authority_is_not_active() {
    let state = state_with_master_key().await;
    let kp = seed_account_with_repo(&state.db, DID).await;
    let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
    seed_did_document(
        &state.db,
        DID,
        serde_json::json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#atproto"), "type": "Multikey", "controller": DID, "publicKeyMultibase": multibase },
                { "id": format!("{DID}#atproto_space"), "type": "Multikey", "controller": DID, "publicKeyMultibase": multibase },
            ],
        }),
    )
    .await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let own_space = format!("at://{DID}/space/org.example.bucket/main");
    let owner = access_jwt(&state.jwt_secret, DID);
    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.simplespace.createSpace",
                &owner,
                serde_json::json!({
                    "type": "org.example.bucket",
                    "skey": "main",
                    "policy": {"$type": "com.atproto.simplespace.defs#publicPolicy"},
                    "appAccess": {"$type": "com.atproto.simplespace.defs#open"},
                }),
            ),
        )
        .await,
        StatusCode::OK
    );

    let key = DpopProofKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        DID,
        &parse_space_ref(&own_space).unwrap(),
        &key.thumbprint(),
        unix_now().unwrap(),
    );
    let path = "/xrpc/com.atproto.simplespace.getSpace";
    let request = || {
        Request::builder()
            .method(http::Method::GET)
            .uri(format!("{path}?space={own_space}"))
            .header("Authorization", format!("DPoP {credential}"))
            .header(
                "DPoP",
                key.proof(
                    "GET",
                    &format!("https://test.example.com{path}"),
                    &credential,
                ),
            )
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        send(&state, request()).await,
        StatusCode::OK,
        "precondition"
    );

    set_lifecycle(&state, DID, "taken_down_at").await;

    let response = crate::app::app(state.clone())
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "SpaceNotFound");
}

// ── migration ────────────────────────────────────────────────────────────────

/// Export a space repo from `source` and import it into `destination`, returning the import's
/// HTTP status and body.
async fn migrate(
    source: &AppState,
    destination: &AppState,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let export = crate::app::app(source.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK, "export");
    let car = axum::body::to_bytes(export.into_body(), usize::MAX)
        .await
        .unwrap();

    let response = crate::app::app(destination.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("/v1/space/import-repo?space={SPACE}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/vnd.ipld.car")
                .body(Body::from(car))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// The whole migration leg: three records written on the source host, exported as the two-root
/// CAR, imported into a deactivated account on a second host — and the destination's head must
/// carry the *same set hash* as the source's, because that digest is what every syncer folds
/// its own copy against.
#[tokio::test]
async fn a_space_repo_survives_export_and_import_with_the_same_set_hash() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    for (rkey, text) in [("one", "first"), ("two", "second"), ("three", "third")] {
        assert_eq!(
            send(
                &source,
                post(
                    "com.atproto.space.createRecord",
                    &token,
                    create_body(rkey, text)
                )
            )
            .await,
            StatusCode::OK
        );
    }
    let source_head = crate::db::space_repos::get_repo(&source.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap();

    let destination = state_with_master_key().await;
    seed_account_with_repo(&destination.db, DID).await;
    set_lifecycle(&destination, DID, "deactivated_at").await;
    let dest_token = scoped_access_jwt(&destination.jwt_secret, DID, GRANT);

    let (status, body) = migrate(&source, &destination, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["records"], 3);

    let dest_head = crate::db::space_repos::get_repo(&destination.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crypto::LtHash::from_state(&dest_head.lthash_state)
            .unwrap()
            .digest(),
        crypto::LtHash::from_state(&source_head.lthash_state)
            .unwrap()
            .digest(),
        "the imported repo must hash to the digest the source published"
    );

    // And the records themselves read back through the ordinary surface once activated.
    sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = ?")
        .bind(DID)
        .execute(&destination.db)
        .await
        .unwrap();
    let response = crate::app::app(destination.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRecord?space={SPACE}&repo={DID}&collection={COLLECTION}&rkey=two"),
            &dest_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["value"]["text"], "second");
}

/// A return migration lands on a repo that still holds the previous residency. Import means
/// "the repo is now exactly this CAR", so a record the index does not name is removed in the
/// same commit — otherwise the destination would hash to a digest the source never published
/// and no syncer could ever converge on it.
#[tokio::test]
async fn import_removes_records_the_car_does_not_name() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.space.createRecord",
                &token,
                create_body("kept", "x")
            )
        )
        .await,
        StatusCode::OK
    );
    let source_head = crate::db::space_repos::get_repo(&source.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap();

    // The destination already carries a stale record from a prior residency.
    let destination = setup().await;
    let dest_token = scoped_access_jwt(&destination.jwt_secret, DID, GRANT);
    for rkey in ["kept", "stale"] {
        assert_eq!(
            send(
                &destination,
                post(
                    "com.atproto.space.createRecord",
                    &dest_token,
                    create_body(rkey, "old")
                )
            )
            .await,
            StatusCode::OK
        );
    }
    set_lifecycle(&destination, DID, "deactivated_at").await;

    let (status, body) = migrate(&source, &destination, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let dest_head = crate::db::space_repos::get_repo(&destination.db, SPACE, DID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crypto::LtHash::from_state(&dest_head.lthash_state)
            .unwrap()
            .digest(),
        crypto::LtHash::from_state(&source_head.lthash_state)
            .unwrap()
            .digest(),
        "the stale record must be gone, not merely shadowed"
    );
    let index = crate::db::space_repos::list_record_index(&destination.db, SPACE, DID)
        .await
        .unwrap();
    assert_eq!(index.len(), 1);
    assert_eq!(index[0].1, "kept");
}

/// The import window is the deactivated state and nothing else: an active account must go
/// through the ordinary write routes, and a taken-down one has no space surface at all.
#[tokio::test]
async fn import_is_refused_outside_the_migration_window() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.space.createRecord",
                &token,
                create_body("one", "x")
            )
        )
        .await,
        StatusCode::OK
    );

    let destination = setup().await;
    let (status, _) = migrate(&source, &destination, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "active account");

    set_lifecycle(&destination, DID, "taken_down_at").await;
    let (status, _) = migrate(&source, &destination, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "taken-down account");
}

/// A CAR whose record block does not hash to the CID its index promised is rejected before
/// anything is committed — the structural check `import_space_car` inherits from the public
/// import path.
#[tokio::test]
async fn import_rejects_a_car_whose_blocks_contradict_its_index() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.space.createRecord",
                &token,
                create_body("one", "x")
            )
        )
        .await,
        StatusCode::OK
    );
    let export = crate::app::app(source.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={SPACE}&repo={DID}"),
            &token,
        ))
        .await
        .unwrap();
    let mut car = axum::body::to_bytes(export.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    // Flip a byte deep in the record payload; the block no longer hashes to its own CID.
    let last = car.len() - 1;
    car[last] ^= 0xff;

    let destination = setup().await;
    set_lifecycle(&destination, DID, "deactivated_at").await;
    let response = crate::app::app(destination.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("/v1/space/import-repo?space={SPACE}"))
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::from(car))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        crate::db::space_repos::get_repo(&destination.db, SPACE, DID)
            .await
            .unwrap()
            .is_none(),
        "a rejected CAR must leave no repo behind"
    );
}
