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
//   * migration — `exportSpaceMeta` and `getRepo` on the source feed `importSpaceMeta` and
//     `importRepo` on the destination, and the imported repo has to hash to the digest the
//     source published.
//
// Routes may not import one another, so these cross-route journeys live here.

use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use custos_core::CoreState;
use tower::ServiceExt;

use crate::auth::space::{mint_space_credential, unix_now};
use crate::test_support::{
    access_jwt, body_json, scoped_access_jwt, seed_account_with_repo, state_with_master_key,
    SpaceSigKey,
};
use crate::test_support::{
    send_status as send, space_record_body, xrpc_get as get, xrpc_post as post,
};
use custos_core::space_uri::parse_space_ref;
use custos_db::dids::seed_did_document;

const DID: &str = "did:plc:spacelifecycleaaaaaaaaa";
const SPACE: &str = "at://did:plc:authorityaaaaaaaaaaaaaaa/space/org.example.bucket/main";
const COLLECTION: &str = "org.example.note";

/// A grant covering exactly this space and collection, for every record verb plus `read_self`.
const GRANT: &str =
    "atproto space:org.example.bucket?authority=did:plc:authorityaaaaaaaaaaaaaaa&skey=main\
&collection=org.example.note&action=create&action=update&action=delete&action=read_self";

async fn setup() -> CoreState {
    let state = state_with_master_key().await;
    seed_account_with_repo(&state.db, DID).await;
    state
}

fn create_body(rkey: &str, text: &str) -> serde_json::Value {
    space_record_body(SPACE, DID, COLLECTION, rkey, text)
}

/// `createSpace` for `at://{DID}/space/org.example.bucket/main`, open to everyone.
async fn create_own_space(state: &CoreState, token: &str) {
    assert_eq!(
        send(
            state,
            post(
                "com.atproto.space.createSpace",
                token,
                serde_json::json!({
                    "spaceType": "org.example.bucket",
                    "skey": "main",
                    "policy": {
                        "$type": "com.atproto.memberspace.policy",
                        "publicRead": true,
                        "publicWrite": true,
                    },
                }),
            ),
        )
        .await,
        StatusCode::OK
    );
}

/// Put `did` into one lifecycle state by setting the column that derives it.
async fn set_lifecycle(state: &CoreState, did: &str, column: &str) {
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

        let response = crate::test_support::test_app(state.clone())
            .oneshot(post(
                "com.atproto.space.createRecord",
                &token,
                create_body("b", "y"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{column}: write"
        );
        assert_eq!(
            body_json(response).await["error"],
            "AccountTakedown",
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
        StatusCode::UNAUTHORIZED,
        "but an ordinary write must still be refused (AccountDeactivated)"
    );
}

/// The writer listing is gated on its authority's status: a syncer holding a valid,
/// correctly-proofed credential is answered `RepoTakendown` once the authority is taken down —
/// never `SpaceDeleted`, since the deletion signal is durable and a takedown is not.
#[tokio::test]
async fn the_writer_listing_answers_the_authoritys_status() {
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
            ],
        }),
    )
    .await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let own_space = format!("at://{DID}/space/org.example.bucket/main");
    let owner = access_jwt(&state.jwt_secret, DID);
    create_own_space(&state, &owner).await;

    let key = SpaceSigKey::generate();
    let credential = mint_space_credential(
        |b| signer.sign(b),
        DID,
        &parse_space_ref(&own_space).unwrap(),
        key.key_id(),
        unix_now().unwrap(),
    );
    let request = || get_space_signed(&own_space, &key, &credential);
    assert_eq!(
        send(&state, request()).await,
        StatusCode::OK,
        "precondition"
    );

    set_lifecycle(&state, DID, "taken_down_at").await;

    let response = crate::test_support::test_app(state.clone())
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "RepoTakendown");
}

/// Credential-authed requests draw from a per-holder budget keyed by the credential's *verified*
/// `cnf.kid` — so re-minting a fresh credential (new `jti`, same bound key) does not reset it,
/// and only a fully authenticated request spends from it.
#[tokio::test]
async fn credential_requests_are_rate_limited_per_bound_key() {
    let mut state = state_with_master_key().await;
    state.rate_limiter = std::sync::Arc::new(custos_core::rate_limit::RateLimiterState::new(
        &common::RateLimitConfig {
            space_credential_per_5min: 1,
            ..common::RateLimitConfig::default()
        },
    ));
    let kp = seed_account_with_repo(&state.db, DID).await;
    let multibase = kp.key_id.0.strip_prefix("did:key:").unwrap().to_string();
    seed_did_document(
        &state.db,
        DID,
        serde_json::json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#atproto"), "type": "Multikey", "controller": DID, "publicKeyMultibase": multibase },
            ],
        }),
    )
    .await;
    let signer = repo_engine::CommitSigner::from_bytes(&kp.private_key_bytes).unwrap();
    let own_space = format!("at://{DID}/space/org.example.bucket/main");
    let owner = access_jwt(&state.jwt_secret, DID);
    create_own_space(&state, &owner).await;

    let key = SpaceSigKey::generate();
    let request = |credential: &str| get_space_signed(&own_space, &key, credential);
    let mint = || {
        mint_space_credential(
            |b| signer.sign(b),
            DID,
            &parse_space_ref(&own_space).unwrap(),
            key.key_id(),
            unix_now().unwrap(),
        )
    };

    let credential = mint();
    assert_eq!(send(&state, request(&credential)).await, StatusCode::OK);

    // The budget is spent: even a freshly minted credential still 429s, because the limiter
    // keys on the credential's bound key, not its jti.
    let response = crate::test_support::test_app(state.clone())
        .oneshot(request(&mint()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
    assert_eq!(body_json(response).await["error"], "RateLimitExceeded");
}

/// `space.listRepos` (a space-level space-host read) for `space` under `credential`, signed by
/// `key` and addressed to the space's authority.
fn get_space_signed(space: &str, key: &SpaceSigKey, credential: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method(http::Method::GET)
        .uri(format!("/xrpc/com.atproto.space.listRepos?space={space}"));
    b.headers_mut()
        .unwrap()
        .extend(key.credential_headers(credential, DID));
    b.body(Body::empty()).unwrap()
}

// ── migration ────────────────────────────────────────────────────────────────

/// `getRepo` on `source` for `did`'s repo in `space`, as raw archive bytes.
async fn export_repo(source: &CoreState, space: &str, did: &str, token: &str) -> Vec<u8> {
    let export = crate::test_support::test_app(source.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRepo?space={space}&repo={did}"),
            token,
        ))
        .await
        .unwrap();
    assert_eq!(export.status(), StatusCode::OK, "export");
    axum::body::to_bytes(export.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// POST a STAR archive to one of the two import methods on `destination`.
async fn import(
    destination: &CoreState,
    method: &str,
    token: &str,
    archive: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let response = crate::test_support::test_app(destination.clone())
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri(format!("/xrpc/com.atproto.space.{method}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/vnd.dasl.star")
                .body(Body::from(archive))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

/// Export `DID`'s repo in `SPACE` from `source` and import it into `destination`.
async fn migrate(
    source: &CoreState,
    destination: &CoreState,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let archive = export_repo(source, SPACE, DID, token).await;
    import(destination, "importRepo", token, archive).await
}

fn digest(head: &crate::db::space_repos::SpaceRepoRow) -> [u8; 32] {
    crypto::LtHash::from_state(&head.lthash_state)
        .unwrap()
        .digest()
}

async fn head(state: &CoreState, space: &str, did: &str) -> crate::db::space_repos::SpaceRepoRow {
    crate::db::space_repos::get_repo(&state.db, space, did)
        .await
        .unwrap()
        .unwrap()
}

/// A destination host with `DID` seeded and deactivated, as `createAccount` leaves a migration
/// target.
async fn deactivated_destination() -> CoreState {
    let destination = state_with_master_key().await;
    seed_account_with_repo(&destination.db, DID).await;
    set_lifecycle(&destination, DID, "deactivated_at").await;
    destination
}

/// The repo leg: three records written on the source host, exported as a STAR archive, imported
/// into a deactivated account on a second host. The destination's head must carry the *same set
/// hash* as the source's, because that digest is what every syncer folds its own copy against.
#[tokio::test]
async fn a_space_repo_survives_get_repo_and_import_repo_with_the_same_set_hash() {
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

    let destination = deactivated_destination().await;
    let full = access_jwt(&destination.jwt_secret, DID);
    let (status, body) = migrate(&source, &destination, &full).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        digest(&head(&destination, SPACE, DID).await),
        digest(&head(&source, SPACE, DID).await),
        "the imported repo must hash to the digest the source published"
    );

    // And the records themselves read back through the ordinary surface once activated.
    sqlx::query("UPDATE accounts SET deactivated_at = NULL WHERE did = ?")
        .bind(DID)
        .execute(&destination.db)
        .await
        .unwrap();
    let dest_token = scoped_access_jwt(&destination.jwt_secret, DID, GRANT);
    let response = crate::test_support::test_app(destination.clone())
        .oneshot(get(
            &format!("com.atproto.space.getRecord?space={SPACE}&repo={DID}&collection={COLLECTION}&rkey=two"),
            &dest_token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["value"]["text"], "second");
}

/// An import replaces the whole repo, so it takes a grant over the whole space, not just the
/// collections the archive happens to hold.
#[tokio::test]
async fn import_takes_a_grant_over_the_whole_space() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    send(
        &source,
        post(
            "com.atproto.space.createRecord",
            &token,
            create_body("one", "x"),
        ),
    )
    .await;
    let destination = deactivated_destination().await;
    let narrow = scoped_access_jwt(&destination.jwt_secret, DID, GRANT);
    let (status, body) = migrate(&source, &destination, &narrow).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let whole = scoped_access_jwt(
        &destination.jwt_secret,
        DID,
        "atproto space:org.example.bucket?authority=did:plc:authorityaaaaaaaaaaaaaaa&skey=main\
&collection=*&action=create&action=update&action=delete&action=read",
    );
    let (status, body) = migrate(&source, &destination, &whole).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A return migration lands on a repo that still holds the previous residency. Import replaces
/// records *and* oplog: a record the archive does not name is gone, the oplog starts empty, and
/// the repo takes a fresh rev after the one this host held, so a syncer with an old `since`
/// heals with `getRepo`.
#[tokio::test]
async fn import_replaces_the_records_and_the_oplog_under_a_fresh_rev() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    send(
        &source,
        post(
            "com.atproto.space.createRecord",
            &token,
            create_body("kept", "x"),
        ),
    )
    .await;

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
    let before = head(&destination, SPACE, DID).await;
    set_lifecycle(&destination, DID, "deactivated_at").await;

    let full = access_jwt(&destination.jwt_secret, DID);
    let (status, body) = migrate(&source, &destination, &full).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let after = head(&destination, SPACE, DID).await;
    assert_eq!(digest(&after), digest(&head(&source, SPACE, DID).await));
    assert!(
        after.rev > before.rev,
        "the imported repo takes a fresh rev"
    );
    let index = crate::db::space_repos::list_record_index(&destination.db, SPACE, DID)
        .await
        .unwrap();
    assert_eq!(index.len(), 1);
    assert_eq!(index[0].1, "kept");
    let ops: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM space_repo_ops WHERE space_uri = ? AND account_did = ?",
    )
    .bind(SPACE)
    .bind(DID)
    .fetch_one(&destination.db)
    .await
    .unwrap();
    assert_eq!(ops, 0, "the imported repo starts with an empty oplog");
}

/// The import window is the deactivated state and nothing else: an active account must go
/// through the ordinary write routes, and a taken-down one has no space surface at all.
#[tokio::test]
async fn import_is_refused_outside_the_migration_window() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    send(
        &source,
        post(
            "com.atproto.space.createRecord",
            &token,
            create_body("one", "x"),
        ),
    )
    .await;

    let destination = setup().await;
    let full = access_jwt(&destination.jwt_secret, DID);
    let (status, _) = migrate(&source, &destination, &full).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "active account");

    set_lifecycle(&destination, DID, "taken_down_at").await;
    let (status, _) = migrate(&source, &destination, &full).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "taken-down account");
}

/// An archive that does not verify against its own commit, or that is another account's repo,
/// is refused before anything is written.
#[tokio::test]
async fn import_refuses_an_archive_that_does_not_verify_or_is_not_the_callers() {
    let source = setup().await;
    let token = scoped_access_jwt(&source.jwt_secret, DID, GRANT);
    send(
        &source,
        post(
            "com.atproto.space.createRecord",
            &token,
            create_body("one", "x"),
        ),
    )
    .await;
    let mut archive = export_repo(&source, SPACE, DID, &token).await;
    let destination = deactivated_destination().await;

    // Flip a byte inside the record's value, just before the end byte.
    let at = archive.len() - 2;
    archive[at] ^= 0xff;
    let full = access_jwt(&destination.jwt_secret, DID);
    let (status, body) = import(&destination, "importRepo", &full, archive).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "InvalidRepoFile");

    const OTHER: &str = "did:plc:spacelifecycleotheraaaa";
    seed_account_with_repo(&destination.db, OTHER).await;
    set_lifecycle(&destination, OTHER, "deactivated_at").await;
    let archive = export_repo(&source, SPACE, DID, &token).await;
    let other = access_jwt(&destination.jwt_secret, OTHER);
    let (status, body) = import(&destination, "importRepo", &other, archive).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "RepoMismatch");

    assert!(
        crate::db::space_repos::get_repo(&destination.db, SPACE, DID)
            .await
            .unwrap()
            .is_none(),
        "a refused archive must leave no repo behind"
    );
}

/// A space round-trips between two hosts the way an authority's account migration carries it:
/// `exportSpaceMeta` → `importSpaceMeta` → `getRepo` → `importRepo`. The destination answers
/// for the space with the same policy, members and writers, and the authority's repo (holding
/// the published member records too) hashes to the same `data`.
#[tokio::test]
async fn an_authoritys_space_round_trips_through_meta_and_repo_with_equal_data() {
    const MEMBER: &str = "did:plc:spacelifecyclememberaaa";
    let own = format!("at://{DID}/space/org.example.bucket/main");
    let source = setup().await;
    let token = access_jwt(&source.jwt_secret, DID);
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.space.createSpace",
                &token,
                serde_json::json!({
                    "spaceType": "org.example.bucket",
                    "skey": "main",
                    "policy": {
                        "$type": "com.atproto.memberspace.policy",
                        "publishMembers": true,
                    },
                }),
            ),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.memberspace.putMembers",
                &token,
                serde_json::json!({
                    "space": own,
                    "members": [{ "did": MEMBER, "read": true, "write": false }],
                }),
            ),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &source,
            post(
                "com.atproto.space.createRecord",
                &token,
                space_record_body(&own, DID, COLLECTION, "note", "hello"),
            ),
        )
        .await,
        StatusCode::OK
    );

    let destination = deactivated_destination().await;
    let dest_token = access_jwt(&destination.jwt_secret, DID);
    let repo = export_repo(&source, &own, DID, &token).await;

    // The authority's repo cannot land before its space does.
    let (status, body) = import(&destination, "importRepo", &dest_token, repo.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "SpaceNotFound");

    let response = crate::test_support::test_app(source.clone())
        .oneshot(get(
            &format!("com.atproto.space.exportSpaceMeta?space={own}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.dasl.star"
    );
    let meta = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let (status, body) = import(&destination, "importSpaceMeta", &dest_token, meta).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = import(&destination, "importRepo", &dest_token, repo).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(
        digest(&head(&destination, &own, DID).await),
        digest(&head(&source, &own, DID).await),
        "the authority's repo must arrive with the data the source published"
    );
    let space_of = |state: &CoreState| {
        let state = state.clone();
        let own = own.clone();
        async move {
            let row = crate::db::spaces::get_space(&state.db, &own)
                .await
                .unwrap()
                .unwrap();
            let members = crate::db::spaces::all_members(&state.db, &own)
                .await
                .unwrap()
                .into_iter()
                .map(|m| (m.member_did, m.can_read, m.can_write))
                .collect::<Vec<_>>();
            let writers = crate::db::space_meta::all_writers(&state.db, &own)
                .await
                .unwrap();
            (row.policy, members, writers)
        }
    };
    let (source_space, dest_space) = (space_of(&source).await, space_of(&destination).await);
    assert_eq!(dest_space, source_space);
    assert_eq!(dest_space.1.len(), 1, "the member list came across");
    assert_eq!(
        dest_space.2.len(),
        1,
        "the authority's writer entry came across"
    );
}

/// An operator takedown of the space (ADR-0035) stops serving it, and an export is serving: the
/// authority's own `exportSpaceMeta` and `getRepo` answer `SpaceNotFound` until it is lifted.
#[tokio::test]
async fn a_space_takedown_blocks_the_authoritys_export() {
    let own = format!("at://{DID}/space/org.example.bucket/main");
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    create_own_space(&state, &token).await;
    send(
        &state,
        post(
            "com.atproto.space.createRecord",
            &token,
            space_record_body(&own, DID, COLLECTION, "note", "hello"),
        ),
    )
    .await;
    crate::db::spaces::set_space_takedown(&state.db, &own, true)
        .await
        .unwrap();
    for path in [
        format!("com.atproto.space.exportSpaceMeta?space={own}"),
        format!("com.atproto.space.getRepo?space={own}&repo={DID}"),
    ] {
        let response = crate::test_support::test_app(state.clone())
            .oneshot(get(&path, &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            body_json(response).await["error"],
            "SpaceNotFound",
            "{path}"
        );
    }
}

// ── repo lifecycle ───────────────────────────────────────────────────────────

/// A space anchored on the writer's own DID must already exist: a repo is created implicitly by
/// its first write, but the space is not. Only `createSpace` makes it, after which the same
/// write lands.
#[tokio::test]
async fn writing_into_an_uncreated_own_space_is_refused() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let own_space = format!("at://{DID}/space/org.example.bucket/main");
    let write = || {
        post(
            "com.atproto.space.createRecord",
            &token,
            space_record_body(&own_space, DID, COLLECTION, "a", "x"),
        )
    };

    let (status, body) = crate::test_support::send(&state, write()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "SpaceNotFound");
    assert!(
        crate::db::spaces::get_space(&state.db, &own_space)
            .await
            .unwrap()
            .is_none(),
        "the refused write must not record the space"
    );

    create_own_space(&state, &token).await;
    assert_eq!(send(&state, write()).await, StatusCode::OK);
}

/// Every repo read, for `space`/`DID`, paired with a label for failure messages.
fn repo_reads(space: &str) -> Vec<(&'static str, String)> {
    let q = format!("space={space}&repo={DID}");
    vec![
        ("getRepo", format!("com.atproto.space.getRepo?{q}")),
        (
            "getLatestCommit",
            format!("com.atproto.space.getLatestCommit?{q}"),
        ),
        (
            "listRecords",
            format!("com.atproto.space.listRecords?{q}&collection={COLLECTION}"),
        ),
        ("listRepoOps", format!("com.atproto.space.listRepoOps?{q}")),
    ]
}

/// An empty repo and a nonexistent one are the same thing: deleting the last record makes the
/// repo read as absent on every surface — `RepoNotFound` from each repo read, gone from
/// `listSpaces` — until the next write recreates it.
#[tokio::test]
async fn deleting_the_last_record_makes_the_repo_absent_until_the_next_write() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let write = || {
        post(
            "com.atproto.space.createRecord",
            &token,
            create_body("a", "x"),
        )
    };
    assert_eq!(send(&state, write()).await, StatusCode::OK);
    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.space.deleteRecord",
                &token,
                serde_json::json!({
                    "space": SPACE, "repo": DID, "collection": COLLECTION, "rkey": "a",
                }),
            ),
        )
        .await,
        StatusCode::OK
    );

    for (label, uri) in repo_reads(SPACE) {
        let (status, body) = crate::test_support::send(&state, get(&uri, &token)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
        assert_eq!(body["error"], "RepoNotFound", "{label}");
    }
    let (status, body) =
        crate::test_support::send(&state, get("com.atproto.space.listSpaces", &token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.to_string().contains(SPACE),
        "an emptied repo's space must drop out of listSpaces: {body}"
    );

    // The next write recreates the repo, readable everywhere again.
    assert_eq!(send(&state, write()).await, StatusCode::OK);
    for (label, uri) in repo_reads(SPACE) {
        // Status only: getRepo answers a CAR, not JSON.
        let response = crate::test_support::test_app(state.clone())
            .oneshot(get(&uri, &token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{label}");
    }
    let (_, body) =
        crate::test_support::send(&state, get("com.atproto.space.listSpaces", &token)).await;
    assert!(body.to_string().contains(SPACE), "{body}");
}

/// On the authority's side, an emptied repo leaves the writer set `listRepos` answers.
#[tokio::test]
async fn an_emptied_repo_leaves_the_authority_writer_set() {
    let state = setup().await;
    let token = access_jwt(&state.jwt_secret, DID);
    let own_space = format!("at://{DID}/space/org.example.bucket/main");
    create_own_space(&state, &token).await;
    let writers = || crate::db::space_notify::list_writers(&state.db, &own_space, None, 10);

    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.space.createRecord",
                &token,
                space_record_body(&own_space, DID, COLLECTION, "a", "x"),
            ),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(writers().await.unwrap().len(), 1, "precondition");

    assert_eq!(
        send(
            &state,
            post(
                "com.atproto.space.deleteRecord",
                &token,
                serde_json::json!({
                    "space": own_space, "repo": DID, "collection": COLLECTION, "rkey": "a",
                }),
            ),
        )
        .await,
        StatusCode::OK
    );
    assert!(writers().await.unwrap().is_empty());
}
