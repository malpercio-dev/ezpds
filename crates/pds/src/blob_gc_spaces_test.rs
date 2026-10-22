// pattern: Imperative Shell
//
// Blob GC across the feature boundary: a blob referenced only from a permissioned space record
// (written through `custos-spaces`' write path, so the stored DAG-CBOR carries a real blob link)
// is pinned by `custos-blobs`' collector. Lives in `pds` because it is the one crate that depends
// on both features.

use custos_blobs::test_support::{add_blob, blob_file_exists, blob_record, gc_state, run_blob_gc};
use custos_db::blobs;

/// A blob referenced only from a permissioned space record is pinned exactly like one
/// referenced from the public MST — for an account with **no public repo at all** (proving
/// the candidate query and the reference walk both cover the space surface) — while an
/// unreferenced expired blob on the same account is still collected.
#[tokio::test]
async fn gc_pins_blob_referenced_only_from_a_space_record() {
    let (state, _dir) = gc_state().await;
    let did = "did:plc:gcspaceref";
    sqlx::query(
        "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
         VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
    )
    .bind(did)
    .bind(format!("{did}@example.com"))
    .execute(&state.db)
    .await
    .unwrap();
    let space = custos_core::space_uri::parse_space_ref(
        "at://did:plc:gcspaceauthority/space/org.example.bucket/self",
    )
    .unwrap();

    // Both blobs are expired temporaries; only one gets referenced from a space record.
    let referenced = add_blob(&state, did, b"space bytes", "2020-01-01 00:00:00").await;
    let orphan = add_blob(&state, did, b"orphan bytes", "2020-01-01 00:00:00").await;
    custos_spaces::space_record_write::apply_space_writes(
        &custos_spaces::SpacesState::new(state.clone()),
        &space,
        did,
        &[custos_spaces::space_record_write::SpaceWriteOp {
            action: custos_spaces::space_record_write::SpaceWriteAction::Put,
            collection: "org.example.note".to_string(),
            rkey: "withblob".to_string(),
            value: Some(blob_record(&referenced)),
        }],
        custos_spaces::space_record_write::SpaceWriteAdmission::Active,
    )
    .await
    .unwrap();

    let stats = run_blob_gc(&state).await;
    assert_eq!(stats.errors, 0);
    assert_eq!(stats.deleted, 1, "the unreferenced blob is collected");

    let owner = blobs::get_owner(&state.db, did, &referenced)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.ref_count, 1);
    assert!(owner.temp_until.is_none(), "space reference pins the blob");
    assert!(blob_file_exists(&state, &referenced));
    assert!(!blob_file_exists(&state, &orphan));
}
