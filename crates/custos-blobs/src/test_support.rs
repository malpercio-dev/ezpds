//! Fixtures for tests that drive the blob surface: everything in `custos_core::test_support`
//! (re-exported below), the router the tests send through ([`test_app`]), and the GC fixtures
//! `pds`'s cross-feature GC test shares.

use std::sync::Arc;

use axum::Router;
pub use custos_core::test_support::*;
use custos_core::CoreState;

pub use crate::blob_gc::run_blob_gc;

/// The blob router over `state`, wrapped the way `pds` wraps its public group: lexicon output
/// validation, the shared layer stack, the XRPC error dialect, and permissive CORS. The rest of
/// the `pds` app is absent, so a path no blob route claims is a plain 404 here.
pub fn test_app(state: CoreState) -> Router {
    let router = crate::router::<CoreState>().layer(axum::middleware::from_fn(
        custos_core::lexicon::validate_xrpc_output,
    ));
    custos_core::apply_shared_layers(router, &state)
        .layer(axum::middleware::from_fn(
            custos_core::xrpc_error_shape::flatten_xrpc_errors,
        ))
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

// ── Blob GC fixtures, shared with `pds`'s space-record GC test ─────────────────────────

/// Test state with a real on-disk data_dir (so file deletes are observable) and the
/// signing-key master key configured (so test records can be written into the repo).
pub async fn gc_state() -> (CoreState, tempfile::TempDir) {
    let base = test_state().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*base.config).clone();
    config.data_dir = dir.path().to_path_buf();
    config.signing_key_master_key = Some(common::Sensitive(zeroize::Zeroizing::new(
        test_master_key(),
    )));
    let state = CoreState {
        config: Arc::new(config),
        ..base
    };
    (state, dir)
}

/// Store `content` as a blob on disk and insert its metadata row with the given
/// `temp_until`. Returns the blob CID.
pub async fn add_blob(state: &CoreState, did: &str, content: &[u8], temp_until: &str) -> String {
    let stored = custos_core::blob_store::store_blob(
        &state.config.data_dir,
        content,
        "application/octet-stream",
    )
    .await
    .unwrap();
    custos_db::blobs::insert_blob(
        &state.db,
        &stored.cid,
        did,
        &stored.mime_type,
        stored.size_bytes as i64,
        &stored.storage_path,
        temp_until,
    )
    .await
    .unwrap();
    stored.cid
}

/// True if a blob's file still exists on disk.
pub fn blob_file_exists(state: &CoreState, cid: &str) -> bool {
    let prefix = &cid[..2.min(cid.len())];
    state
        .config
        .data_dir
        .join(format!("blobs/{prefix}/{cid}"))
        .exists()
}

pub fn blob_record(cid: &str) -> serde_json::Value {
    serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "look at this",
        "embed": {
            "$type": "app.bsky.embed.images",
            "images": [
                { "image": { "$type": "blob", "ref": { "$link": cid }, "mimeType": "image/png", "size": 10 } }
            ]
        }
    })
}

/// Write a record into the account's repo and advance the persisted root.
pub async fn write_record(state: &CoreState, did: &str, key: &str, value: serde_json::Value) {
    let master = test_master_key();
    let root_str = custos_db::accounts::get_repo_root_cid(&state.db, did)
        .await
        .unwrap()
        .unwrap();
    let root = repo_engine::Cid::try_from(root_str.as_str()).unwrap();
    let signer = custos_core::auth::signing_key::load_repo_signer(&state.db, did, &master)
        .await
        .unwrap();
    let store = custos_db::blocks::SqliteBlockStore::new(state.db.clone(), did.to_string());
    let mut repo = repo_engine::Repository::open(store, root).await.unwrap();
    repo_engine::put_record_json(&mut repo, &signer, key, &value)
        .await
        .unwrap();
    let new_root = repo.root().to_string();
    sqlx::query("UPDATE accounts SET repo_root_cid = ? WHERE did = ?")
        .bind(&new_root)
        .bind(did)
        .execute(&state.db)
        .await
        .unwrap();
}
