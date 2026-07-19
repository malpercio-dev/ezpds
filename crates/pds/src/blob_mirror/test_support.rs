// pattern: Imperative Shell (test-only)
//
//! Shared test doubles for the blob-mirror surface: a stateful in-memory fake S3 server
//! (path-style, PUT/GET/DELETE + paginated ListObjectsV2) and a [`BlobMirror`] builder wired
//! to it. Used by this module's own sweep/restore tests and by `blob_scrub`'s auto-heal
//! tests, which need a mirror bucket to fetch a known-good copy from without a real S3
//! dependency.

#![cfg(test)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::BlobMirror;
use crate::app::AppState;
use crate::blob_store;
use crate::db::blobs;

const FAKE_BUCKET: &str = "testbucket";
const FAKE_PAGE_SIZE: usize = 2;

pub(crate) type ObjectStore = Arc<Mutex<BTreeMap<String, (String, Vec<u8>)>>>;

pub(crate) struct FakeS3 {
    objects: ObjectStore,
    pub(crate) endpoint: String,
}

impl FakeS3 {
    pub(crate) fn object(&self, key: &str) -> Option<(String, Vec<u8>)> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    pub(crate) fn put(&self, key: &str, content_type: &str, bytes: Vec<u8>) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), (content_type.to_string(), bytes));
    }

    pub(crate) fn keys(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                urlencoding::decode(k).ok()?.into_owned(),
                urlencoding::decode(v).ok()?.into_owned(),
            ))
        })
        .collect()
}

async fn fake_s3_handler(objects: ObjectStore, request: Request) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let key = uri
        .path()
        .strip_prefix(&format!("/{FAKE_BUCKET}"))
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let query = parse_query(uri.query().unwrap_or(""));
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap();

    if method == axum::http::Method::GET && query.get("list-type").map(String::as_str) == Some("2")
    {
        let prefix = query.get("prefix").cloned().unwrap_or_default();
        let after = query.get("continuation-token").cloned();
        let store = objects.lock().unwrap();
        let matching: Vec<&String> = store
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .filter(|k| {
                after
                    .as_ref()
                    .is_none_or(|token| k.as_str() > token.as_str())
            })
            .collect();
        let page: Vec<&String> = matching.iter().take(FAKE_PAGE_SIZE).copied().collect();
        let truncated = matching.len() > page.len();
        let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
        xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
        for key in &page {
            xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
        }
        if truncated {
            xml.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                page.last().unwrap()
            ));
        }
        xml.push_str("</ListBucketResult>");
        return xml.into_response();
    }

    match method {
        axum::http::Method::PUT => {
            objects
                .lock()
                .unwrap()
                .insert(key, (content_type, body.to_vec()));
            StatusCode::OK.into_response()
        }
        axum::http::Method::GET => match objects.lock().unwrap().get(&key) {
            Some((ct, bytes)) => {
                ([("content-type", ct.clone())], Bytes::from(bytes.clone())).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        axum::http::Method::DELETE => {
            objects.lock().unwrap().remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

pub(crate) async fn spawn_fake_s3() -> FakeS3 {
    let objects: ObjectStore = Arc::new(Mutex::new(BTreeMap::new()));
    let handler_objects = objects.clone();
    let router = axum::Router::new()
        .fallback(move |request: Request| fake_s3_handler(handler_objects.clone(), request));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    FakeS3 { objects, endpoint }
}

fn test_mirror_config(fake: &FakeS3) -> common::BlobMirrorConfig {
    common::BlobMirrorConfig {
        bucket: Some(FAKE_BUCKET.to_string()),
        endpoint: Some(fake.endpoint.clone()),
        access_key_id: Some("test-access-key".to_string()),
        secret_access_key: Some(common::Sensitive("test-secret".to_string())),
        force_path_style: true,
        ..Default::default()
    }
}

/// A fresh test `AppState` (real on-disk `data_dir` so file effects are observable) paired
/// with a `BlobMirror` wired to a freshly spawned fake S3 server.
pub(crate) async fn build_test_mirror() -> (AppState, tempfile::TempDir, FakeS3, BlobMirror) {
    let base = crate::app::test_state().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*base.config).clone();
    config.data_dir = dir.path().to_path_buf();
    let state = AppState {
        config: Arc::new(config),
        ..base
    };
    let fake = spawn_fake_s3().await;
    let mirror = BlobMirror::from_config(&test_mirror_config(&fake))
        .unwrap()
        .expect("bucket configured, mirror enabled");
    (state, dir, fake, mirror)
}

/// Store `content` on disk and insert its `blobs` + `blob_owners` rows (the FK needs an
/// account, seeded on first use per DID). Shared by the mirror sweep/restore tests and
/// `blob_scrub`'s tests.
pub(crate) async fn add_blob(state: &AppState, did: &str, content: &[u8], mime: &str) -> String {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE did = ?")
        .bind(did)
        .fetch_one(&state.db)
        .await
        .unwrap();
    if exists == 0 {
        sqlx::query(
            "INSERT INTO accounts (did, email, password_hash, created_at, updated_at) \
             VALUES (?, ?, NULL, datetime('now'), datetime('now'))",
        )
        .bind(did)
        .bind(format!("{did}@example.com"))
        .execute(&state.db)
        .await
        .unwrap();
    }
    let stored = blob_store::store_blob(&state.config.data_dir, content, mime)
        .await
        .unwrap();
    blobs::insert_blob(
        &state.db,
        &stored.cid,
        did,
        &stored.mime_type,
        stored.size_bytes as i64,
        &stored.storage_path,
        "2999-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    stored.cid
}

/// The on-disk path the blob store would use for `cid`, given `state`'s configured `data_dir`.
pub(crate) fn local_path(state: &AppState, cid: &str) -> std::path::PathBuf {
    state
        .config
        .data_dir
        .join(format!("blobs/{}/{cid}", &cid[..2]))
}
