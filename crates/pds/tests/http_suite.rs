// pattern: Imperative Shell
//
// Black-box HTTP integration suite for the Custos PDS. It spawns the real compiled `pds` binary
// against a temp-file SQLite DB with plc.directory mocked, then walks the golden path the
// `tools/interop` Node suite covers, minus the live network. The two suites mirror each other's
// step order so they stay conceptually paired.
//
// Design: ONE spawned server + ONE `#[tokio::test]` running every step sequentially. Splitting into
// separate tests would re-spawn (and re-migrate) the server per test — too slow for the CI budget.
// Each step runs inside `step(name, ...)`, which labels any panic with the step name so a failure
// localizes to exactly one leg. A step never early-returns green: a missing precondition panics.

mod common;

use std::future::Future;
use std::time::Duration;

use common::{create_account, Harness, USER_DOMAIN};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// Percent-encode a query-parameter value so DIDs (with `:`) and NSIDs survive the URL.
fn enc(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

/// Run one named step, prefixing any panic with the step name so failures localize.
async fn step<F, Fut>(name: &str, f: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    eprintln!("▶ {name}");
    f().await;
    eprintln!("  ✔ {name}");
}

/// The `{op, t}` header that prefixes every subscribeRepos message frame. Decoding just this from
/// the front of a binary frame is enough to identify the frame type (the body follows as a second,
/// independently-decodable DAG-CBOR value).
#[derive(Deserialize)]
struct FrameHeader {
    #[allow(dead_code)]
    op: i64,
    t: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_golden_path_suite() {
    let h = Harness::start().await;

    // 1. health → 200 with a version + db:ok body.
    step("health", || async {
        let resp = h
            .http
            .get(h.url("/xrpc/_health"))
            .send()
            .await
            .expect("health request");
        assert!(
            resp.status().is_success(),
            "health status: {}",
            resp.status()
        );
        let body: serde_json::Value = resp.json().await.expect("health json");
        assert_eq!(body["db"], "ok", "health db field: {body}");
        assert!(
            body["version"].is_string(),
            "health version missing: {body}"
        );
    })
    .await;

    // 2. describeServer → advertises the configured user domain.
    step("describeServer", || async {
        let resp = h
            .http
            .get(h.url("/xrpc/com.atproto.server.describeServer"))
            .send()
            .await
            .expect("describeServer request");
        assert!(resp.status().is_success());
        let body: serde_json::Value = resp.json().await.expect("describeServer json");
        let domains = body["availableUserDomains"]
            .as_array()
            .expect("availableUserDomains array");
        assert!(
            domains.iter().any(|d| d == USER_DOMAIN),
            "availableUserDomains must contain {USER_DOMAIN}: {body}"
        );
    })
    .await;

    // 3. /metrics → Prometheus exposition with http_requests_total. `firehose_subscribers` only
    //    surfaces after a subscriber has connected once, so that this half of the assertion happens
    //    in a later /metrics scrape (step "metrics after firehose"), after step 7 has connected a WS.
    step("metrics before firehose", || async {
        let resp = h
            .http
            .get(h.url("/metrics"))
            .send()
            .await
            .expect("metrics request");
        assert!(
            resp.status().is_success(),
            "metrics status: {}",
            resp.status()
        );
        let text = resp.text().await.expect("metrics body");
        assert!(
            text.contains("http_requests_total"),
            "metrics must expose http_requests_total; got:\n{text}"
        );
    })
    .await;

    // 4. createAccount with a client-supplied self-signed plcOp (helper replicates the unit-test
    //    genesis-op construction; the mocked plc.directory accepts the submission).
    let handle = format!("alice.{USER_DOMAIN}");
    let email = "alice@example.com";
    let password = "hunter2hunter2";
    let mut account = None;
    step("createAccount", || async {
        let acct = create_account(&h, &handle, email, password).await;
        assert!(acct.did.starts_with("did:plc:"), "did shape: {}", acct.did);
        assert!(!acct.access_jwt.is_empty(), "access jwt present");
        account = Some(acct);
    })
    .await;
    let account = account.expect("account created");
    let did = account.did.clone();

    // 5. createSession with the account's credentials → fresh access + refresh JWTs.
    let mut session_jwt = None;
    step("createSession", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.createSession"))
            .json(&json!({ "identifier": handle, "password": password }))
            .send()
            .await
            .expect("createSession request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("createSession json");
        assert!(
            status.is_success(),
            "createSession failed ({status}): {body}"
        );
        assert_eq!(body["did"], did, "session did matches account");
        assert!(body["accessJwt"].as_str().is_some(), "accessJwt present");
        assert!(body["refreshJwt"].as_str().is_some(), "refreshJwt present");
        session_jwt = Some(body["accessJwt"].as_str().unwrap().to_string());
    })
    .await;
    // Use the account-creation token for writes; both carry full access scope.
    let token = account.access_jwt.clone();
    let _ = session_jwt.expect("session established");

    // 6. Repo CRUD round trip: create → get → put → list → delete.
    let collection = "app.bsky.feed.post";
    let mut created_uri = None;
    let mut rkey = None;
    step("createRecord", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&token)
            .json(&json!({
                "repo": did,
                "collection": collection,
                "record": { "$type": collection, "text": "hello", "createdAt": "2026-07-07T00:00:00Z" },
            }))
            .send()
            .await
            .expect("createRecord request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("createRecord json");
        assert!(status.is_success(), "createRecord failed ({status}): {body}");
        let uri = body["uri"].as_str().expect("record uri").to_string();
        rkey = Some(uri.rsplit('/').next().expect("rkey in uri").to_string());
        created_uri = Some(uri);
    })
    .await;
    let rkey = rkey.expect("rkey captured");
    let _created_uri = created_uri.expect("uri captured");

    step("getRecord", || async {
        let url = h.url(&format!(
            "/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
            enc(&did),
            enc(collection),
            enc(&rkey)
        ));
        let resp = h.http.get(url).send().await.expect("getRecord request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("getRecord json");
        assert!(status.is_success(), "getRecord failed ({status}): {body}");
        assert_eq!(body["value"]["text"], "hello", "record round-trips: {body}");
    })
    .await;

    step("putRecord", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.putRecord"))
            .bearer_auth(&token)
            .json(&json!({
                "repo": did,
                "collection": collection,
                "rkey": rkey,
                "record": { "$type": collection, "text": "edited", "createdAt": "2026-07-07T00:00:00Z" },
            }))
            .send()
            .await
            .expect("putRecord request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("putRecord json");
        assert!(status.is_success(), "putRecord failed ({status}): {body}");
    })
    .await;

    step("listRecords", || async {
        let url = h.url(&format!(
            "/xrpc/com.atproto.repo.listRecords?repo={}&collection={}",
            enc(&did),
            enc(collection)
        ));
        let resp = h.http.get(url).send().await.expect("listRecords request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("listRecords json");
        assert!(status.is_success(), "listRecords failed ({status}): {body}");
        let records = body["records"].as_array().expect("records array");
        assert!(
            records.iter().any(|r| r["value"]["text"] == "edited"),
            "listRecords must reflect the put edit: {body}"
        );
    })
    .await;

    // 7. Firehose: connect a subscriber, perform one createRecord, assert a #commit binary frame
    //    arrives. Connect BEFORE writing so the live commit is observed on the stream (not only in
    //    replay). This also raises firehose_subscribers, checked in the next /metrics scrape.
    step("firehose #commit", || async {
        let ws_url = h.ws_url("/xrpc/com.atproto.sync.subscribeRepos");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .unwrap_or_else(|e| panic!("subscribeRepos connect failed: {e}"));

        // Trigger a commit now that the subscriber is attached.
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&token)
            .json(&json!({
                "repo": did,
                "collection": collection,
                "record": { "$type": collection, "text": "firehose", "createdAt": "2026-07-07T00:00:00Z" },
            }))
            .send()
            .await
            .expect("firehose-trigger createRecord");
        assert!(
            resp.status().is_success(),
            "firehose-trigger createRecord failed: {}",
            resp.status()
        );

        // Read frames until a #commit shows up or a deadline elapses. Genesis frames from account
        // creation may replay first; skip past them.
        let saw_commit = timeout(Duration::from_secs(10), async {
            while let Some(msg) = ws.next().await {
                let msg = msg.expect("firehose frame");
                if let Message::Binary(bytes) = msg {
                    // The frame is two concatenated DAG-CBOR values: header then body.
                    // `from_reader_once` reads exactly the first value (the header) and leaves the
                    // body in the reader untouched — decoding just the header identifies the frame.
                    let mut reader = &bytes[..];
                    if let Ok(header) =
                        serde_ipld_dagcbor::de::from_reader_once::<FrameHeader, _>(&mut reader)
                    {
                        if header.t.as_deref() == Some("#commit") {
                            return true;
                        }
                    }
                }
            }
            false
        })
        .await
        .expect("timed out waiting for a #commit firehose frame");
        assert!(saw_commit, "no #commit frame observed on subscribeRepos");

        // Dropping the stream closes the WebSocket, which decrements firehose_subscribers.
        drop(ws);
    })
    .await;

    // With a subscriber having connected, firehose_subscribers is a
    // registered series in the exposition.
    step("metrics after firehose", || async {
        let resp = h
            .http
            .get(h.url("/metrics"))
            .send()
            .await
            .expect("metrics request");
        assert!(resp.status().is_success());
        let text = resp.text().await.expect("metrics body");
        assert!(
            text.contains("firehose_subscribers"),
            "metrics must expose firehose_subscribers after a subscription; got:\n{text}"
        );
    })
    .await;

    // 8. uploadBlob → getBlob round trip. getBlob verifies DID ownership, which a freshly uploaded
    //    blob satisfies, so it returns the bytes without needing a referencing record.
    let blob_bytes: &[u8] = b"integration-harness-blob-payload";
    step("uploadBlob / getBlob", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.uploadBlob"))
            .bearer_auth(&token)
            .header("content-type", "application/octet-stream")
            .body(blob_bytes.to_vec())
            .send()
            .await
            .expect("uploadBlob request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("uploadBlob json");
        assert!(status.is_success(), "uploadBlob failed ({status}): {body}");
        let cid = body["blob"]["ref"]["$link"]
            .as_str()
            .expect("blob ref $link")
            .to_string();

        let got = h
            .http
            .get(h.url(&format!(
                "/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
                enc(&did),
                enc(&cid)
            )))
            .send()
            .await
            .expect("getBlob request");
        assert!(
            got.status().is_success(),
            "getBlob status: {}",
            got.status()
        );
        let returned = got.bytes().await.expect("getBlob body");
        assert_eq!(
            returned.as_ref(),
            blob_bytes,
            "getBlob must return the uploaded bytes verbatim"
        );
    })
    .await;

    // 9. sync.getRepo → a non-empty CAR export beginning with a valid CARv1 header.
    step("sync.getRepo CAR export", || async {
        let resp = h
            .http
            .get(h.url(&format!("/xrpc/com.atproto.sync.getRepo?did={}", enc(&did))))
            .send()
            .await
            .expect("getRepo request");
        assert!(
            resp.status().is_success(),
            "getRepo status: {}",
            resp.status()
        );
        let car = resp.bytes().await.expect("getRepo body");
        assert!(!car.is_empty(), "CAR export must be non-empty");
        // A CARv1 file starts with a varint length prefix for the header block. That length must be
        // non-zero and fit within the file — a cheap structural sanity check that the export is a
        // real CAR, not an error page.
        let (header_len, consumed) = read_uvarint(&car).expect("CAR header length varint");
        assert!(header_len > 0, "CAR header length must be non-zero");
        assert!(
            consumed + header_len as usize <= car.len(),
            "CAR header length {header_len} overruns the {}-byte export",
            car.len()
        );
    })
    .await;

    // 9b. No-input strictness parity: a no-input XRPC procedure rejects a spurious body
    //     with 400 InvalidRequest, matching the reference PDS. The wallet develops against Custos,
    //     so this is where Custos's strictness backstops the wallet. Uses `activateAccount` (the
    //     account is still active here, so an empty-body call would be a 200 no-op) and
    //     `requestPlcOperationSignature` as representatives, and
    //     confirms the same call with no body still succeeds.
    step("no-input procedures reject a body", || async {
        for path in [
            "/xrpc/com.atproto.server.activateAccount",
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        ] {
            let resp = h
                .http
                .post(h.url(path))
                .bearer_auth(&token)
                .json(&json!({}))
                .send()
                .await
                .expect("no-input body request");
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.expect("error json");
            assert_eq!(
                status.as_u16(),
                400,
                "{path} must reject a body with 400, got {status}: {body}"
            );
            assert_eq!(
                body["error"]["code"], "InvalidRequest",
                "{path} body rejection must be InvalidRequest: {body}"
            );
        }

        // The same procedure with no body still succeeds (activateAccount on an active account is a
        // 200 no-op) — the guard rejects only a present body, never an empty request.
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.activateAccount"))
            .bearer_auth(&token)
            .send()
            .await
            .expect("empty-body activateAccount request");
        assert!(
            resp.status().is_success(),
            "activateAccount with no body must still succeed, got {}",
            resp.status()
        );
    })
    .await;

    // 9c. Lexicon input validation parity (MM-364): every natively-handled JSON procedure now
    //     runs its request body through the vendored `com.atproto.*` lexicon before the handler,
    //     so a missing required field, a format violation, or a wrong/absent Content-Type gets
    //     the reference PDS's 400 InvalidRequest envelope (previously axum's bare `Json`
    //     extractor answered 422/415 with a plain-text body). Message shapes are asserted
    //     byte-for-byte against `@atproto/lexicon` / `@atproto/xrpc-server`.
    step("lexicon input validation parity", || async {
        let expect_invalid_request = |resp: reqwest::Response, expected_message: &'static str| async move {
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.expect("error json");
            assert_eq!(status.as_u16(), 400, "expected 400, got {status}: {body}");
            assert_eq!(
                body["error"]["code"], "InvalidRequest",
                "expected InvalidRequest: {body}"
            );
            assert_eq!(
                body["error"]["message"], expected_message,
                "reference-parity message mismatch: {body}"
            );
        };

        // Missing required field, named in lexicon declaration order.
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.createSession"))
            .json(&json!({"identifier": "someone.example.com"}))
            .send()
            .await
            .expect("createSession request");
        expect_invalid_request(resp, "Input must have the property \"password\"").await;

        // String-format violation, path-prefixed.
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&token)
            .json(&json!({"repo": did, "collection": "not-an-nsid", "record": {"text": "x"}}))
            .send()
            .await
            .expect("createRecord request");
        expect_invalid_request(resp, "Input/collection must be a valid nsid").await;

        // Closed union: an unknown $type is rejected, printing the fully-qualified refs.
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.applyWrites"))
            .bearer_auth(&token)
            .json(&json!({
                "repo": did,
                "writes": [{"$type": "com.atproto.repo.applyWrites#upsert"}],
            }))
            .send()
            .await
            .expect("applyWrites request");
        expect_invalid_request(
            resp,
            "Input/writes/0 $type must be one of lex:com.atproto.repo.applyWrites#create, \
             lex:com.atproto.repo.applyWrites#update, lex:com.atproto.repo.applyWrites#delete",
        )
        .await;

        // A body with the wrong Content-Type is a 400 (bare `Json` used to answer 415).
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.createSession"))
            .header("Content-Type", "text/plain")
            .body(r#"{"identifier":"someone.example.com","password":"hunter2"}"#)
            .send()
            .await
            .expect("wrong-content-type request");
        expect_invalid_request(resp, "Wrong request encoding (Content-Type): text/plain").await;

        // A procedure that declares an input requires a body (reqwest sends neither a body nor
        // a Content-Length header here — the reference's "missing" body presence).
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.createSession"))
            .send()
            .await
            .expect("missing-body request");
        expect_invalid_request(resp, "A request body is expected but none was provided").await;
    })
    .await;

    // 10. deactivateAccount → subsequent createRecord is 403; getRepoStatus reflects deactivated;
    //     then re-deactivate with a `deleteAfter` already in the past and poll until the reaper
    //     (running every second via EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS in the harness)
    //     permanently purges the account. The first deactivation carries no `deleteAfter` so the
    //     403/getRepoStatus assertions can't race the purge; re-deactivating is idempotent and
    //     refreshes `deleteAfter`.
    step("deactivateAccount", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.deactivateAccount"))
            .bearer_auth(&token)
            .json(&json!({}))
            .send()
            .await
            .expect("deactivateAccount request");
        assert!(
            resp.status().is_success(),
            "deactivateAccount status: {}",
            resp.status()
        );
    })
    .await;

    step("write after deactivate is 403", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.repo.createRecord"))
            .bearer_auth(&token)
            .json(&json!({
                "repo": did,
                "collection": collection,
                "record": { "$type": collection, "text": "post-deactivate", "createdAt": "2026-07-07T00:00:00Z" },
            }))
            .send()
            .await
            .expect("post-deactivate createRecord request");
        assert_eq!(
            resp.status().as_u16(),
            403,
            "a write on a deactivated account must be 403, got {}",
            resp.status()
        );
    })
    .await;

    step("getRepoStatus reflects deactivated", || async {
        let resp = h
            .http
            .get(h.url(&format!(
                "/xrpc/com.atproto.sync.getRepoStatus?did={}",
                enc(&did)
            )))
            .send()
            .await
            .expect("getRepoStatus request");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("getRepoStatus json");
        assert!(
            status.is_success(),
            "getRepoStatus failed ({status}): {body}"
        );
        assert_eq!(body["active"], false, "repo must report inactive: {body}");
        assert_eq!(
            body["status"], "deactivated",
            "status must be deactivated: {body}"
        );
    })
    .await;

    step("reaper purges account past deleteAfter", || async {
        let resp = h
            .http
            .post(h.url("/xrpc/com.atproto.server.deactivateAccount"))
            .bearer_auth(&token)
            .json(&json!({ "deleteAfter": "2020-01-01T00:00:00Z" }))
            .send()
            .await
            .expect("deactivateAccount (deleteAfter) request");
        assert!(
            resp.status().is_success(),
            "deactivateAccount with deleteAfter status: {}",
            resp.status()
        );

        // The account is now due immediately; with a 1s reaper interval the purge should land
        // within a few passes. 30s is deliberately generous for a loaded CI runner — the loop
        // exits on the first 404.
        let status_url = h.url(&format!(
            "/xrpc/com.atproto.sync.getRepoStatus?did={}",
            enc(&did)
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let resp = h
                .http
                .get(&status_url)
                .send()
                .await
                .expect("getRepoStatus poll request");
            let status = resp.status();
            if status.as_u16() == 404 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "account was not reaped within 30s: getRepoStatus still returns {status}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
}

/// Read an unsigned LEB128 varint from the front of `buf`, returning `(value, bytes_consumed)`.
/// Used only to sanity-check the CAR header-length prefix. Returns `None` on a truncated varint.
fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}
