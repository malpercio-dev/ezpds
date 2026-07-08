// pattern: Imperative Shell
//
// Shared harness machinery for the black-box HTTP integration suite. Everything here is I/O:
// it binds sockets, spawns the real compiled `pds` binary, mocks plc.directory over HTTP, and
// drives the server over real TCP. The `pds` crate is binary-only (no lib target), so the suite
// cannot call `app()` in-process — it must exercise the shipped binary through EZPDS_* config,
// which is the whole point: this covers the real migration/startup path, not `test_state()`.

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::json;
use tempfile::TempDir;
use tokio::time::sleep;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Fixed 32-byte signing-key master key (hex) handed to the child via
/// `EZPDS_SIGNING_KEY_MASTER_KEY`. Value is arbitrary; it only has to be a valid 64-char hex
/// string so the server can encrypt/decrypt reserved repo keys at rest.
const MASTER_KEY_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

/// A single served user domain. Handles created by the suite live under this domain so they pass
/// the server's `available_user_domains` policy check.
pub const USER_DOMAIN: &str = "test.example.com";

/// A running `pds` child process plus everything that must outlive it. Dropping this struct kills
/// the child (and waits for it) so a panicking test step never leaks a server process, and holds
/// the temp dir and the plc mock open for the server's whole lifetime.
pub struct Harness {
    child: Child,
    /// Base URL of the server, e.g. `http://127.0.0.1:53017`. Public so steps build request URLs.
    pub base_url: String,
    /// Bare `host:port` authority, used to build `ws://` firehose URLs.
    pub authority: String,
    /// Async reqwest client reused across every step.
    pub http: reqwest::Client,
    // Held only for their Drop / lifetime side effects.
    _temp: TempDir,
    _plc: MockServer,
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Best-effort teardown: kill then reap so a failed test never orphans the server.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reserve a free TCP port by binding to `:0`, reading the assigned port, then dropping the
/// listener so the child can rebind it. The gap between drop and rebind is a small accepted race.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("read local addr").port()
}

/// Start a plc.directory mock. Account creation POSTs the signed genesis op to `/{did}`; the mock
/// accepts any such POST with 200. A permissive audit-log GET is also mounted so any incidental
/// state read resolves locally instead of reaching the real network (AC3.1: no network access).
async fn start_plc_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/did:plc:[a-z2-7]+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/did:plc:[a-z2-7]+/log/audit$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    server
}

impl Harness {
    /// Boot a fresh server: mock plc.directory FIRST, pick a port, spawn the real binary against a
    /// temp-file SQLite DB, and await `/xrpc/_health` returning 200. Panics with a clear message on
    /// any failure — a harness that cannot start must never masquerade as a passing test.
    ///
    /// `free_port` releases its reservation before the child rebinds it, so a concurrent bind can
    /// steal the port; that lost race surfaces as a health timeout. Retry the whole spawn with a
    /// fresh port a bounded number of times so the race self-heals instead of flaking the run.
    pub async fn start() -> Self {
        const ATTEMPTS: u32 = 3;
        for attempt in 1..=ATTEMPTS {
            let harness = Self::spawn_once().await;
            match harness.wait_for_health().await {
                Ok(()) => return harness,
                Err(e) if attempt < ATTEMPTS => {
                    // The failed harness's Drop kills the child before the next attempt.
                    eprintln!(
                        "harness start attempt {attempt} failed ({e}); retrying with a fresh port"
                    );
                }
                Err(e) => panic!("pds server failed to start after {ATTEMPTS} attempts: {e}"),
            }
        }
        unreachable!("the attempt loop either returns a healthy harness or panics");
    }

    /// One spawn attempt: everything in [`Harness::start`] except the health wait.
    async fn spawn_once() -> Self {
        let plc = start_plc_mock().await;
        let plc_url = plc.uri();

        let temp = tempfile::tempdir().expect("create temp data dir");
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let db_path = data_dir.join("pds.db");

        let port = free_port();
        let base_url = format!("http://127.0.0.1:{port}");
        let authority = format!("127.0.0.1:{port}");

        let bin = env!("CARGO_BIN_EXE_pds");
        let mut cmd = Command::new(bin);
        cmd.env_clear();
        // Preserve PATH so any dynamically-loaded system libs resolve; everything else is explicit.
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("EZPDS_BIND_ADDRESS", "127.0.0.1")
            .env("EZPDS_PORT", port.to_string())
            .env("EZPDS_DATA_DIR", &data_dir)
            .env(
                "EZPDS_DATABASE_URL",
                db_path.to_str().expect("utf-8 db path"),
            )
            // public_url must be https:// to satisfy the OAuth-issuer config check, even though the
            // socket itself binds plaintext http on loopback. describeServer derives a did:web from
            // this host; the suite does not assert the DID value, so the scheme mismatch is benign.
            .env("EZPDS_PUBLIC_URL", format!("https://{authority}"))
            .env("EZPDS_AVAILABLE_USER_DOMAINS", USER_DOMAIN)
            // No invite gate: the simplest path the config supports (the alternative is minting a
            // code through the admin route as an extra step).
            .env("EZPDS_INVITE_CODE_REQUIRED", "false")
            // Traces off (no OTLP exporter reachable), metrics ON (the suite scrapes /metrics).
            .env("EZPDS_TELEMETRY_ENABLED", "false")
            .env("EZPDS_METRICS_ENABLED", "true")
            // No throttling during the suite.
            .env("EZPDS_RATE_LIMIT_ENABLED", "false")
            // No outbound crawl notifications — keeps the run fully offline.
            .env("EZPDS_CRAWLERS", "")
            // All plc.directory traffic is redirected to the mock.
            .env("EZPDS_PLC_DIRECTORY_URL", &plc_url)
            // Reaper every second, so the deactivate→reap lifecycle leg can poll for the purge
            // instead of waiting out the 1-hour default.
            .env("EZPDS_ACCOUNTS_DELETION_REAPER_INTERVAL_SECS", "1")
            .env("EZPDS_SIGNING_KEY_MASTER_KEY", MASTER_KEY_HEX);

        let child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn pds binary at {bin}: {e}"));

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build reqwest client");

        Harness {
            child,
            base_url,
            authority,
            http,
            _temp: temp,
            _plc: plc,
        }
    }

    /// Poll `/xrpc/_health` until it returns 200 or a ~30s deadline elapses. The timeout is an
    /// `Err` (not a panic) so [`Harness::start`] can retry a lost port race with a fresh port.
    async fn wait_for_health(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let url = format!("{}/xrpc/_health", self.base_url);
        loop {
            if let Ok(resp) = self.http.get(&url).send().await {
                if resp.status().is_success() {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("no healthy response from {url} within 30s"));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `ws://host:port/path` URL for the firehose WebSocket.
    pub fn ws_url(&self, path: &str) -> String {
        format!("ws://{}{}", self.authority, path)
    }
}

/// A created account plus the credentials the rest of the suite needs.
pub struct Account {
    pub did: String,
    #[allow(dead_code)]
    pub handle: String,
    #[allow(dead_code)]
    pub password: String,
    pub access_jwt: String,
}

/// Build a self-signed did:plc genesis op the way `create_account_xrpc`'s unit tests do:
/// rotationKeys[0] is a fresh device key that signs the op; verificationMethods.atproto (and
/// rotationKeys[1]) is `atproto_key_did`, the reserved per-account key the server holds. Returns
/// the op JSON ready to embed as the request's `plcOp`.
fn signed_genesis_op(handle: &str, public_url: &str, atproto_key_did: &str) -> serde_json::Value {
    use crypto::{build_did_plc_genesis_op, generate_p256_keypair, DidKeyUri};
    let device = generate_p256_keypair().expect("device keypair");
    let device_private = *device.private_key_bytes;
    let op = build_did_plc_genesis_op(
        &device.key_id,
        &DidKeyUri(atproto_key_did.to_string()),
        &device_private,
        handle,
        public_url,
    )
    .expect("build genesis op");
    serde_json::from_str(&op.signed_op_json).expect("genesis op is valid JSON")
}

/// Reserve a per-account signing key over HTTP (`reserveSigningKey`), then create a new account by
/// submitting a self-signed genesis op referencing that reserved key — mirroring the real
/// onboarding ceremony and the construction in `create_account_xrpc`'s tests. Panics on any
/// non-success so a broken precondition surfaces immediately.
pub async fn create_account(h: &Harness, handle: &str, email: &str, password: &str) -> Account {
    let reserve: serde_json::Value = h
        .http
        .post(h.url("/xrpc/com.atproto.server.reserveSigningKey"))
        .json(&json!({}))
        .send()
        .await
        .expect("reserveSigningKey request")
        .json()
        .await
        .expect("reserveSigningKey json");
    let atproto_key = reserve["signingKey"]
        .as_str()
        .expect("reserveSigningKey returned a signingKey")
        .to_string();

    // The genesis op's service endpoint must match the public_url the server was configured with.
    let public_url = format!("https://{}", h.authority);
    let op = signed_genesis_op(handle, &public_url, &atproto_key);

    let resp = h
        .http
        .post(h.url("/xrpc/com.atproto.server.createAccount"))
        .json(&json!({
            "handle": handle,
            "email": email,
            "password": password,
            "plcOp": op,
        }))
        .send()
        .await
        .expect("createAccount request");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("createAccount json");
    assert!(
        status.is_success(),
        "createAccount failed ({status}): {body}"
    );

    Account {
        did: body["did"].as_str().expect("did in response").to_string(),
        handle: handle.to_string(),
        password: password.to_string(),
        access_jwt: body["accessJwt"]
            .as_str()
            .expect("accessJwt in response")
            .to_string(),
    }
}
