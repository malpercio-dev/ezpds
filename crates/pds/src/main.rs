// pattern: Imperative Shell

use anyhow::Context;
use clap::Parser;
use reqwest::Client;
use std::{path::PathBuf, sync::Arc};

mod account_delete;
mod account_reaper;
mod admin_nonce_sweep;
mod agent_claim_sweep;
mod app;
mod auth;
mod blob_gc;
mod blob_store;
mod code_gen;
mod crawler;
mod db;
mod email;
mod firehose;
mod firehose_gc;
mod identity;
mod iroh_tunnel;
mod lexicon;
mod metrics;
mod no_input;
mod platform;
mod rate_limit;
mod read_after_write;
mod record_write;
mod repo_rev;
mod request_host;
mod rewrap;
mod routes;
mod session_issuer;
mod state;
mod sweep_status;
mod telemetry;
mod time;
mod transfer;
mod uniqueness;
mod xrpc_dispatch;

/// Convert a config database_url (which may be a plain filesystem path or a sqlx URL) to a valid sqlx URL.
///
/// - If the URL already starts with "sqlite:", pass through unchanged.
/// - If the URL is an absolute path (starts with "/"), format as "sqlite:///path".
/// - If the URL is a relative path, format as "sqlite:path" and log a warning
///   (CWD-relative paths are sensitive to working directory).
fn to_sqlite_url(s: &str) -> String {
    if s.starts_with("sqlite:") {
        s.to_string()
    } else if s.starts_with('/') {
        format!("sqlite://{s}")
    } else {
        tracing::warn!(
            path = s,
            "using relative-path database URL; this is sensitive to working directory"
        );
        format!("sqlite:{s}")
    }
}

#[derive(Parser)]
#[command(name = "pds", about = "ezpds PDS server (Custos)")]
struct Cli {
    /// Path to pds.toml config file
    #[arg(long, env = "EZPDS_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Re-encrypt every KEK-wrapped secret under a new master key (offline
    /// maintenance; the server must be stopped — the DB pool is
    /// single-connection). Reads the old and new 64-hex-char keys from the
    /// EZPDS_REWRAP_OLD_MASTER_KEY and EZPDS_REWRAP_NEW_MASTER_KEY environment
    /// variables (env-only, so key material never appears in process listings
    /// or shell history). On success, set EZPDS_SIGNING_KEY_MASTER_KEY to the
    /// new key before restarting the server.
    RewrapMasterKey,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

/// Load config: if an explicit path is given via --config or EZPDS_CONFIG, error if missing.
/// Otherwise, tolerate a missing default pds.toml and load from env only.
fn load_config_auto(config_path: Option<PathBuf>) -> anyhow::Result<common::Config> {
    if let Some(config_path) = config_path {
        // Explicit config file: must exist
        common::load_config(&config_path)
            .with_context(|| format!("failed to load config from {}", config_path.display()))
    } else {
        // Default pds.toml: tolerate absence, load from env only
        let default_path = PathBuf::from("pds.toml");
        match common::load_config(&default_path) {
            Ok(cfg) => Ok(cfg),
            Err(common::ConfigError::Io { .. }) => {
                // File not found: load from env only
                let env = common::collect_ezpds_env()
                    .context("failed to collect environment variables")?;
                common::load_config_from_env_only(&env)
                    .context("failed to load config from environment variables")
            }
            Err(e) => Err(e).context("failed to load config from pds.toml"),
        }
    }
}

/// Read and validate a 64-hex-char master key from an environment variable.
fn rewrap_key_from_env(var: &'static str) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    let value = std::env::var(var)
        .map_err(|_| anyhow::anyhow!("{var} must be set (64 hex characters, 32 bytes)"))?;
    Ok(zeroize::Zeroizing::new(common::parse_hex_32(var, &value)?))
}

/// The `rewrap-master-key` subcommand: open the DB named by the ordinary
/// config (env/pds.toml), apply pending migrations so every wrapped table
/// exists, and re-encrypt all KEK-wrapped secrets old→new in one transaction.
async fn run_rewrap(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let old_key = rewrap_key_from_env("EZPDS_REWRAP_OLD_MASTER_KEY")?;
    let new_key = rewrap_key_from_env("EZPDS_REWRAP_NEW_MASTER_KEY")?;

    let config = load_config_auto(config_path)?;
    let db_url = to_sqlite_url(&config.database_url);
    let pool = db::open_pool(&db_url)
        .await
        .with_context(|| format!("failed to open database at {}", config.database_url))?;
    db::run_migrations(&pool)
        .await
        .with_context(|| "failed to run database migrations")?;

    let report = rewrap::rewrap_master_key(&pool, &old_key, &new_key).await?;

    println!(
        "master-key re-wrap complete (KEK generation {}):",
        report.kek_generation
    );
    for (table, count) in &report.families {
        println!("  {table}: {count} row(s) re-encrypted");
    }
    println!("  total: {} row(s)", report.total());
    println!("next: set EZPDS_SIGNING_KEY_MASTER_KEY to the new key, then start the server");
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    // Captured before any startup work (config load, migrations, key setup) so the health
    // endpoint's uptime reflects process start, not listen start.
    let started_at = std::time::Instant::now();
    let cli = Cli::parse();

    if let Some(Command::RewrapMasterKey) = cli.command {
        return run_rewrap(cli.config).await;
    }

    let mut config = load_config_auto(cli.config)?;

    // Initialize tracing after config is loaded so telemetry settings can be applied.
    // Any config parse error surfaces via eprintln (the error propagation above); tracing
    // is not available until this line succeeds.
    //
    // IMPORTANT: must be `_otel_guard`, NOT bare `_`. A bare `_` binding drops
    // immediately (Rust only keeps `_foo` bindings alive for the scope), which would
    // shut down the OTLP exporter before the server starts.
    let _otel_guard = telemetry::init_subscriber(&config.telemetry)?;

    // Canonicalize the operator-configured agent scope tokens so scope clamping matches them by
    // exact string; a mistyped/unsupported token fails fast here instead of silently dropping the
    // capability when an agent assertion is minted.
    config.agent_auth.granted_scopes =
        auth::oauth_scopes::canonicalize_agent_scopes(&config.agent_auth.granted_scopes)
            .map_err(|e| anyhow::anyhow!("invalid [agent_auth] granted_scopes: {e}"))?;
    config.agent_auth.pre_claim_scopes =
        auth::oauth_scopes::canonicalize_agent_scopes(&config.agent_auth.pre_claim_scopes)
            .map_err(|e| anyhow::anyhow!("invalid [agent_auth] pre_claim_scopes: {e}"))?;

    tracing::info!(
        bind_address = %config.bind_address,
        port = config.port,
        public_url = %config.public_url,
        "pds starting"
    );

    let addr = format!("{}:{}", config.bind_address, config.port);

    // **Intentional deviation from design:** The design doc's startup sequence shows
    // `open_pool(&config.database_url)` directly. However, `config.database_url` defaults
    // to a plain filesystem path (e.g. `/var/pds/relay.db`) when not explicitly set, which
    // is not a valid sqlx URL. We format it here rather than changing Config or open_pool,
    // keeping both functions general-purpose.
    let db_url = to_sqlite_url(&config.database_url);

    let pool = db::open_pool(&db_url)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "fatal: failed to open database pool");
            e
        })
        .with_context(|| format!("failed to open database at {}", config.database_url))?;

    db::run_migrations(&pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "fatal: failed to run database migrations");
            e
        })
        .with_context(|| {
            format!(
                "failed to run database migrations on {}",
                config.database_url
            )
        })?;

    let oauth_signing_keypair = auth::load_or_create_oauth_signing_key(
        &pool,
        config.signing_key_master_key.as_ref().map(|s| &*s.0),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "fatal: failed to load OAuth signing key");
        e
    })
    .with_context(|| "failed to load or create OAuth signing keypair")?;

    let http_client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    // Shared, pooled client for every SSRF-guarded fetch to a caller-influenced target
    // (atproto-proxy header target, did:web document, handle well-known endpoint,
    // Lexicon-authority permission-set record): redirects disabled + a DNS resolver that
    // re-checks the public-address allowlist at connect time. `false` (never `allow_loopback`) in
    // production.
    let hardened_http_client = identity::proxy::build_hardened_client(false)
        .expect("failed to build hardened HTTP client");

    let txt_resolver: Option<Arc<dyn identity::dns::TxtResolver>> =
        match identity::dns::HickoryTxtResolver::from_system_conf() {
            Ok(r) => {
                tracing::info!("DNS TXT resolver initialised (handle resolution fallback enabled)");
                Some(Arc::new(r))
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to initialise DNS TXT resolver; handle resolution will be local-only"
                );
                None
            }
        };

    let well_known_resolver: Option<Arc<dyn identity::well_known::WellKnownResolver>> =
        Some(Arc::new(identity::well_known::HttpWellKnownResolver::new(
            hardened_http_client.clone(),
        )));

    // Dynamic-trust JWKS cache for the auth.md `identity_assertion` flow: reuses the shared HTTP
    // client and the operator-configured cache TTL + refetch cooldown (the anti-amplification
    // bound for the public agent-auth endpoints). The static-PEM trust path never touches it.
    let jwks_cache = Arc::new(auth::jwks::JwksCache::new(
        Arc::new(auth::jwks::HttpJwksFetcher::new(http_client.clone())),
        std::time::Duration::from_secs(config.agent_auth.jwks_cache_ttl_secs),
        std::time::Duration::from_secs(config.agent_auth.jwks_refetch_cooldown_secs),
    ));

    let jwt_secret = auth::load_or_create_jwt_secret(
        &pool,
        config.signing_key_master_key.as_ref().map(|s| &*s.0),
    )
    .await
    .with_context(|| "failed to load or create JWT signing secret")?;

    // Iroh tunnel: when enabled, load (or generate on first boot) the persistent Ed25519
    // identity so the pds advertises a stable node id across restarts, then bind the QUIC
    // endpoint. Disabled by default, so a plain pds does no Iroh work at all. A bind failure
    // is fatal — if the operator asked for the tunnel, starting without it would silently
    // drop a configured capability.
    let iroh = if config.iroh.enabled {
        let secret = auth::load_or_create_iroh_secret_key(
            &pool,
            config.signing_key_master_key.as_ref().map(|s| &*s.0),
        )
        .await
        .with_context(|| "failed to load or create Iroh node identity")?;
        let iroh_state = iroh_tunnel::start(secret, config.iroh.ipv6)
            .await
            .with_context(|| "failed to bind Iroh endpoint")?;
        tracing::info!(node_id = %iroh_state.node_id, "Iroh endpoint bound");
        Some(Arc::new(iroh_state))
    } else {
        None
    };

    // Build the metrics pipeline from config before `config` is moved into the AppState's Arc,
    // and before the subsystems that record through it (crawler, firehose) are constructed.
    // A broken exporter is fatal here rather than failing every scrape at runtime.
    let metrics = Arc::new(if config.telemetry.metrics_enabled {
        let m = metrics::Metrics::new(&config.telemetry.service_name)
            .with_context(|| "failed to build metrics pipeline")?;
        tracing::info!("metrics enabled: serving Prometheus exposition at /metrics");
        m
    } else {
        tracing::info!("metrics disabled: /metrics is not registered");
        metrics::Metrics::disabled()
    });

    // Crawler notifier: after each commit, ping the configured relays/BGSes via requestCrawl.
    // The hostname advertised to crawlers is derived from the relay's public URL.
    let crawler_hostname = crawler::host_from_url(&config.public_url);
    let crawlers = Arc::new({
        let mut c = crawler::CrawlerNotifier::new(
            http_client.clone(),
            crawler_hostname,
            &config.crawlers.urls,
        );
        c.attach_metrics(metrics.clone());
        c
    });
    if config.crawlers.urls.is_empty() {
        tracing::info!("crawler notifications disabled (no crawlers configured)");
    } else {
        tracing::info!(
            crawlers = ?config.crawlers.urls,
            "crawler notifications enabled"
        );
    }

    // Seed the firehose sequencer from the persisted event log so `seq` continues monotonically
    // across restarts and cursor replay survives redeploys (the log is read back from `repo_seq`).
    let firehose = Arc::new({
        let mut f = firehose::Firehose::new(pool.clone())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "fatal: failed to initialise firehose sequencer");
                e
            })
            .with_context(|| "failed to initialise firehose sequencer from the event log")?;
        f.attach_metrics(metrics.clone());
        f
    });

    // Build the outbound email sender from config before `config` is moved into the AppState's Arc.
    // A misconfigured SMTP setup is fatal here rather than failing every send at runtime.
    let email = email::build_email_sender(&config.email)
        .with_context(|| "failed to build outbound email sender")?;
    match config.email.provider {
        common::EmailProvider::Smtp => tracing::info!(
            host = config.email.smtp_host.as_deref().unwrap_or(""),
            "outbound email: SMTP delivery enabled"
        ),
        common::EmailProvider::Mailtrap => tracing::info!(
            api_url = config
                .email
                .http_api_url
                .as_deref()
                .unwrap_or(common::MAILTRAP_SEND_API_URL),
            "outbound email: Mailtrap HTTP-API delivery enabled"
        ),
        common::EmailProvider::Log => {
            tracing::warn!("outbound email: using the log provider (messages are not sent)")
        }
    }

    // Build the rate limiter from config before `config` is moved into the AppState's Arc.
    let rate_limiter = Arc::new(rate_limit::RateLimiterState::new(&config.rate_limit));
    if config.rate_limit.enabled {
        tracing::info!(
            global_ip_per_5min = config.rate_limit.global_ip_per_5min,
            write_points_hourly = config.rate_limit.write_points_hourly,
            write_points_daily = config.rate_limit.write_points_daily,
            "request rate limiting enabled"
        );
    } else {
        tracing::warn!("request rate limiting is disabled");
    }

    let state = app::AppState {
        config: Arc::new(config),
        db: pool,
        http_client,
        hardened_http_client,
        dns_provider: None,
        txt_resolver,
        well_known_resolver,
        jwks_cache,
        jwt_secret,
        oauth_signing_keypair,
        dpop_nonces: auth::new_nonce_store(),
        poll_tracker: auth::new_claim_poll_tracker(),
        permission_set_cache: auth::new_permission_set_cache(),
        failed_login_attempts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        firehose,
        crawlers,
        iroh,
        rate_limiter,
        email,
        allow_loopback_proxy_targets: false,
        metrics,
        repo_write_locks: Arc::new(record_write::RepoWriteLocks::new()),
        sweeps: Arc::new(sweep_status::SweepStatus::default()),
        started_at,
    };

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;

    tracing::info!(address = %addr, "listening");

    // Spawn the periodic blob garbage collector. It reclaims unreferenced and expired blobs;
    // it is best-effort and runs for the life of the process, so the handle is dropped on
    // shutdown rather than joined.
    let gc_interval = std::time::Duration::from_secs(state.config.blobs.gc_interval_secs);
    let _blob_gc = blob_gc::spawn_blob_gc(state.clone(), gc_interval);
    tracing::info!(
        interval_secs = state.config.blobs.gc_interval_secs,
        "blob garbage collector started"
    );

    // Spawn the periodic `repo_seq` firehose event-log retention sweep. It prunes rows below the
    // configured age/count watermark so the durable log backing
    // `subscribeRepos` cursor replay does not grow without bound; it is best-effort and runs for
    // the life of the process, so the handle is dropped on shutdown rather than joined.
    let fh_gc_interval = std::time::Duration::from_secs(state.config.firehose.gc_interval_secs);
    let _firehose_gc = firehose_gc::spawn_firehose_gc(state.clone(), fh_gc_interval);
    tracing::info!(
        interval_secs = state.config.firehose.gc_interval_secs,
        retention_secs = state.config.firehose.log_retention_secs,
        retention_count = state.config.firehose.log_retention_count,
        "firehose repo_seq retention sweep started"
    );

    // Spawn the scheduled-deletion reaper. Each pass permanently deletes accounts whose
    // `deleteAfter` (set by deactivateAccount) has elapsed; like the GC tasks it is best-effort and
    // runs for the life of the process, so the handle is dropped on shutdown rather than joined.
    let reaper_interval =
        std::time::Duration::from_secs(state.config.accounts.deletion_reaper_interval_secs);
    let _account_reaper = account_reaper::spawn_account_reaper(state.clone(), reaper_interval);
    tracing::info!(
        interval_secs = state.config.accounts.deletion_reaper_interval_secs,
        "scheduled account-deletion reaper started"
    );

    // Spawn the agent-claim-attempt expiry sweep. Each pass flips lapsed pending claim attempts to
    // `expired` and records a `claim_expired` audit event for each, so a wallet's per-agent history
    // reports how every ceremony ended; like the GC tasks it is best-effort and runs for the life
    // of the process, so the handle is dropped on shutdown rather than joined.
    let claim_sweep_interval =
        std::time::Duration::from_secs(state.config.agent_auth.claim_sweep_interval_secs);
    let _agent_claim_sweep =
        agent_claim_sweep::spawn_agent_claim_sweep(state.clone(), claim_sweep_interval);
    tracing::info!(
        interval_secs = state.config.agent_auth.claim_sweep_interval_secs,
        "agent claim-attempt expiry sweep started"
    );

    // Spawn the admin-nonce retention sweep. Each pass deletes `admin_nonces` rows older than
    // the configured max age; anti-replay is enforced by the `(device_id, nonce)` primary key
    // as long as the row survives the request's full replay-acceptance window, which config
    // validation guarantees `nonce_max_age_secs` exceeds — so this is pure storage reclamation.
    // Like the GC tasks it is best-effort and runs for the life of the process, so the handle
    // is dropped on shutdown rather than joined.
    let nonce_sweep_interval =
        std::time::Duration::from_secs(state.config.admin_devices.nonce_sweep_interval_secs);
    let nonce_max_age_secs = i64::try_from(state.config.admin_devices.nonce_max_age_secs)
        .expect("admin_devices.nonce_max_age_secs is validated to fit in i64 at config load");
    let _admin_nonce_sweep = admin_nonce_sweep::spawn_admin_nonce_sweep(
        state.clone(),
        nonce_sweep_interval,
        nonce_max_age_secs,
    );
    tracing::info!(
        interval_secs = state.config.admin_devices.nonce_sweep_interval_secs,
        max_age_secs = state.config.admin_devices.nonce_max_age_secs,
        "admin-nonce retention sweep started"
    );

    // Spawn the Iroh accept loop when the tunnel is enabled. Like the blob GC it is detached
    // and runs for the life of the endpoint; closing the endpoint at shutdown ends the loop.
    // Keep a clone of the endpoint state so we can close it after the HTTP server stops.
    let iroh_shutdown = state.iroh.clone();
    if let Some(iroh) = &state.iroh {
        let _iroh_accept = iroh_tunnel::spawn_accept_loop(iroh.endpoint.clone());
        tracing::info!("iroh accept loop started");
    }

    axum::serve(
        listener,
        app::app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        if let Err(e) = shutdown_signal().await {
            tracing::error!(error = %e, "signal handler error");
        }
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "axum server exited with error");
        anyhow::anyhow!("server error: {e}")
    })?;

    // The HTTP server has stopped. Close the Iroh endpoint so in-flight connections drain and
    // the accept loop exits cleanly (accept() yields None once the endpoint is closed).
    if let Some(iroh) = iroh_shutdown {
        iroh.endpoint.close().await;
        tracing::info!("iroh endpoint closed");
    }

    tracing::info!("pds shut down");
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .context("failed to install Ctrl+C handler")
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?
            .recv()
            .await;
        Ok(())
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<anyhow::Result<()>>();

    tokio::select! {
        result = ctrl_c => result,
        result = terminate => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_sqlite_url_passthrough_sqlite_prefix() {
        assert_eq!(to_sqlite_url("sqlite:relay.db"), "sqlite:relay.db");
        assert_eq!(to_sqlite_url("sqlite::memory:"), "sqlite::memory:");
    }

    #[test]
    fn to_sqlite_url_absolute_path() {
        assert_eq!(
            to_sqlite_url("/var/pds/relay.db"),
            "sqlite:///var/pds/relay.db"
        );
        assert_eq!(to_sqlite_url("/tmp/test.db"), "sqlite:///tmp/test.db");
    }

    #[test]
    fn to_sqlite_url_relative_path() {
        assert_eq!(to_sqlite_url("relay.db"), "sqlite:relay.db");
        assert_eq!(to_sqlite_url("./data/relay.db"), "sqlite:./data/relay.db");
    }
}
