// pattern: Imperative Shell

use anyhow::Context;
use clap::Parser;
use reqwest::Client;
use std::{path::PathBuf, sync::Arc};

mod app;
mod auth;
mod blob_store;
mod db;
mod dns;
mod routes;
mod telemetry;
mod well_known;

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
#[command(name = "relay", about = "ezpds relay server")]
struct Cli {
    /// Path to relay.toml config file
    #[arg(long, env = "EZPDS_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config: if an explicit path is given via --config or EZPDS_CONFIG, error if missing.
    // Otherwise, tolerate a missing default relay.toml and load from env only.
    let config = if let Some(config_path) = cli.config {
        // Explicit config file: must exist
        common::load_config(&config_path)
            .with_context(|| format!("failed to load config from {}", config_path.display()))?
    } else {
        // Default relay.toml: tolerate absence, load from env only
        let default_path = PathBuf::from("relay.toml");
        match common::load_config(&default_path) {
            Ok(cfg) => cfg,
            Err(common::ConfigError::Io { .. }) => {
                // File not found: load from env only
                let env = common::collect_ezpds_env()
                    .context("failed to collect environment variables")?;
                common::load_config_from_env_only(&env)
                    .context("failed to load config from environment variables")?
            }
            Err(e) => return Err(e).context("failed to load config from relay.toml"),
        }
    };

    // Initialize tracing after config is loaded so telemetry settings can be applied.
    // Any config parse error surfaces via eprintln (the error propagation above); tracing
    // is not available until this line succeeds.
    //
    // IMPORTANT: must be `_otel_guard`, NOT bare `_`. A bare `_` binding drops
    // immediately (Rust only keeps `_foo` bindings alive for the scope), which would
    // shut down the OTLP exporter before the server starts.
    let _otel_guard = telemetry::init_subscriber(&config.telemetry)?;

    tracing::info!(
        bind_address = %config.bind_address,
        port = config.port,
        public_url = %config.public_url,
        "relay starting"
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

    let txt_resolver: Option<Arc<dyn dns::TxtResolver>> =
        match dns::HickoryTxtResolver::from_system_conf() {
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

    let well_known_resolver: Option<Arc<dyn well_known::WellKnownResolver>> = Some(Arc::new(
        well_known::HttpWellKnownResolver::new(http_client.clone()),
    ));

    let jwt_secret = auth::load_or_create_jwt_secret(
        &pool,
        config.signing_key_master_key.as_ref().map(|s| &*s.0),
    )
    .await
    .with_context(|| "failed to load or create JWT signing secret")?;

    let state = app::AppState {
        config: Arc::new(config),
        db: pool,
        http_client,
        dns_provider: None,
        txt_resolver,
        well_known_resolver,
        jwt_secret,
        oauth_signing_keypair,
        dpop_nonces: auth::new_nonce_store(),
        failed_login_attempts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    };

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind to {addr}"))?;

    tracing::info!(address = %addr, "listening");

    axum::serve(listener, app::app(state))
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

    tracing::info!("relay shut down");
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
