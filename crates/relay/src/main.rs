use anyhow::Context;
use clap::Parser;
use std::{path::PathBuf, sync::Arc};

mod app;
#[allow(dead_code)]
mod db;

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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .map_err(|e| anyhow::anyhow!("failed to initialize tracing subscriber: {e}"))?;

    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("relay.toml"));

    let config = common::load_config(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;

    tracing::info!(
        bind_address = %config.bind_address,
        port = config.port,
        public_url = %config.public_url,
        "relay starting"
    );

    let addr = format!("{}:{}", config.bind_address, config.port);
    let state = app::AppState {
        config: Arc::new(config),
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
