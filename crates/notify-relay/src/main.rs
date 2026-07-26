// pattern: Imperative Shell
//
// Startup: load config, open the store, run migrations, load the node identity, bind the
// iroh endpoint, spawn the accept loop, and wait for a shutdown signal. Plus the
// operator-local `mint-code` subcommand — enrollment grants are minted at the relay's own
// shell, not over a remote admin surface, so there is no privileged network API at all.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;

mod config;
mod db;
mod identity;
mod protocol;
mod rate_limit;
mod service;
mod transport;

#[derive(Parser)]
#[command(
    name = "notify-relay",
    about = "ezpds notification relay (blind APNs courier)"
)]
struct Cli {
    /// Path to notify-relay.toml. Absent, the relay reads ./notify-relay.toml if present
    /// and otherwise takes every setting from the environment.
    #[arg(long, env = "EZPDS_NOTIFY_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Mint an enrollment grant code and print it. Hand the code to the instance
    /// operator; it is single-use and expires.
    MintCode {
        /// How long the code stays redeemable, e.g. `60m`, `24h`, `7d`, `900s`.
        #[arg(long, default_value = "60m")]
        ttl: String,
    },
}

/// Convert a config `database_url` (a plain path or a sqlx URL) into a sqlx URL.
fn to_sqlite_url(s: &str) -> String {
    if s.starts_with("sqlite:") {
        s.to_owned()
    } else if s.starts_with('/') {
        format!("sqlite://{s}")
    } else {
        format!("sqlite:{s}")
    }
}

/// Parse a `<number><s|m|h|d>` duration into seconds (Functional Core). A bare number is
/// read as seconds.
fn parse_ttl(spec: &str) -> anyhow::Result<i64> {
    let spec = spec.trim();
    let (digits, multiplier) = match spec.chars().last() {
        Some('s') => (&spec[..spec.len() - 1], 1),
        Some('m') => (&spec[..spec.len() - 1], 60),
        Some('h') => (&spec[..spec.len() - 1], 3600),
        Some('d') => (&spec[..spec.len() - 1], 86_400),
        _ => (spec, 1),
    };
    let value: i64 = digits
        .parse()
        .with_context(|| format!("invalid --ttl {spec:?}: expected e.g. 60m, 24h, 7d, 900s"))?;
    if value <= 0 {
        anyhow::bail!("--ttl must be positive");
    }
    value
        .checked_mul(multiplier)
        .context("--ttl is implausibly large")
}

/// A code an operator can read aloud: 120 bits of entropy as 24 base32 characters, in
/// four groups of six for transcription.
fn generate_enrollment_code() -> String {
    let mut bytes = [0u8; 15];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    let encoded = data_encoding::BASE32_NOPAD.encode(&bytes);
    encoded
        .as_bytes()
        .chunks(6)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

fn load_config(path: Option<PathBuf>) -> anyhow::Result<config::Config> {
    let env = config::collect_env().context("failed to collect environment variables")?;
    match path {
        // An explicitly named file must exist — a typo'd path silently falling back to
        // env-only config would run the relay under settings the operator never chose.
        Some(path) => config::load_with_env(&path, &env)
            .with_context(|| format!("failed to load config from {}", path.display())),
        None => {
            let default_path = PathBuf::from("notify-relay.toml");
            match config::load_with_env(&default_path, &env) {
                Ok(config) => Ok(config),
                Err(config::ConfigError::Io { .. }) => config::load_from_env_only(&env)
                    .context("failed to load config from environment variables"),
                Err(e) => Err(e).context("failed to load config from notify-relay.toml"),
            }
        }
    }
}

async fn open_store(config: &config::Config) -> anyhow::Result<sqlx::SqlitePool> {
    let url = to_sqlite_url(&config.database_url);
    let pool = db::open_pool(&url)
        .await
        .with_context(|| format!("failed to open database at {}", config.database_url))?;
    db::run_migrations(&pool)
        .await
        .context("failed to run database migrations")?;
    Ok(pool)
}

async fn run_mint_code(config_path: Option<PathBuf>, ttl: &str) -> anyhow::Result<()> {
    let ttl_secs = parse_ttl(ttl)?;
    let config = load_config(config_path)?;
    let pool = open_store(&config).await?;

    let code = generate_enrollment_code();
    let expires_at = db::enrollment_codes::insert_code(&pool, &code, ttl_secs)
        .await
        .context("failed to store the enrollment code")?;

    println!("enrollment code: {code}");
    println!("expires at:      {expires_at} UTC");
    println!("single use — the first node to redeem it is enrolled, and it cannot be reused");
    Ok(())
}

async fn run_serve(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    let config = Arc::new(load_config(config_path)?);
    let pool = open_store(&config).await?;

    let secret = identity::load_or_create_secret_key(&config.secret_key_path)?;
    let endpoint = transport::bind(secret, config.ipv6).await?;
    let node_id = endpoint.id().to_string();

    let service = Arc::new(service::RelayService::new(pool, Arc::clone(&config)));
    let accept = transport::spawn_accept_loop(endpoint.clone(), service);

    tracing::info!(
        %node_id,
        open_enrollment = config.open_enrollment,
        "notification relay listening; instances dial this node id"
    );
    println!("notify-relay node id: {node_id}");

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;
    tracing::info!("shutting down");
    endpoint.close().await;
    let _ = accept.await;
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match cli.command {
        Some(Command::MintCode { ref ttl }) => run_mint_code(cli.config.clone(), ttl).await,
        None => run_serve(cli.config).await,
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_units_parse() {
        assert_eq!(parse_ttl("900s").expect("seconds"), 900);
        assert_eq!(parse_ttl("60m").expect("minutes"), 3600);
        assert_eq!(parse_ttl("24h").expect("hours"), 86_400);
        assert_eq!(parse_ttl("7d").expect("days"), 604_800);
        assert_eq!(parse_ttl("30").expect("bare seconds"), 30);
    }

    #[test]
    fn a_nonpositive_or_malformed_ttl_is_refused() {
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("-5m").is_err());
        assert!(parse_ttl("soon").is_err());
    }

    #[test]
    fn a_minted_code_is_grouped_and_unpredictable() {
        let first = generate_enrollment_code();
        assert_eq!(first.len(), 27, "24 base32 chars in 6-char groups: {first}");
        assert_ne!(first, generate_enrollment_code());
    }

    #[test]
    fn database_urls_are_normalized() {
        assert_eq!(to_sqlite_url("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(to_sqlite_url("/data/relay.db"), "sqlite:///data/relay.db");
        assert_eq!(to_sqlite_url("relay.db"), "sqlite:relay.db");
    }
}
