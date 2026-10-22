pub mod code_gen;
mod config;
mod config_loader;
mod email;
mod error;
pub mod html;
mod ident;
pub mod token;

pub use config::{
    default_reserved_handles, parse_hex_32, replay_span_secs, retention_covers_replay,
    AccountsConfig, AdminDevicesConfig, AgentAuthConfig, AppViewConfig, BlobMirrorConfig,
    BlobScrubConfig, BlobsConfig, ChatConfig, Config, ConfigError, ContactConfig, CrawlersConfig,
    EmailConfig, EmailProvider, FirehoseConfig, IrohConfig, LabelerConfig, LogFormat,
    NotificationsConfig, OAuthConfig, RateLimitConfig, RecoveryConfig, Sensitive,
    ServerLinksConfig, SmtpTls, SpacesConfig, TelemetryConfig, TrustedIssuer, WaitlistConfig,
    WatchedLabeler, ADMIN_TIMESTAMP_WINDOW_SECS, MAILTRAP_SEND_API_URL,
    SOVEREIGN_TIMESTAMP_WINDOW_SECS,
};
pub use config_loader::{
    collect_ezpds_env, load_config, load_config_from_env_only, load_config_with_env,
};
pub use email::{is_plausible_email, normalize_email};
pub use error::{ApiError, ApiErrorParts, ApiResultExt, ErrorCode};
pub use ident::{is_valid_did, validate_handle_structure, Did, Handle, InvalidIdentifier};
