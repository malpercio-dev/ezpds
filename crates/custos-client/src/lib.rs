//! `custos-client`: the DPoP/OAuth/XRPC HTTP client shared by the identity-wallet and (in
//! future PRs) admin-companion Tauri apps. Tauri-free by design — it depends on nothing from
//! either app's `src-tauri`, so it can be reused by a platform-agnostic wallet core.
//!
//! - [`dpop`]: RFC 9449 DPoP proof construction/signing ([`DpopKeypair`]).
//! - [`error`]: the shared XRPC failure shape ([`PdsClientError`]) and the classification tail
//!   (`xrpc_ok`/`xrpc_json`) every XRPC call routes through, plus the [`TransportObserver`]
//!   seam apps use to record diagnostics breadcrumbs.
//! - [`oauth_client`]: [`OAuthClient`], the authenticated XRPC HTTP client (DPoP and Bearer
//!   modes).
//! - [`custos_client`]: [`CustosClient`], the pre-session HTTP client for one configured
//!   PDS — plain JSON/Bearer requests plus OAuth PAR/token-exchange.
//! - [`pds_client`]: [`PdsClient`], discovery/auth/XRPC against *arbitrary* PDS endpoints and
//!   plc.directory.
//! - [`identity`], [`app_passwords`], [`migration`]: typed XRPC methods over an authenticated
//!   [`OAuthClient`], grouped per concern (not re-exported at the crate root — reference them
//!   as `custos_client::identity::…` etc.). No method name collides across the 17 exported
//!   today, but grouping by concern means a future `get_preferences`-shaped name landing in
//!   two groups needs no rename — the module path already disambiguates it.
//! - [`agents`]: typed methods for auth.md's own agent-consent/child-lifecycle endpoints
//!   (not `com.atproto.*` XRPC, so they classify responses into their own [`agents::AgentError`]
//!   rather than [`error::PdsClientError`]). Minting a child account and post-recovery
//!   reconciliation stay in the app — they sign with wallet key material this crate does not
//!   hold.
//! - [`sovereign_session`]: [`sovereign_session::sovereign_login`] (the Custos passwordless
//!   full-access session ceremony over [`PdsClient`]) and the pure JWT helpers apps reuse to
//!   validate a restored session's sub/aud binding. No Keychain/persistence concept — the
//!   caller resolves signing and persists the result (see that module's doc).
//!
//! App-specific concerns this crate deliberately does not own: Keychain storage (apps supply
//! an `ios_device_key::KeychainStore` impl), diagnostics UI/export (apps supply a
//! [`TransportObserver`]), and the wallet's own OAuth client identity (`client_id`,
//! `redirect_uri`) — those stay in the app, since they name the app itself.

pub mod agents;
pub mod app_passwords;
mod base64url;
pub mod custos_client;
pub mod dpop;
pub mod error;
pub mod identity;
pub mod migration;
pub mod oauth_client;
pub mod pds_client;
pub mod sovereign_session;

pub use custos_client::{CustosClient, ParRequest, ParResponse, TokenErrorResponse};
pub use dpop::{DpopError, DpopKeypair};
pub use error::{
    classify_xrpc_error, classify_xrpc_response, error_code_is, parse_xrpc_error_envelope,
    xrpc_json, xrpc_ok, NoopObserver, PdsClientError, TransportObserver,
};
pub use oauth_client::{
    NoopTokenPersister, OAuthClient, OAuthError, OAuthSession, TokenPersister, TokenResponse,
};
pub use pds_client::{DescribeServerObserver, NoopDescribeServerObserver, PdsClient};

// Re-exported so callers can implement `DpopKeypair::get_or_create::<K>` against the same
// `KeychainStore` trait without a direct `ios-device-key` dependency of their own.
pub use ios_device_key::KeychainStore;
