pub(crate) mod auth;
pub mod claim_codes;
pub mod create_account;
pub mod create_did;
pub mod create_handle;
pub mod create_mobile_account;
pub mod create_session;
pub mod create_signing_key;
pub mod describe_server;
pub mod get_relay_signing_key;
pub mod get_session;
pub mod health;
pub mod oauth_authorize;
pub mod oauth_jwks;
pub mod oauth_par;
pub mod oauth_server_metadata;
pub(super) mod oauth_templates;
pub mod oauth_token;
pub mod provisioning_session;
pub mod refresh_session;
pub mod register_device;
pub mod resolve_handle;

mod code_gen;
pub(crate) mod token;
pub(crate) mod uniqueness;

#[cfg(test)]
pub(crate) mod test_utils;
