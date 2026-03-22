pub(crate) mod auth;
pub mod claim_codes;
pub mod create_account;
pub mod create_did;
pub mod create_handle;
pub mod create_mobile_account;
pub mod create_signing_key;
pub mod describe_server;
pub mod get_relay_signing_key;
pub mod health;
pub mod oauth_server_metadata;
pub mod register_device;
pub mod resolve_handle;

mod code_gen;
pub(crate) mod token;
pub(crate) mod uniqueness;

#[cfg(test)]
pub(crate) mod test_utils;
