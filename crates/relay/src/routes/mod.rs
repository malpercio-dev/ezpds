pub(crate) mod auth;
pub mod claim_codes;
pub mod create_account;
pub mod create_did;
pub mod create_mobile_account;
pub mod create_signing_key;
pub mod describe_server;
pub mod health;
pub mod register_device;

mod code_gen;

#[cfg(test)]
pub(crate) mod test_utils;
