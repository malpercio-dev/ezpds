// crypto: signing, Shamir secret sharing, DID operations.

pub mod error;
pub mod keys;
pub mod plc;
pub mod shamir;

pub use error::CryptoError;
pub use keys::{
    decrypt_private_key, encrypt_private_key, generate_p256_keypair, DidKeyUri, P256Keypair,
};
pub use plc::{build_did_plc_genesis_op, PlcGenesisOp};
pub use shamir::{combine_shares, split_secret, ShamirShare};
