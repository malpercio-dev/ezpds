// crypto: signing, Shamir secret sharing, DID operations.

pub mod error;
pub mod keys;

pub use error::CryptoError;
pub use keys::{
    decrypt_private_key, encrypt_private_key, generate_p256_keypair, DidKeyUri, P256Keypair,
};
