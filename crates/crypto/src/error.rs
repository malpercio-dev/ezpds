#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("secret sharing failed: {0}")]
    SecretSharing(String),
    #[error("secret reconstruction failed: {0}")]
    SecretReconstruction(String),
}
