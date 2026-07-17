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
    #[error("share envelope has unsupported version: {0}")]
    ShareVersion(String),
    #[error("share envelope checksum mismatch: {0}")]
    ShareChecksum(String),
    #[error("share envelope malformed: {0}")]
    ShareFormat(String),
    #[error("plc operation failed: {0}")]
    PlcOperation(String),
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),
}
