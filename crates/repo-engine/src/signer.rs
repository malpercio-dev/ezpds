// repo-engine: Commit signer for ATProto repository commits.
//
// Wraps P-256 ECDSA signing for use with atrium-repo's CommitBuilder::finalize.
// The signer receives the CBOR-encoded unsigned commit bytes and returns
// the 64-byte r‖s P-256 ECDSA signature.

use p256::ecdsa::{signature::Signer, Signature, SigningKey};

/// Errors from commit signing operations.
#[derive(Debug, thiserror::Error)]
pub enum CommitSignerError {
    #[error("invalid P-256 private key: {0}")]
    InvalidKey(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// A P-256 ECDSA signer for ATProto repository commits.
///
/// Holds the signing key and produces 64-byte r‖s signatures compatible
/// with atrium-repo's `CommitBuilder::finalize`.
///
/// # Usage
///
/// ```rust,ignore
/// use repo_engine::CommitSigner;
///
/// let signer = CommitSigner::from_bytes(&private_key_bytes)?;
/// let commit_builder = repo.commit().await?;
/// let sig = signer.sign(&commit_builder.bytes())?;
/// let commit_cid = commit_builder.finalize(sig).await?;
/// ```
pub struct CommitSigner {
    key: SigningKey,
}

impl CommitSigner {
    /// Create a signer from raw 32-byte P-256 private key scalar.
    ///
    /// # Errors
    /// Returns `CommitSignerError::InvalidKey` if the bytes are not a valid
    /// P-256 scalar (e.g. all-zero, or value ≥ curve order).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CommitSignerError> {
        let key = SigningKey::from_bytes(bytes.into())
            .map_err(|e| CommitSignerError::InvalidKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Sign the given commit bytes and return the 64-byte r‖s signature.
    ///
    /// The bytes are typically from `CommitBuilder::bytes()` — the CBOR-encoded
    /// unsigned commit. The returned signature is compatible with
    /// `CommitBuilder::finalize(sig)`.
    pub fn sign(&self, commit_bytes: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(commit_bytes);
        // ATProto requires canonical low-S signatures; ~half of raw P-256 signatures
        // are high-S and would be rejected by network verifiers. normalize_s() returns
        // Some(normalized) only when the original was high-S.
        let sig = sig.normalize_s().unwrap_or(sig);
        sig.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    #[test]
    fn from_valid_key_succeeds() {
        // Generate a valid P-256 key.
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = signing_key.to_bytes().into();

        let signer = CommitSigner::from_bytes(&bytes);
        assert!(signer.is_ok(), "valid key should succeed");
    }

    #[test]
    fn from_zero_key_returns_error() {
        let zero_bytes = [0u8; 32];
        let result = CommitSigner::from_bytes(&zero_bytes);
        assert!(result.is_err(), "zero key should return InvalidKey error");
    }

    #[test]
    fn sign_produces_64_byte_signature() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = signing_key.to_bytes().into();
        let signer = CommitSigner::from_bytes(&bytes).unwrap();

        let message = b"test commit bytes for signing";
        let sig = signer.sign(message);

        assert_eq!(sig.len(), 64, "P-256 signature must be 64 bytes (r‖s)");
    }

    #[test]
    fn sign_is_deterministic() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = signing_key.to_bytes().into();
        let signer = CommitSigner::from_bytes(&bytes).unwrap();

        let message = b"deterministic test";
        let sig1 = signer.sign(message);
        let sig2 = signer.sign(message);

        assert_eq!(
            sig1, sig2,
            "same input must produce same signature (RFC 6979)"
        );
    }

    #[test]
    fn sign_verifies_with_corresponding_public_key() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let bytes: [u8; 32] = signing_key.to_bytes().into();
        let signer = CommitSigner::from_bytes(&bytes).unwrap();

        let message = b"verify this signature";
        let sig_bytes = signer.sign(message);

        let signature = Signature::from_slice(&sig_bytes).expect("valid signature bytes");
        assert!(
            verifying_key.verify(message, &signature).is_ok(),
            "signature must verify with the corresponding public key"
        );
    }

    #[test]
    fn sign_produces_low_s_signatures() {
        // ATProto requires canonical low-S signatures; verifiers reject high-S.
        // Sample many keys/messages — roughly half of un-normalized P-256 sigs are high-S.
        for i in 0..256u32 {
            let signing_key = SigningKey::random(&mut rand_core::OsRng);
            let bytes: [u8; 32] = signing_key.to_bytes().into();
            let signer = CommitSigner::from_bytes(&bytes).unwrap();

            let sig_bytes = signer.sign(format!("commit bytes {i}").as_bytes());
            let sig = Signature::from_slice(&sig_bytes).unwrap();

            // normalize_s() returns Some(_) only when the signature WAS high-S.
            assert!(
                sig.normalize_s().is_none(),
                "signature must already be canonical low-S (iteration {i})"
            );
        }
    }

    #[test]
    fn sign_different_messages_produce_different_signatures() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let bytes: [u8; 32] = signing_key.to_bytes().into();
        let signer = CommitSigner::from_bytes(&bytes).unwrap();

        let sig1 = signer.sign(b"message one");
        let sig2 = signer.sign(b"message two");

        assert_ne!(
            sig1, sig2,
            "different messages must produce different signatures"
        );
    }
}
