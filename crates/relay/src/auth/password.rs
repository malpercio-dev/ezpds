// pattern: Functional Core
//
// Password hashing (argon2id) and verification. No I/O, no database, no state.

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};

use common::{ApiError, ErrorCode};

/// Hash `password` with argon2id and return the PHC string.
///
/// Uses `Argon2::default()` (argon2id, m=19456 KiB ≈19 MiB, t=2, p=1) with a freshly
/// generated random salt. The PHC string embeds the algorithm, parameters, salt, and
/// hash — everything `verify_password` needs for later verification.
pub(crate) fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| {
            tracing::error!(error = %e, "argon2id hashing failed");
            ApiError::new(ErrorCode::InternalError, "failed to process password")
        })
}

/// Verify `password` against a stored argon2id PHC-format hash string.
pub(crate) fn verify_password(stored_hash: &str, password: &str) -> bool {
    let Ok(hash) = PasswordHash::new(stored_hash) else {
        tracing::error!("stored password_hash is not a valid PHC string; possible DB corruption");
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}
