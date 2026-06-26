// pattern: Functional Core
//
// Password hashing (argon2id) and verification. No I/O, no database, no state.

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};

use common::{ApiError, ErrorCode};

/// Outcome of verifying a password against a stored hash.
///
/// Callers must handle `CorruptHash` separately from `WrongPassword`:
/// - `WrongPassword` → increment rate-limit counter, return 401
/// - `CorruptHash`   → log with identifier, return 500, do NOT increment counter
pub(crate) enum VerifyResult {
    /// Password is correct.
    Ok,
    /// Password is wrong (argon2 computed but didn't match).
    WrongPassword,
    /// The stored hash is not a valid PHC string — possible DB corruption.
    CorruptHash,
}

/// A valid argon2id PHC string used as dummy input for timing equalization when a
/// login identifier is not found. This never matches any real user's password — its
/// only purpose is to ensure that the "identifier not found" path spends the same
/// wall-clock time as the "wrong password" path, preventing account-enumeration via
/// timing side-channels.
///
/// Parameters match `Argon2::default()` (argon2id v19, m=19456, t=2, p=1). The salt
/// and hash are 16 and 32 bytes of zeros respectively, expressed as base64 without
/// padding (standard alphabet). Using a compile-time constant avoids the panic risk
/// of the `OnceLock` + `unwrap` pattern.
pub(crate) const TIMING_DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
///
/// Returns `CorruptHash` if `stored_hash` cannot be parsed as a PHC string.
/// The caller is responsible for logging with the account identifier and returning a
/// 500 without incrementing the rate-limit counter — corrupt hash is a server-side
/// defect, not a user authentication failure.
pub(crate) fn verify_password(stored_hash: &str, password: &str) -> VerifyResult {
    let Ok(hash) = PasswordHash::new(stored_hash) else {
        return VerifyResult::CorruptHash;
    };
    match Argon2::default().verify_password(password.as_bytes(), &hash) {
        Ok(()) => VerifyResult::Ok,
        Err(_) => VerifyResult::WrongPassword,
    }
}
