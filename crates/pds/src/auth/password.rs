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

/// What a newly created account's `accounts.password_hash` column becomes — resolved from the
/// request shape and the operator's policy before any state is written.
pub(crate) enum PasswordDisposition {
    /// Store this argon2id PHC string. The account can `createSession` with a password.
    Hashed(String),
    /// Store NULL. The account authenticates through the device-key paths (wallet-confirmed
    /// OAuth consent, sovereign sessions) and through app passwords for standard clients — the
    /// same column state migration-mode `createAccount` has always written for OAuth-only accounts.
    None,
}

impl PasswordDisposition {
    /// The value to bind to `accounts.password_hash`.
    pub(crate) fn as_column(&self) -> Option<&str> {
        match self {
            Self::Hashed(hash) => Some(hash.as_str()),
            Self::None => None,
        }
    }
}

/// Decide what an account is created with, given the password the client supplied (`None` when
/// the field was omitted entirely) and whether the operator allows passwordless accounts
/// (`accounts.password_optional`, advertised as the `optionalPassword` capability).
///
/// Returning `Err` refuses the request outright — nothing is written.
///
/// The empty string is deliberately not a way to ask for a passwordless account: `""` is what an
/// uninitialized form field serializes to, so honoring it would let a client bug silently produce
/// an account with no password. Omission is the unambiguous signal, and it is the only one
/// accepted — under either policy.
///
/// Shared by the two account-creation routes (`create_did`, `create_account_xrpc`), which cannot
/// import each other, so the policy cannot drift between the native ceremony and the standard
/// XRPC path.
pub(crate) fn resolve_password(
    supplied: Option<&str>,
    password_optional: bool,
) -> Result<PasswordDisposition, ApiError> {
    match supplied {
        // argon2 happily hashes "", so without this the PDS would store a zero-length password.
        // Refused under both policies: it is indistinguishable from an uninitialized field, and
        // guessing which of the two a client meant is a guess worth not making.
        Some("") => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "password must not be empty; omit the field entirely to create a passwordless account",
        )),
        Some(password) => Ok(PasswordDisposition::Hashed(hash_password(password)?)),
        None if password_optional => Ok(PasswordDisposition::None),
        // Named separately from the empty-string case: the client sent no password at all, and
        // telling it "must not be empty" would send it looking for a bug it does not have.
        None => Err(ApiError::new(
            ErrorCode::InvalidClaim,
            "password is required; this server does not offer passwordless accounts",
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The `message` an `ApiError` would put on the wire. The field is private, so read it back
    /// through the serialized envelope — which is what a client actually sees anyway.
    fn message_of(err: &ApiError) -> String {
        serde_json::to_value(err)
            .expect("ApiError serializes")
            .get("message")
            .and_then(|m| m.as_str())
            .expect("the error envelope carries a message")
            .to_string()
    }

    /// A supplied password is hashed and stored under either policy — enabling passwordless
    /// accounts must not stop anyone from choosing to have a password.
    #[test]
    fn supplied_password_is_hashed_under_either_policy() {
        for password_optional in [false, true] {
            let disposition = resolve_password(Some("hunter2hunter2"), password_optional)
                .expect("a supplied password is always accepted");
            let hash = disposition
                .as_column()
                .expect("a supplied password yields a stored hash");
            assert!(
                hash.starts_with("$argon2id$"),
                "expected an argon2id PHC string, got: {hash}"
            );
            assert!(
                matches!(verify_password(hash, "hunter2hunter2"), VerifyResult::Ok),
                "the stored hash should verify against the supplied password"
            );
        }
    }

    /// The empty string is never consent to a passwordless account, in either direction. This is
    /// the whole reason the field is `Option<String>` rather than `String`: `""` is what an
    /// uninitialized form field serializes to, and honoring it would let a client bug create an
    /// account with no credential.
    #[test]
    fn empty_password_is_rejected_under_either_policy() {
        for password_optional in [false, true] {
            let err = resolve_password(Some(""), password_optional)
                .err()
                .expect("an empty password is always refused");
            let message = message_of(&err);
            assert!(
                message.contains("must not be empty"),
                "the empty-string rejection should say so, got: {message}"
            );
        }
    }

    /// An omitted password creates a passwordless account only where the operator allows it.
    #[test]
    fn omitted_password_follows_the_operator_policy() {
        let allowed =
            resolve_password(None, true).expect("omission is accepted when passwords are optional");
        assert!(
            allowed.as_column().is_none(),
            "a passwordless account stores NULL, not a hash of nothing"
        );

        let refused = resolve_password(None, false)
            .err()
            .expect("omission is refused when the server requires a password");
        let message = message_of(&refused);
        assert!(
            message.contains("does not offer passwordless"),
            "the refusal should name the real reason rather than blaming an empty field, \
             got: {message}"
        );
    }
}
