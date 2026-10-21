// pattern: Functional Core

/// Normalize an email address for storage, lookup, and uniqueness comparison.
///
/// Trims surrounding whitespace and lowercases, matching the reference PDS's case-insensitive
/// email handling. Applied on every write (account creation, `updateEmail`) and read
/// (`resolve_by_email`, uniqueness checks, `confirmEmail`'s account-email match) so a
/// differently-cased or accidentally-padded address never causes a silent lookup miss (e.g. a
/// `requestPasswordReset` that silently no-ops because the stored and submitted addresses differ
/// only by case).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A minimal email plausibility check: exactly one `@` with a non-empty local part and a
/// dotted domain. Not full RFC 5322 validation — just enough to reject obvious garbage before
/// a DB write. Homed here beside `normalize_email` so the account-creation, `updateEmail`, and
/// admin-repair routes share one validator without importing across route modules.
pub fn is_plausible_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
        assert_eq!(normalize_email("bob@example.com"), "bob@example.com");
    }

    #[test]
    fn normalize_email_is_idempotent() {
        let once = normalize_email("Alice@Example.COM");
        assert_eq!(normalize_email(&once), once);
    }

    #[test]
    fn is_plausible_email_accepts_and_rejects() {
        assert!(is_plausible_email("alice@example.com"));
        assert!(is_plausible_email("a.b+c@sub.example.co.uk"));
        assert!(!is_plausible_email("no-at-sign"));
        assert!(!is_plausible_email("@example.com"));
        assert!(!is_plausible_email("alice@nodot"));
        assert!(!is_plausible_email("alice@.com"));
        assert!(!is_plausible_email("alice@example."));
        assert!(!is_plausible_email("two@at@example.com"));
    }
}
