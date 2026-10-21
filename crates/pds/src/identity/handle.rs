// pattern: Functional Core

//! Handle validation shared by the account-provisioning and handle-registration routes.
//!
//! An AT Protocol handle is a domain name (`<name>.<domain...>`, at least two DNS labels).
//! A bare single-segment label like `alice` is NOT a valid handle: relays and AppViews read
//! the handle from the published DID document's `alsoKnownAs` (`at://<handle>`) without
//! re-validating it, and a syntactically invalid handle fails bidirectional verification and
//! renders as `handle.invalid`. So provisioning must reject bare labels *before* a did:plc
//! genesis op (whose hash is the DID) bakes the handle in permanently.
//!
//! Two entry points:
//! - `validate_handle_structure` — spec structural validity only (re-exported from `common`,
//!   where it backs [`Handle`]). Used at account provisioning, before the server knows which
//!   domain the client will register under.
//! - `validate_handle` — structural validity PLUS domain policy: the handle's domain is one
//!   this server actually serves (the authoritative gate for `available_user_domains`), and its
//!   first label is not an operator-reserved infrastructure name (`Config::reserved_handles`,
//!   default `identitywallet`/`about`). Returns the parsed [`Handle`]. Callers that skip this
//!   check for served domains — updateHandle's served-domain branch — apply `is_reserved_name`
//!   themselves.

pub(crate) use common::validate_handle_structure;
use common::Handle;

/// Whether `name` (a handle's first DNS label) is one of the operator's reserved
/// infrastructure names. `reserved` is `Config::reserved_handles` (normalized to
/// lowercase at config load; the reference default reserves `identitywallet` — the
/// wallet's OAuth client_id host — and `about`). Compared case-insensitively.
///
/// Callers that bypass [`validate_handle`] for served domains (updateHandle's
/// served-domain branch skips external resolution) must apply this check themselves.
pub(crate) fn is_reserved_name(name: &str, reserved: &[String]) -> bool {
    reserved.iter().any(|r| name.eq_ignore_ascii_case(r))
}

/// Whether `handle` (assumed structurally valid) uses a reserved first label on one of
/// this server's served domains — the reserved-name half of [`validate_handle`], factored
/// out for callers that validate the served-domain policy separately or skip it: the
/// migration create path (foreign handles, no served-domain gate) and updateHandle.
///
/// A reserved name on a *foreign* domain (e.g. `about.someco.com`) is deliberately allowed —
/// the reservation defends only this server's own wildcard space, so migration can't be used
/// to claim `identitywallet.obsign.org` while a genuinely foreign handle is unaffected.
pub(crate) fn reserved_on_served_domain(
    handle: &str,
    available_domains: &[String],
    reserved: &[String],
) -> bool {
    let Some(dot) = handle.find('.') else {
        return false;
    };
    available_domains.iter().any(|d| d == &handle[dot + 1..])
        && is_reserved_name(&handle[..dot], reserved)
}

/// Validate `handle` structurally (see [`validate_handle_structure`]) and additionally require
/// that its domain (everything after the first label) is one of the server's
/// `available_domains` and that the name is not one of the operator's `reserved_handles`.
/// Returns the parsed [`Handle`] on success.
///
/// # Errors
/// Returns a static message suitable for a 400 response body.
pub(crate) fn validate_handle(
    handle: &str,
    available_domains: &[String],
    reserved_handles: &[String],
) -> Result<Handle, &'static str> {
    let handle = Handle::parse(handle).map_err(|e| e.0)?;
    if !available_domains.iter().any(|d| d == handle.domain()) {
        return Err("handle domain is not served by this server");
    }
    if is_reserved_name(handle.name(), reserved_handles) {
        return Err("this handle name is reserved");
    }
    Ok(handle)
}

/// What a client- or user-supplied `login_hint` normalizes to: either a `did:` value taken
/// as-is, or a handle that has been unwrapped of its `at://`/`@` decoration, lowercased, and
/// confirmed structurally valid. Neither variant is resolved to a DID — callers on an
/// unauthenticated surface may need local-only resolution, so that step stays theirs.
pub(crate) enum LoginHint {
    Did(String),
    Handle(String),
}

/// Normalize a `login_hint` (a `did:` string, `at://` URI, `@handle`, or bare handle) into a
/// [`LoginHint`]. Returns `None` for a handle-shaped hint that fails [`validate_handle_structure`]
/// — an attacker-suppliable hint on an unauthenticated surface, so an invalid one means "no
/// usable hint" rather than an error.
pub(crate) fn normalize_login_hint(hint: &str) -> Option<LoginHint> {
    if hint.starts_with("did:") {
        return Some(LoginHint::Did(hint.to_string()));
    }
    let handle = hint.strip_prefix("at://").unwrap_or(hint);
    let handle = handle
        .strip_prefix('@')
        .unwrap_or(handle)
        .to_ascii_lowercase();
    validate_handle_structure(&handle).ok()?;
    Some(LoginHint::Handle(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse an upstream syntax fixture without normalizing the case itself. In particular,
    /// leading/trailing whitespace is significant invalid input. Upstream comments use `# `;
    /// a bare `#` prefix can itself be a syntax vector in other fixture sets.
    fn load_syntax_cases(raw: &str) -> Vec<&str> {
        raw.lines()
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .filter(|line| !line.trim().is_empty() && !line.starts_with("# "))
            .collect()
    }

    fn assert_handle_syntax_cases(valid_raw: &str, invalid_raw: &str) {
        let valid = load_syntax_cases(valid_raw);
        let invalid = load_syntax_cases(invalid_raw);
        assert!(!valid.is_empty() && !invalid.is_empty());

        for handle in valid {
            assert!(
                validate_handle_structure(handle).is_ok(),
                "expected valid handle from interop fixture: {handle:?}",
            );
        }
        for handle in invalid {
            assert!(
                validate_handle_structure(handle).is_err(),
                "expected invalid handle from interop fixture: {handle:?}",
            );
        }
    }

    #[test]
    fn structure_matches_interop_fixtures() {
        assert_handle_syntax_cases(
            include_str!("../../tests/fixtures/interop/handle_syntax_valid.txt"),
            include_str!("../../tests/fixtures/interop/handle_syntax_invalid.txt"),
        );
    }

    #[test]
    #[should_panic(expected = "expected valid handle from interop fixture")]
    fn corrupted_handle_fixture_is_detected() {
        assert_handle_syntax_cases(
            include_str!("../../tests/fixtures/interop/handle_syntax_invalid.txt"),
            include_str!("../../tests/fixtures/interop/handle_syntax_valid.txt"),
        );
    }

    // ── validate_handle: structure + domain policy ─────────────────────────────

    fn reserved() -> Vec<String> {
        vec!["identitywallet".to_string(), "about".to_string()]
    }

    #[test]
    fn domain_policy_accepts_served_domain() {
        let domains = vec!["example.com".to_string()];
        assert_eq!(
            validate_handle("alice.example.com", &domains, &reserved())
                .map(|h| h.name().to_owned()),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn domain_policy_accepts_multi_label_served_domain() {
        let domains = vec!["test.example.com".to_string()];
        assert_eq!(
            validate_handle("alice.test.example.com", &domains, &reserved())
                .map(|h| h.name().to_owned()),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn domain_policy_rejects_unserved_domain() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("alice.other.com", &domains, &reserved()).is_err());
    }

    #[test]
    fn domain_policy_rejects_bare_label_before_checking_domain() {
        let domains = vec!["example.com".to_string()];
        assert!(validate_handle("alice", &domains, &reserved()).is_err());
    }

    // ── Reserved names ──────────────────────────────────────────────────────────

    #[test]
    fn reserved_name_rejected_on_served_domain() {
        let domains = vec!["obsign.org".to_string()];
        assert!(validate_handle("identitywallet.obsign.org", &domains, &reserved()).is_err());
        // The operator-configured `about` is reserved too.
        assert!(validate_handle("about.obsign.org", &domains, &reserved()).is_err());
    }

    #[test]
    fn reserved_name_check_is_case_insensitive() {
        let domains = vec!["obsign.org".to_string()];
        assert!(validate_handle("IdentityWallet.obsign.org", &domains, &reserved()).is_err());
        assert!(is_reserved_name("IDENTITYWALLET", &reserved()));
    }

    #[test]
    fn reserved_name_only_applies_to_first_label() {
        // "identitywallet" appearing as a *domain* label is not a reservation hit.
        let domains = vec!["identitywallet.example.com".to_string()];
        assert_eq!(
            validate_handle("alice.identitywallet.example.com", &domains, &reserved())
                .map(|h| h.name().to_owned()),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn non_reserved_names_still_accepted() {
        let domains = vec!["obsign.org".to_string()];
        assert_eq!(
            validate_handle("alice.obsign.org", &domains, &reserved()).map(|h| h.name().to_owned()),
            Ok("alice".to_owned())
        );
    }

    #[test]
    fn empty_reserved_list_reserves_nothing() {
        let domains = vec!["obsign.org".to_string()];
        assert_eq!(
            validate_handle("identitywallet.obsign.org", &domains, &[])
                .map(|h| h.name().to_owned()),
            Ok("identitywallet".to_owned())
        );
        assert!(!is_reserved_name("identitywallet", &[]));
    }

    // ── reserved_on_served_domain (migration path) ─────────────────────────────

    #[test]
    fn reserved_on_served_domain_matches_only_served_domain() {
        let domains = vec!["obsign.org".to_string()];
        let res = reserved();
        // Reserved name on a served domain → true.
        assert!(reserved_on_served_domain(
            "identitywallet.obsign.org",
            &domains,
            &res
        ));
        // Reserved name on a FOREIGN domain → false (only our wildcard space is defended).
        assert!(!reserved_on_served_domain(
            "identitywallet.migrated.example",
            &domains,
            &res
        ));
        // Non-reserved name on a served domain → false.
        assert!(!reserved_on_served_domain(
            "alice.obsign.org",
            &domains,
            &res
        ));
    }
}
