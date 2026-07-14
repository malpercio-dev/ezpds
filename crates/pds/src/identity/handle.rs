// pattern: Functional Core
//
// Handle validation shared by the account-provisioning and handle-registration routes.
//
// An AT Protocol handle is a domain name (`<name>.<domain...>`, at least two DNS labels).
// A bare single-segment label like `alice` is NOT a valid handle: relays and AppViews read
// the handle from the published DID document's `alsoKnownAs` (`at://<handle>`) without
// re-validating it, and a syntactically invalid handle fails bidirectional verification and
// renders as `handle.invalid`. So provisioning must reject bare labels *before* a did:plc
// genesis op (whose hash is the DID) bakes the handle in permanently.
//
// Two entry points:
//   - `validate_handle_structure` — spec structural validity only. Used at account
//     provisioning, before the server knows which domain the client will register under.
//   - `validate_handle` — structural validity PLUS the domain-policy check that the handle's
//     domain is one this server actually serves. Used by the handle-registration route, the
//     authoritative gate for `available_user_domains`.
//
// Both return the first DNS label (the "name") on success, which the handle route uses as the
// DNS record name.

/// Maximum total handle length (DNS name limit), per the AT Protocol handle spec.
const MAX_HANDLE_LEN: usize = 253;
/// Maximum length of a single DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;

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

/// Validate that `handle` is structurally a valid AT Protocol handle: a domain name of at
/// least two DNS labels, each 1..=63 chars of ASCII alphanumerics and internal hyphens, with
/// total length at most 253. Returns the first label (the "name") on success.
///
/// This rejects bare single-segment labels (`alice`), which are the root cause of the
/// `handle.invalid` federation bug.
///
/// # Errors
/// Returns a static message suitable for a 400 response body.
pub(crate) fn validate_handle_structure(handle: &str) -> Result<&str, &'static str> {
    if handle.is_empty() {
        return Err("handle must not be empty");
    }
    if handle.len() > MAX_HANDLE_LEN {
        return Err("handle must be at most 253 characters");
    }

    let labels: Vec<&str> = handle.split('.').collect();
    if labels.len() < 2 {
        return Err(
            "handle must be a domain name with at least two parts (e.g. alice.example.com)",
        );
    }
    for label in &labels {
        validate_label(label)?;
    }
    // AT Protocol handle syntax additionally forbids the final label (the effective TLD) from
    // starting with a digit — unlike earlier labels, which may — so a handle can never be
    // confused with an IPv4-literal-shaped name.
    if labels[labels.len() - 1]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit())
    {
        return Err("handle's final label must not start with a digit");
    }

    Ok(labels[0])
}

/// Validate a single DNS label: non-empty, at most 63 chars, ASCII alphanumerics and hyphens
/// only, no leading or trailing hyphen.
fn validate_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("handle labels must not be empty");
    }
    if label.len() > MAX_LABEL_LEN {
        return Err("handle label exceeds maximum DNS label length of 63 characters");
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("handle labels cannot start or end with a hyphen");
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("handle labels may only contain letters, digits, and hyphens");
    }
    Ok(())
}

/// Validate `handle` structurally (see [`validate_handle_structure`]) and additionally require
/// that its domain (everything after the first label) is one of the server's
/// `available_domains` and that the name is not one of the operator's `reserved_handles`.
/// Returns the first label (the "name") on success.
///
/// # Errors
/// Returns a static message suitable for a 400 response body.
pub(crate) fn validate_handle<'a>(
    handle: &'a str,
    available_domains: &[String],
    reserved_handles: &[String],
) -> Result<&'a str, &'static str> {
    let name = validate_handle_structure(handle)?;
    // Structural validation guarantees at least one dot.
    let dot = handle.find('.').expect("structure guarantees a dot");
    let domain = &handle[dot + 1..];
    if !available_domains.iter().any(|d| d == domain) {
        return Err("handle domain is not served by this server");
    }
    if is_reserved_name(name, reserved_handles) {
        return Err("this handle name is reserved");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_handle_structure: accepts valid handles ───────────────────────

    #[test]
    fn structure_accepts_two_label_handle() {
        assert_eq!(validate_handle_structure("alice.example.com"), Ok("alice"));
        assert_eq!(validate_handle_structure("malpercio.dev"), Ok("malpercio"));
        assert_eq!(validate_handle_structure("a.b"), Ok("a"));
    }

    #[test]
    fn structure_accepts_internal_hyphen_in_name() {
        assert_eq!(
            validate_handle_structure("al-ice.example.com"),
            Ok("al-ice")
        );
    }

    #[test]
    fn structure_accepts_label_of_exactly_63_chars() {
        let name = "a".repeat(MAX_LABEL_LEN);
        let handle = format!("{name}.example.com");
        assert_eq!(validate_handle_structure(&handle), Ok(name.as_str()));
    }

    // ── validate_handle_structure: rejects bare labels (the bug) ────────────────

    #[test]
    fn structure_rejects_bare_label() {
        assert!(validate_handle_structure("alice").is_err());
    }

    #[test]
    fn structure_rejects_bare_253_char_label() {
        // The previous permissive validator ACCEPTED this (a 253-char single label with no
        // dot). That acceptance was the bug: it let `at://<label>` reach the genesis op.
        assert!(validate_handle_structure(&"a".repeat(253)).is_err());
    }

    // ── validate_handle_structure: rejects other malformed handles ──────────────

    #[test]
    fn structure_rejects_empty() {
        assert!(validate_handle_structure("").is_err());
    }

    #[test]
    fn structure_rejects_empty_labels() {
        assert!(validate_handle_structure(".example.com").is_err());
        assert!(validate_handle_structure("alice..com").is_err());
        assert!(validate_handle_structure("alice.").is_err());
    }

    #[test]
    fn structure_rejects_leading_or_trailing_hyphen() {
        assert!(validate_handle_structure("-alice.example.com").is_err());
        assert!(validate_handle_structure("alice-.example.com").is_err());
    }

    #[test]
    fn structure_rejects_invalid_characters() {
        assert!(validate_handle_structure("ali_ce.example.com").is_err());
        assert!(validate_handle_structure("alice example.com").is_err());
        assert!(validate_handle_structure("alice\t.example.com").is_err());
    }

    #[test]
    fn structure_rejects_non_ascii() {
        assert!(validate_handle_structure("älice.example.com").is_err());
    }

    #[test]
    fn structure_rejects_numeric_leading_final_label() {
        assert!(validate_handle_structure("alice.123").is_err());
        assert!(validate_handle_structure("alice.example.1com").is_err());
    }

    #[test]
    fn structure_accepts_numeric_leading_non_final_label() {
        // Digits are only forbidden in the final label; an earlier label may start with one.
        assert_eq!(validate_handle_structure("123.example.com"), Ok("123"));
    }

    #[test]
    fn structure_rejects_label_exceeding_63_chars() {
        let name = "a".repeat(MAX_LABEL_LEN + 1);
        assert!(validate_handle_structure(&format!("{name}.example.com")).is_err());
    }

    #[test]
    fn structure_rejects_total_length_over_253() {
        // Four 63-char labels joined by dots = 63*4 + 3 = 255 chars; every label is itself
        // valid, so this isolates the total-length rule.
        let label = "a".repeat(MAX_LABEL_LEN);
        let handle = [label.as_str(); 4].join(".");
        assert!(handle.len() > MAX_HANDLE_LEN);
        assert!(validate_handle_structure(&handle).is_err());
    }

    // ── validate_handle: structure + domain policy ─────────────────────────────

    fn reserved() -> Vec<String> {
        vec!["identitywallet".to_string(), "about".to_string()]
    }

    #[test]
    fn domain_policy_accepts_served_domain() {
        let domains = vec!["example.com".to_string()];
        assert_eq!(
            validate_handle("alice.example.com", &domains, &reserved()),
            Ok("alice")
        );
    }

    #[test]
    fn domain_policy_accepts_multi_label_served_domain() {
        let domains = vec!["test.example.com".to_string()];
        assert_eq!(
            validate_handle("alice.test.example.com", &domains, &reserved()),
            Ok("alice")
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
            validate_handle("alice.identitywallet.example.com", &domains, &reserved()),
            Ok("alice")
        );
    }

    #[test]
    fn non_reserved_names_still_accepted() {
        let domains = vec!["obsign.org".to_string()];
        assert_eq!(
            validate_handle("alice.obsign.org", &domains, &reserved()),
            Ok("alice")
        );
    }

    #[test]
    fn empty_reserved_list_reserves_nothing() {
        let domains = vec!["obsign.org".to_string()];
        assert_eq!(
            validate_handle("identitywallet.obsign.org", &domains, &[]),
            Ok("identitywallet")
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
