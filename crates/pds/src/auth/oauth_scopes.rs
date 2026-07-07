// pattern: Functional Core
//
//! ATProto granular OAuth auth-scope grammar (proposal 0011 / the atproto
//! permission spec).
//!
//! This is the *functional core* of the granular-scope work: it parses,
//! validates, and canonically normalizes the scope grammar
//! `resource[:positional][?param=value...]` across the five resource types
//! (`repo`, `rpc`, `blob`, `account`, `identity`), the permission-set reference
//! (`include:`), and the fixed scopes (`atproto`, `transition:generic`,
//! `transition:email`, `transition:chat.bsky`).
//!
//! The grammar and canonical forms are ported from the reference implementation
//! (`@atproto/oauth-scopes`), so a scope string minted by a real atproto client
//! parses here, and a string this module emits round-trips through the
//! reference.

use std::collections::BTreeSet;

use common::{ApiError, ErrorCode};

use super::jwt::SCOPE_ACCESS;

/// The fixed, non-parameterized scopes.
const STATIC_SCOPES: [&str; 4] = [
    "atproto",
    "transition:email",
    "transition:generic",
    "transition:chat.bsky",
];

/// The base scope that every atproto OAuth request must include.
const ATPROTO_BASE_SCOPE: &str = "atproto";

const REPO_ACTIONS: [&str; 3] = ["create", "update", "delete"];
const ACCOUNT_ATTRS: [&str; 3] = ["email", "repo", "status"];
const ACCOUNT_ACTIONS: [&str; 2] = ["read", "manage"];
const IDENTITY_ATTRS: [&str; 2] = ["handle", "*"];

/// A declarative summary of each granular resource-type prefix, for `scopes_supported` in
/// OAuth discovery metadata. Each prefix accepts further positional/query parameters per the
/// grammar above — the full grantable scope space is unbounded, so this summarizes it by
/// prefix rather than enumerating every concrete value.
const SCOPE_PREFIX_SUMMARY: [&str; 6] = [
    "repo:*",
    "rpc:*",
    "blob:*/*",
    "account:*",
    "identity:*",
    "include:*",
];

/// The full scope surface this server supports, for `scopes_supported` in OAuth discovery
/// metadata (RFC 8414 / RFC 9728): the fixed/transition scopes plus the resource-prefix summary.
pub fn supported_scopes() -> Vec<&'static str> {
    STATIC_SCOPES
        .iter()
        .copied()
        .chain(SCOPE_PREFIX_SUMMARY.iter().copied())
        .collect()
}

/// Human-readable group heading for a scope token's resource-type prefix, for the OAuth
/// consent screen (`routes::oauth_templates::render_permission_groups`). Kept alongside
/// `SCOPE_PREFIX_SUMMARY` — the two lists name the same resource types — so a future resource
/// type is at least a one-file change instead of two independently-maintained matches.
pub(crate) fn resource_group_label(token: &str) -> &'static str {
    match token.split(':').next().unwrap_or(token) {
        "repo" => "Repository writes",
        "rpc" => "Cross-service requests",
        "blob" => "File uploads",
        "account" => "Account settings",
        "identity" => "Identity",
        "transition" => "Legacy full access",
        "include" => "Permission set",
        _ => "Other",
    }
}

/// Validate and canonically normalize a requested OAuth `scope` string.
///
/// On success returns the canonical scope string: each token parsed and
/// re-emitted in canonical form, duplicates removed, and the whole set sorted
/// and space-joined. On failure returns a human-readable reason suitable for an
/// OAuth `invalid_scope` `error_description`.
///
/// The `atproto` base scope is required — an atproto OAuth session is
/// meaningless without it, and the reference authorization server rejects a
/// request that omits it.
pub fn normalize_scope_request(requested: &str) -> Result<String, String> {
    let mut canonical: BTreeSet<String> = BTreeSet::new();
    let mut saw_atproto = false;

    for token in requested.split(' ').filter(|t| !t.is_empty()) {
        let normalized = normalize_token(token)
            .ok_or_else(|| format!("unsupported or malformed scope: \"{token}\""))?;
        if normalized == ATPROTO_BASE_SCOPE {
            saw_atproto = true;
        }
        canonical.insert(normalized);
    }

    if canonical.is_empty() {
        return Err("scope must not be empty".to_string());
    }
    if !saw_atproto {
        return Err("the \"atproto\" scope is required".to_string());
    }

    Ok(canonical.into_iter().collect::<Vec<_>>().join(" "))
}

/// Intersect two scope-token sets by canonical token string, returning the tokens present in
/// **both**, sorted and de-duplicated.
///
/// Used to clamp an agent registration's stored `granted_scopes` to the operator's *current*
/// `[agent_auth] granted_scopes` config at assertion-mint time: the config acts as a live ceiling,
/// so narrowing it narrows subsequently minted assertions without re-registration
/// (agent-scope-enforcement AC2.2), while the result can never exceed what was stored at
/// registration (AC2.1). The comparison is token-exact — both inputs are the same canonical scope
/// tokens the config carries — so a merely reordered/rephrased config token is treated as a
/// different capability; operators should change `granted_scopes` by adding/removing whole tokens.
pub fn intersect_scope_tokens(a: &[String], b: &[String]) -> Vec<String> {
    let in_b: BTreeSet<&str> = b.iter().map(String::as_str).collect();
    let kept: BTreeSet<String> = a
        .iter()
        .filter(|t| in_b.contains(t.as_str()))
        .cloned()
        .collect();
    kept.into_iter().collect()
}

/// Whether `scope` is a valid atproto OAuth scope string — every token parses
/// and the set includes the `atproto` base scope.
///
/// The auth guard uses this to recognize a granular OAuth session and treat it
/// as access-level for coarse route admission; route handlers then inspect the
/// raw scope claim with the `allows_*` helpers below for resource-specific
/// enforcement.
pub fn is_atproto_oauth_scope(scope: &str) -> bool {
    normalize_scope_request(scope).is_ok()
}

/// Normalize a single scope token to its canonical string, or `None` if it is
/// not a recognized/valid scope.
///
/// `pub(super)`: also used by `auth::permission_sets` to validate/canonicalize each rendered
/// permission-set entry through the same grammar a client-supplied token would go through.
pub(super) fn normalize_token(token: &str) -> Option<String> {
    if STATIC_SCOPES.contains(&token) {
        return Some(token.to_string());
    }

    let syntax = ScopeSyntax::parse(token);
    match syntax.prefix.as_str() {
        "repo" => normalize_repo(&syntax),
        "rpc" => normalize_rpc(&syntax),
        "blob" => normalize_blob(&syntax),
        "account" => normalize_account(&syntax),
        "identity" => normalize_identity(&syntax),
        "include" => normalize_include(&syntax),
        _ => None,
    }
}

// ── Scope syntax parsing ──────────────────────────────────────────────────────

/// A scope token split into its `prefix`, optional `positional` argument, and
/// query `params` — the structural layer shared by every resource type, mirroring
/// the reference `ScopeStringSyntax`.
///
/// `pub(super)`: also used by `auth::permission_sets` to pull the `nsid`/`aud` back out of an
/// already-normalized `include:` token without re-deriving this parsing.
pub(super) struct ScopeSyntax {
    pub(super) prefix: String,
    pub(super) positional: Option<String>,
    /// Percent-decoded `(key, value)` pairs, in the order they appeared.
    params: Vec<(String, String)>,
}

impl ScopeSyntax {
    pub(super) fn parse(token: &str) -> ScopeSyntax {
        let colon = token.find(':');
        let question = token.find('?');

        let prefix_end = match (colon, question) {
            (Some(c), Some(q)) => Some(c.min(q)),
            (Some(c), None) => Some(c),
            (None, Some(q)) => Some(q),
            (None, None) => None,
        };

        let Some(prefix_end) = prefix_end else {
            return ScopeSyntax {
                prefix: token.to_string(),
                positional: None,
                params: Vec::new(),
            };
        };

        let prefix = token[..prefix_end].to_string();

        // Positional: text between ':' and '?' (or end), only when the colon
        // comes before any query string.
        let positional = match (colon, question) {
            (Some(c), Some(q)) if c < q => Some(percent_decode(&token[c + 1..q])),
            (Some(c), None) => Some(percent_decode(&token[c + 1..])),
            (Some(_), Some(_)) => None, // '?' precedes ':' — no positional
            _ => None,
        };

        // Params: everything after '?', if present and non-empty.
        let params = match question {
            Some(q) if q + 1 < token.len() => parse_query(&token[q + 1..]),
            _ => Vec::new(),
        };

        ScopeSyntax {
            prefix,
            positional,
            params,
        }
    }

    /// All distinct param keys present.
    fn keys(&self) -> BTreeSet<&str> {
        self.params.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Values for a repeatable key, in order.
    fn get_multi(&self, key: &str) -> Vec<&str> {
        self.params
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The single value for `key`. `None` if absent; `Some(None)` if present
    /// more than once (which is invalid for a single-valued param).
    pub(super) fn get_single(&self, key: &str) -> Option<Option<&str>> {
        let vals = self.get_multi(key);
        match vals.len() {
            0 => None,
            1 => Some(Some(vals[0])),
            _ => Some(None),
        }
    }
}

/// Parse an `application/x-www-form-urlencoded`-style query string into
/// percent-decoded `(key, value)` pairs. A segment without `=` yields an empty
/// value. Unlike a browser's `URLSearchParams`, `+` is left literal — MIME types
/// such as `application/ld+json` carry a meaningful `+`.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|seg| !seg.is_empty())
        .map(|seg| match seg.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(seg), String::new()),
        })
        .collect()
}

/// Decode `%XX` escapes. Invalid escapes are left verbatim.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a scope component, keeping the characters the scope grammar
/// allows unencoded (URI unreserved plus `: / + , @ *`). Notably `#` becomes
/// `%23`, matching the canonical form of an `aud` service reference.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'!'
                    | b'*'
                    | b'\''
                    | b'('
                    | b')'
                    | b':'
                    | b'/'
                    | b'+'
                    | b','
                    | b'@'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Assemble a canonical scope string from its parts.
///
/// `pub(super)`: also used by `auth::permission_sets` to render a resolved permission-set
/// entry into a raw candidate token before it's passed through `normalize_token`.
pub(super) fn format_scope(
    prefix: &str,
    positional: Option<&str>,
    params: &[(String, String)],
) -> String {
    let mut out = String::from(prefix);
    if let Some(pos) = positional {
        out.push(':');
        out.push_str(&encode_component(pos));
    }
    if !params.is_empty() {
        out.push('?');
        let joined = params
            .iter()
            .map(|(k, v)| format!("{k}={}", encode_component(v)))
            .collect::<Vec<_>>()
            .join("&");
        out.push_str(&joined);
    }
    out
}

/// Reject any param key not in `allowed`, and any positional colliding with the
/// same-named param (both express the positional argument).
fn keys_allowed(syntax: &ScopeSyntax, allowed: &[&str]) -> bool {
    syntax.keys().iter().all(|k| allowed.contains(k))
}

// ── Per-resource normalization ────────────────────────────────────────────────

fn is_collection_param(v: &str) -> bool {
    v == "*" || is_nsid(v)
}

fn normalize_repo(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["collection", "action"]) {
        return None;
    }

    // collection (positional name; required, multi)
    let mut collection = collect_positional_multi(syntax, "collection")?;
    if collection.is_empty() || !collection.iter().all(|v| is_collection_param(v)) {
        return None;
    }
    // normalize: `*` subsumes any explicit collections; else dedupe + sort.
    if collection.iter().any(|c| c == "*") {
        collection = vec!["*".to_string()];
    } else {
        collection = dedupe_sorted(collection);
    }

    // action (optional, multi, default = all three)
    let action = match syntax.get_multi("action") {
        v if v.is_empty() => REPO_ACTIONS.iter().map(|s| s.to_string()).collect(),
        v => {
            if !v.iter().all(|a| REPO_ACTIONS.contains(a)) {
                return None;
            }
            // canonical order: create, update, delete
            REPO_ACTIONS
                .iter()
                .filter(|a| v.contains(a))
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        }
    };

    let mut params: Vec<(String, String)> = Vec::new();
    let positional = if collection.len() == 1 {
        Some(collection[0].clone())
    } else {
        for c in &collection {
            params.push(("collection".to_string(), c.clone()));
        }
        None
    };
    if action.len() != REPO_ACTIONS.len() {
        for a in &action {
            params.push(("action".to_string(), a.clone()));
        }
    }

    Some(format_scope("repo", positional.as_deref(), &params))
}

fn is_lxm_param(v: &str) -> bool {
    v == "*" || is_nsid(v)
}

fn normalize_rpc(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["lxm", "aud"]) {
        return None;
    }

    // lxm (positional name; required, multi)
    let mut lxm = collect_positional_multi(syntax, "lxm")?;
    if lxm.is_empty() || !lxm.iter().all(|v| is_lxm_param(v)) {
        return None;
    }
    if lxm.iter().any(|c| c == "*") {
        lxm = vec!["*".to_string()];
    } else {
        lxm = dedupe_sorted(lxm);
    }

    // aud (required, single)
    let aud = match syntax.get_single("aud") {
        Some(Some(v)) if v == "*" || is_atproto_audience(v) => v.to_string(),
        _ => return None,
    };

    // rpc:*?aud=* is forbidden.
    if aud == "*" && lxm.iter().any(|c| c == "*") {
        return None;
    }

    let mut params: Vec<(String, String)> = Vec::new();
    let positional = if lxm.len() == 1 {
        Some(lxm[0].clone())
    } else {
        for l in &lxm {
            params.push(("lxm".to_string(), l.clone()));
        }
        None
    };
    params.push(("aud".to_string(), aud));

    Some(format_scope("rpc", positional.as_deref(), &params))
}

fn normalize_blob(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["accept"]) {
        return None;
    }

    let accept = collect_positional_multi(syntax, "accept")?;
    if accept.is_empty() || !accept.iter().all(|v| is_accept(v)) {
        return None;
    }

    // normalize: `*/*` subsumes everything; else lowercase, drop entries
    // covered by a `base/*` wildcard, dedupe + sort.
    let normalized: Vec<String> = if accept.iter().any(|a| a == "*/*") {
        vec!["*/*".to_string()]
    } else {
        let lowered: Vec<String> = accept.iter().map(|a| a.to_lowercase()).collect();
        let unique = dedupe_sorted(lowered);
        unique
            .iter()
            .filter(|a| !is_redundant_accept(a, &unique))
            .cloned()
            .collect()
    };

    let mut params: Vec<(String, String)> = Vec::new();
    let positional = if normalized.len() == 1 {
        Some(normalized[0].clone())
    } else {
        for a in &normalized {
            params.push(("accept".to_string(), a.clone()));
        }
        None
    };

    Some(format_scope("blob", positional.as_deref(), &params))
}

/// A concrete `type/subtype` is redundant when the set also contains the
/// `type/*` wildcard for the same base type. Wildcards themselves are never
/// redundant with one another.
fn is_redundant_accept(value: &str, set: &[String]) -> bool {
    if value.ends_with("/*") {
        return false;
    }
    let base = value.split('/').next().unwrap_or("");
    set.iter().any(|other| other == &format!("{base}/*"))
}

fn normalize_account(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["attr", "action"]) {
        return None;
    }

    // attr (positional name; required, single)
    let attr = collect_positional_single(syntax, "attr")?;
    if !ACCOUNT_ATTRS.contains(&attr.as_str()) {
        return None;
    }

    // action (optional, multi, default = ["read"])
    let action: Vec<String> = match syntax.get_multi("action") {
        v if v.is_empty() => vec!["read".to_string()],
        v => {
            if !v.iter().all(|a| ACCOUNT_ACTIONS.contains(a)) {
                return None;
            }
            dedupe_sorted(v.iter().map(|s| s.to_string()).collect())
        }
    };

    let mut params: Vec<(String, String)> = Vec::new();
    if !(action.len() == 1 && action[0] == "read") {
        for a in &action {
            params.push(("action".to_string(), a.clone()));
        }
    }

    Some(format_scope("account", Some(&attr), &params))
}

fn normalize_identity(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["attr"]) {
        return None;
    }
    let attr = collect_positional_single(syntax, "attr")?;
    if !IDENTITY_ATTRS.contains(&attr.as_str()) {
        return None;
    }
    Some(format_scope("identity", Some(&attr), &[]))
}

fn normalize_include(syntax: &ScopeSyntax) -> Option<String> {
    if !keys_allowed(syntax, &["nsid", "aud"]) {
        return None;
    }
    // nsid (positional name; required, single)
    let nsid = collect_positional_single(syntax, "nsid")?;
    if !is_nsid(&nsid) {
        return None;
    }
    // aud (optional, single)
    let aud = match syntax.get_single("aud") {
        None => None,
        Some(Some(v)) if is_atproto_audience(v) => Some(v.to_string()),
        Some(_) => return None,
    };

    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(aud) = aud {
        params.push(("aud".to_string(), aud));
    }
    Some(format_scope("include", Some(&nsid), &params))
}

/// Collect the values of a required, multi-valued positional param. Returns
/// `None` if both the positional and the same-named query param are present
/// (they are two spellings of the same argument), or if the value is absent.
fn collect_positional_multi(syntax: &ScopeSyntax, name: &str) -> Option<Vec<String>> {
    let named = syntax.get_multi(name);
    match &syntax.positional {
        Some(pos) => {
            if !named.is_empty() {
                return None; // positional + named collision
            }
            Some(vec![pos.clone()])
        }
        None => {
            if named.is_empty() {
                None
            } else {
                Some(named.iter().map(|s| s.to_string()).collect())
            }
        }
    }
}

/// Collect a required, single-valued positional param. `None` on
/// positional+named collision, a repeated named param, or absence.
fn collect_positional_single(syntax: &ScopeSyntax, name: &str) -> Option<String> {
    match &syntax.positional {
        Some(pos) => {
            if syntax.params.iter().any(|(k, _)| k == name) {
                return None; // positional + named collision
            }
            Some(pos.clone())
        }
        None => match syntax.get_single(name) {
            Some(Some(v)) => Some(v.to_string()),
            _ => None,
        },
    }
}

fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let set: BTreeSet<String> = values.into_iter().collect();
    set.into_iter().collect()
}

// ── NSID / DID / MIME validators (ported from @atproto/syntax + @atproto/did) ──

/// Validate an atproto NSID: a reversed domain authority plus a name segment
/// (letters, no leading digit). Mirrors `@atproto/syntax`'s `validateNsid`.
fn is_nsid(v: &str) -> bool {
    if v.len() > 253 + 1 + 63 {
        return false;
    }
    if !v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return false;
    }
    let segments: Vec<&str> = v.split('.').collect();
    if segments.len() < 3 {
        return false;
    }
    for l in &segments {
        if l.is_empty() || l.len() > 63 {
            return false;
        }
        if l.starts_with('-') || l.ends_with('-') {
            return false;
        }
    }
    // First authority segment must not start with a digit.
    if segments[0].starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    // Name segment: no leading digit and no hyphen (letters/digits only, letter first).
    let name = segments[segments.len() - 1];
    if name.starts_with(|c: char| c.is_ascii_digit()) || name.contains('-') {
        return false;
    }
    true
}

/// An atproto audience: an atproto DID, optionally with a `#serviceId` fragment.
fn is_atproto_audience(v: &str) -> bool {
    match v.split_once('#') {
        Some((did, fragment)) => {
            !fragment.is_empty() && !fragment.contains('#') && is_atproto_did(did)
        }
        None => is_atproto_did(v),
    }
}

fn is_atproto_did(v: &str) -> bool {
    is_did_plc(v) || is_atproto_did_web(v)
}

/// `did:plc:` + 24 base32 `[a-z2-7]` characters (32 chars total).
fn is_did_plc(v: &str) -> bool {
    const PREFIX: &str = "did:plc:";
    if v.len() != 32 || !v.starts_with(PREFIX) {
        return false;
    }
    v.as_bytes()[PREFIX.len()..]
        .iter()
        .all(|&c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
}

/// An atproto `did:web` — a plain host, no path and no port (except localhost).
fn is_atproto_did_web(v: &str) -> bool {
    const PREFIX: &str = "did:web:";
    let Some(rest) = v.strip_prefix(PREFIX) else {
        return false;
    };
    if rest.is_empty() || rest.starts_with(':') {
        return false;
    }
    // A literal ':' after the host encodes a path component — not allowed.
    if rest.contains(':') {
        return false;
    }
    // A `%3A` encodes a port — allowed only for localhost.
    let has_port = rest.contains("%3A") || rest.contains("%3a");
    if has_port && !(rest == "localhost" || rest.to_ascii_lowercase().starts_with("localhost%3a")) {
        return false;
    }
    // Host chars: DID method-specific-id set (alnum, '.', '-', '_', pct-encoded).
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'%'))
}

/// A MIME `accept` value: `*/*`, `type/*`, or a concrete `type/subtype`.
fn is_accept(v: &str) -> bool {
    if v == "*/*" {
        return true;
    }
    if !is_type_slash_subtype(v) {
        return false;
    }
    !v.contains('*') || v.ends_with("/*")
}

fn is_type_slash_subtype(v: &str) -> bool {
    match v.find('/') {
        None => false,
        Some(0) => false,
        Some(idx) => idx != v.len() - 1 && !v[idx + 1..].contains('/') && !v.contains(' '),
    }
}

/// Repo write action checked against `repo:` granular scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAction {
    Create,
    Update,
    Delete,
}

impl RepoAction {
    fn as_str(self) -> &'static str {
        match self {
            RepoAction::Create => "create",
            RepoAction::Update => "update",
            RepoAction::Delete => "delete",
        }
    }
}

/// Return an ATProto `InsufficientScope` denial.
pub fn insufficient_scope(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::InsufficientScope, message)
}

/// Require that a non-legacy granular OAuth grant permits reading email fields.
pub fn require_email(scope: &str) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_email(scope) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit reading email fields",
        ))
    }
}

/// Require that a non-legacy granular OAuth grant permits an identity operation.
pub fn require_identity(scope: &str, attr: &str) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_identity(scope, attr) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit identity operations",
        ))
    }
}

/// Require that a non-legacy granular OAuth grant permits an account operation.
pub fn require_account(scope: &str, attr: &str, action: &str) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_account(scope, attr, action) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit account status changes",
        ))
    }
}

/// Require that a non-legacy granular OAuth grant permits a repo write.
pub fn require_repo(scope: &str, collection: &str, action: RepoAction) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_repo(scope, collection, action) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit this repo write",
        ))
    }
}

/// Require that a non-legacy granular OAuth grant permits an RPC audience/method.
pub fn require_rpc(
    scope: &str,
    lxm: &str,
    aud: &str,
    message: &'static str,
) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_rpc(scope, lxm, aud) {
        Ok(())
    } else {
        Err(insufficient_scope(message))
    }
}

/// Require that a non-legacy granular OAuth grant permits uploading a blob MIME type.
pub fn require_blob(scope: &str, mime_type: &str) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_blob(scope, mime_type) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit this blob upload",
        ))
    }
}

/// Legacy transition scope that preserves pre-granular behavior for OAuth clients.
pub fn has_transition_generic(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|token| token == "transition:generic")
}

/// Whether a granular OAuth grant permits reading account email fields.
pub fn allows_email(scope: &str) -> bool {
    has_transition_generic(scope)
        || scope
            .split_whitespace()
            .any(|token| token == "transition:email" || account_token_allows(token, "email"))
}

/// Whether a granular OAuth grant permits an identity-management operation.
pub fn allows_identity(scope: &str, attr: &str) -> bool {
    has_transition_generic(scope)
        || scope
            .split_whitespace()
            .any(|token| match parse_token(token) {
                (prefix, Some(pos), _) if prefix == "identity" => pos == "*" || pos == attr,
                _ => false,
            })
}

/// Whether a granular OAuth grant permits an account operation.
pub fn allows_account(scope: &str, attr: &str, action: &str) -> bool {
    has_transition_generic(scope)
        || scope
            .split_whitespace()
            .any(|token| account_token_allows_action(token, attr, action))
}

/// Whether a granular OAuth grant permits a repo write for `collection` and `action`.
pub fn allows_repo(scope: &str, collection: &str, action: RepoAction) -> bool {
    has_transition_generic(scope)
        || scope
            .split_whitespace()
            .any(|token| match parse_token(token) {
                (prefix, Some(pos), params) if prefix == "repo" => {
                    collection_matches(&pos, collection) && repo_actions_match(&params, action)
                }
                (prefix, None, params) if prefix == "repo" => {
                    let collections: Vec<&str> = params
                        .iter()
                        .filter(|(key, _)| key == "collection")
                        .map(|(_, value)| value.as_str())
                        .collect();
                    !collections.is_empty()
                        && collections
                            .iter()
                            .any(|c| collection_matches(c, collection))
                        && repo_actions_match(&params, action)
                }
                _ => false,
            })
}

/// Whether a granular OAuth grant permits proxying/minting service auth for an RPC.
pub fn allows_rpc(scope: &str, lxm: &str, aud: &str) -> bool {
    has_transition_generic(scope)
        || scope.split_whitespace().any(|token| {
            // The chat transition scope grants the whole chat.bsky.* proxy/service-auth
            // surface regardless of audience — it is the granular-era equivalent of a
            // privileged app password's DM access, not a per-method rpc: grant.
            if token == "transition:chat.bsky" {
                return lxm.starts_with("chat.bsky.");
            }
            match parse_token(token) {
                (prefix, Some(pos), params) if prefix == "rpc" => {
                    lxm_matches(&pos, lxm) && aud_matches(&params, aud)
                }
                (prefix, None, params) if prefix == "rpc" => {
                    let lxms: Vec<&str> = params
                        .iter()
                        .filter(|(key, _)| key == "lxm")
                        .map(|(_, value)| value.as_str())
                        .collect();
                    !lxms.is_empty()
                        && lxms.iter().any(|candidate| lxm_matches(candidate, lxm))
                        && aud_matches(&params, aud)
                }
                _ => false,
            }
        })
}

/// Whether a granular OAuth grant permits uploading a blob of `mime_type`.
pub fn allows_blob(scope: &str, mime_type: &str) -> bool {
    has_transition_generic(scope)
        || scope
            .split_whitespace()
            .any(|token| match parse_token(token) {
                (prefix, Some(pos), _) if prefix == "blob" => accept_matches(&pos, mime_type),
                (prefix, None, params) if prefix == "blob" => params
                    .iter()
                    .filter(|(key, _)| key == "accept")
                    .any(|(_, accept)| accept_matches(accept, mime_type)),
                _ => false,
            })
}

fn parse_token(token: &str) -> (String, Option<String>, Vec<(String, String)>) {
    let syntax = ScopeSyntax::parse(token);
    (syntax.prefix, syntax.positional, syntax.params)
}

fn collection_matches(grant: &str, collection: &str) -> bool {
    grant == "*" || grant == collection
}

fn lxm_matches(grant: &str, lxm: &str) -> bool {
    grant == "*" || grant == lxm
}

fn repo_actions_match(params: &[(String, String)], action: RepoAction) -> bool {
    let requested = action.as_str();
    let actions: Vec<&str> = params
        .iter()
        .filter(|(key, _)| key == "action")
        .map(|(_, value)| value.as_str())
        .collect();
    actions.is_empty() || actions.contains(&requested)
}

fn aud_matches(params: &[(String, String)], aud: &str) -> bool {
    params
        .iter()
        .find(|(key, _)| key == "aud")
        .is_some_and(|(_, value)| value == "*" || value == aud)
}

fn accept_matches(grant: &str, mime_type: &str) -> bool {
    let grant = grant.to_ascii_lowercase();
    let mime_type = mime_type.to_ascii_lowercase();
    grant == "*/*"
        || grant == mime_type
        || grant
            .strip_suffix("/*")
            .is_some_and(|prefix| mime_type.starts_with(&format!("{prefix}/")))
}

fn account_token_allows(token: &str, attr: &str) -> bool {
    account_token_allows_action(token, attr, "read")
        || account_token_allows_action(token, attr, "manage")
}

fn account_token_allows_action(token: &str, attr: &str, action: &str) -> bool {
    match parse_token(token) {
        (prefix, Some(pos), params) if prefix == "account" && pos == attr => {
            let actions: Vec<&str> = params
                .iter()
                .filter(|(key, _)| key == "action")
                .map(|(_, value)| value.as_str())
                .collect();
            if actions.is_empty() {
                action == "read"
            } else {
                actions.contains(&action)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(token: &str) -> Option<String> {
        normalize_token(token)
    }

    // ── static scopes ─────────────────────────────────────────────────────────

    #[test]
    fn static_scopes_round_trip() {
        for s in STATIC_SCOPES {
            assert_eq!(norm(s).as_deref(), Some(s), "static scope {s} must be kept");
        }
    }

    #[test]
    fn unknown_prefix_is_rejected() {
        assert_eq!(norm("bogus"), None);
        assert_eq!(norm("bogus:foo"), None);
        assert_eq!(norm("transition:unknown"), None);
    }

    // ── repo ──────────────────────────────────────────────────────────────────

    #[test]
    fn repo_positional_and_wildcard() {
        assert_eq!(norm("repo:*").as_deref(), Some("repo:*"));
        assert_eq!(
            norm("repo:app.bsky.feed.post").as_deref(),
            Some("repo:app.bsky.feed.post")
        );
    }

    #[test]
    fn repo_default_action_is_omitted() {
        assert_eq!(
            norm("repo:com.example.foo?action=create&action=update&action=delete").as_deref(),
            Some("repo:com.example.foo")
        );
        assert_eq!(
            norm("repo:com.example.foo?action=create").as_deref(),
            Some("repo:com.example.foo?action=create")
        );
    }

    #[test]
    fn repo_wildcard_subsumes_collections() {
        // `*` present among several collections collapses to `repo:*`.
        assert_eq!(
            norm("repo?collection=*&collection=com.example.foo").as_deref(),
            Some("repo:*")
        );
    }

    #[test]
    fn repo_multiple_collections_sorted() {
        assert_eq!(
            norm("repo?collection=com.example.foo&collection=com.example.bar&action=create")
                .as_deref(),
            Some("repo?collection=com.example.bar&collection=com.example.foo&action=create")
        );
    }

    #[test]
    fn repo_invalid_is_rejected() {
        assert_eq!(norm("repo:invalid"), None); // not a 3-part NSID
        assert_eq!(norm("repo:.foo"), None);
        assert_eq!(norm("repo:bar."), None);
        assert_eq!(norm("repo:com.example.foo?action=invalid"), None);
        // positional + named collection collision
        assert_eq!(norm("repo:*?collection=com.example.foo"), None);
        // unknown param
        assert_eq!(norm("repo:*?bogus=1"), None);
    }

    // ── rpc ───────────────────────────────────────────────────────────────────

    #[test]
    fn rpc_positional_lxm_with_aud() {
        assert_eq!(
            norm("rpc:com.example.method1?aud=*").as_deref(),
            Some("rpc:com.example.method1?aud=*")
        );
        assert_eq!(
            norm("rpc:*?aud=did:web:example.com%23service_id").as_deref(),
            Some("rpc:*?aud=did:web:example.com%23service_id")
        );
    }

    #[test]
    fn rpc_requires_aud() {
        assert_eq!(norm("rpc:com.example.method1"), None);
        assert_eq!(norm("rpc:*"), None);
    }

    #[test]
    fn rpc_wildcard_lxm_and_aud_forbidden() {
        assert_eq!(norm("rpc:*?aud=*"), None);
    }

    #[test]
    fn rpc_positional_and_named_lxm_collision_rejected() {
        assert_eq!(
            norm("rpc:com.example.method1?aud=did:web:example.com&lxm=com.example.method2"),
            None
        );
    }

    #[test]
    fn rpc_did_plc_audience() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx"; // 32 chars total
        let scope = format!("rpc:foo.bar.baz?aud={did}");
        assert_eq!(norm(&scope).as_deref(), Some(scope.as_str()));
    }

    #[test]
    fn rpc_invalid_audience_rejected() {
        assert_eq!(norm("rpc:foo.bar.baz?aud=invalid"), None);
        assert_eq!(norm("rpc:foo.bar.baz?aud=did:web"), None);
        assert_eq!(norm("rpc:foo.bar.baz?aud=did:plc:111"), None); // wrong length
    }

    // ── blob ──────────────────────────────────────────────────────────────────

    #[test]
    fn blob_mime_forms() {
        assert_eq!(norm("blob:*/*").as_deref(), Some("blob:*/*"));
        assert_eq!(norm("blob:image/png").as_deref(), Some("blob:image/png"));
        assert_eq!(norm("blob:image/*").as_deref(), Some("blob:image/*"));
    }

    #[test]
    fn blob_wildcard_collapses() {
        assert_eq!(
            norm("blob?accept=image/png&accept=*/*").as_deref(),
            Some("blob:*/*")
        );
    }

    #[test]
    fn blob_drops_redundant_mime() {
        // image/png is covered by image/* → dropped, leaving the wildcard.
        assert_eq!(
            norm("blob?accept=image/*&accept=image/png").as_deref(),
            Some("blob:image/*")
        );
    }

    #[test]
    fn blob_invalid_rejected() {
        assert_eq!(norm("blob"), None);
        assert_eq!(norm("blob:invalid"), None);
        assert_eq!(norm("blob:*/png"), None);
    }

    // ── account ───────────────────────────────────────────────────────────────

    #[test]
    fn account_attrs_and_default_action() {
        assert_eq!(norm("account:email").as_deref(), Some("account:email"));
        // read is the default action → omitted
        assert_eq!(
            norm("account:email?action=read").as_deref(),
            Some("account:email")
        );
        assert_eq!(
            norm("account:status?action=manage").as_deref(),
            Some("account:status?action=manage")
        );
    }

    #[test]
    fn account_invalid_rejected() {
        assert_eq!(norm("account"), None);
        assert_eq!(norm("account:"), None);
        assert_eq!(norm("account:invalid"), None);
        assert_eq!(norm("account:email?action=invalid"), None);
    }

    // ── identity ──────────────────────────────────────────────────────────────

    #[test]
    fn identity_attrs() {
        assert_eq!(norm("identity:*").as_deref(), Some("identity:*"));
        assert_eq!(norm("identity:handle").as_deref(), Some("identity:handle"));
    }

    #[test]
    fn identity_invalid_rejected() {
        assert_eq!(norm("identity:invalid"), None);
        assert_eq!(norm("identity:*?action=manage"), None); // unknown param
    }

    // ── include ───────────────────────────────────────────────────────────────

    #[test]
    fn include_permission_set_reference() {
        assert_eq!(
            norm("include:app.bsky.authFull").as_deref(),
            Some("include:app.bsky.authFull")
        );
        assert_eq!(
            norm("include:com.example.foo?aud=did:web:example.com%23svc").as_deref(),
            Some("include:com.example.foo?aud=did:web:example.com%23svc")
        );
    }

    #[test]
    fn include_invalid_rejected() {
        assert_eq!(norm("include"), None);
        assert_eq!(norm("include:"), None);
        assert_eq!(norm("include:com"), None); // not a 3-part NSID
        assert_eq!(norm("include:com..example"), None);
    }

    // ── whole-string normalization ────────────────────────────────────────────

    #[test]
    fn normalize_request_sorts_and_dedupes_and_requires_atproto() {
        let out = normalize_scope_request("transition:generic atproto atproto").unwrap();
        assert_eq!(out, "atproto transition:generic");
    }

    #[test]
    fn normalize_request_requires_atproto_base() {
        let err = normalize_scope_request("transition:generic").unwrap_err();
        assert!(
            err.contains("atproto"),
            "error should mention atproto: {err}"
        );
    }

    #[test]
    fn normalize_request_rejects_malformed_token() {
        let err = normalize_scope_request("atproto repo:invalid").unwrap_err();
        assert!(
            err.contains("repo:invalid"),
            "error should name the bad token: {err}"
        );
    }

    #[test]
    fn normalize_request_rejects_empty() {
        assert!(normalize_scope_request("").is_err());
        assert!(normalize_scope_request("   ").is_err());
    }

    #[test]
    fn normalize_request_canonicalizes_granular_set() {
        let out = normalize_scope_request(
            "atproto repo:com.example.foo?action=create&action=update&action=delete \
             rpc:com.example.method1?aud=*",
        )
        .unwrap();
        assert_eq!(
            out,
            "atproto repo:com.example.foo rpc:com.example.method1?aud=*"
        );
    }

    #[test]
    fn granular_permission_checks_match_resources() {
        let scope = "atproto repo:app.bsky.feed.post?action=create rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app blob:image/* account:email identity:handle transition:email";
        assert!(allows_repo(scope, "app.bsky.feed.post", RepoAction::Create));
        assert!(!allows_repo(
            scope,
            "app.bsky.feed.post",
            RepoAction::Delete
        ));
        assert!(!allows_repo(
            scope,
            "app.bsky.graph.follow",
            RepoAction::Create
        ));
        assert!(allows_rpc(
            scope,
            "app.bsky.feed.getTimeline",
            "did:web:api.bsky.app"
        ));
        assert!(!allows_rpc(
            scope,
            "chat.bsky.convo.listConvos",
            "did:web:api.bsky.chat#bsky_chat"
        ));
        assert!(allows_blob(scope, "image/png"));
        assert!(!allows_blob(scope, "application/json"));
        assert!(allows_email(scope));
        assert!(allows_identity(scope, "handle"));
        assert!(!allows_account(scope, "status", "manage"));
    }

    #[test]
    fn transition_generic_preserves_legacy_full_access() {
        let scope = "atproto transition:generic";
        assert!(allows_repo(
            scope,
            "app.bsky.graph.follow",
            RepoAction::Delete
        ));
        assert!(allows_rpc(
            scope,
            "chat.bsky.convo.listConvos",
            "did:web:api.bsky.chat#bsky_chat"
        ));
        assert!(allows_blob(scope, "application/json"));
        assert!(allows_email(scope));
        assert!(allows_account(scope, "status", "manage"));
        assert!(allows_identity(scope, "handle"));
    }

    #[test]
    fn transition_chat_scope_grants_chat_rpc_only() {
        let scope = "atproto transition:chat.bsky";
        assert!(allows_rpc(
            scope,
            "chat.bsky.convo.listConvos",
            "did:web:api.bsky.chat#bsky_chat"
        ));
        assert!(allows_rpc(
            scope,
            "chat.bsky.convo.sendMessage",
            "did:example:other-chat-service"
        ));
        assert!(!allows_rpc(
            scope,
            "app.bsky.feed.getTimeline",
            "did:web:api.bsky.app"
        ));
        assert!(!allows_repo(
            scope,
            "app.bsky.feed.post",
            RepoAction::Create
        ));
        assert!(!allows_blob(scope, "image/png"));
        assert!(!allows_email(scope));
        assert!(!allows_account(scope, "status", "manage"));
        assert!(!allows_identity(scope, "handle"));
    }

    #[test]
    fn is_atproto_oauth_scope_matches_valid_sets() {
        assert!(is_atproto_oauth_scope("atproto"));
        assert!(is_atproto_oauth_scope("atproto transition:generic"));
        assert!(is_atproto_oauth_scope("atproto repo:app.bsky.feed.post"));
        assert!(!is_atproto_oauth_scope("transition:generic")); // missing atproto
        assert!(!is_atproto_oauth_scope("atproto bogus:token"));
        assert!(!is_atproto_oauth_scope("com.atproto.access")); // legacy session scope, not granular
    }

    // ── scope-token intersection (agent scope clamping) ───────────────────────

    #[test]
    fn intersect_keeps_only_common_tokens_sorted() {
        let stored = vec![
            "atproto".to_string(),
            "repo:*?action=create&action=update".to_string(),
            "blob:*/*".to_string(),
        ];
        // Operator narrowed the config to drop blob uploads.
        let config = vec![
            "atproto".to_string(),
            "repo:*?action=create&action=update".to_string(),
        ];
        assert_eq!(
            intersect_scope_tokens(&stored, &config),
            vec![
                "atproto".to_string(),
                "repo:*?action=create&action=update".to_string(),
            ]
        );
    }

    #[test]
    fn intersect_never_widens_beyond_stored() {
        // A config that grants more than the stored set can't add capabilities.
        let stored = vec!["atproto".to_string(), "blob:*/*".to_string()];
        let config = vec![
            "atproto".to_string(),
            "blob:*/*".to_string(),
            "identity:*".to_string(),
        ];
        assert_eq!(
            intersect_scope_tokens(&stored, &config),
            vec!["atproto".to_string(), "blob:*/*".to_string()]
        );
    }

    // ── idempotent normalization (parse→normalize→serialize round-trip) ────────

    #[test]
    fn normalization_is_idempotent() {
        let inputs = [
            "atproto",
            "atproto transition:generic transition:email transition:chat.bsky",
            "atproto repo:*",
            "atproto repo:app.bsky.feed.post?action=create",
            "atproto repo?collection=com.example.b&collection=com.example.a",
            "atproto rpc:com.example.method?aud=did:web:example.com%23svc",
            "atproto blob:image/*",
            "atproto account:email?action=manage",
            "atproto identity:*",
            "atproto include:com.example.perms",
        ];
        for input in inputs {
            let once = normalize_scope_request(input)
                .unwrap_or_else(|e| panic!("{input:?} should be valid: {e}"));
            let twice = normalize_scope_request(&once)
                .unwrap_or_else(|e| panic!("normalized {once:?} should re-validate: {e}"));
            assert_eq!(
                once, twice,
                "normalization must be idempotent for {input:?}"
            );
        }
    }
}
