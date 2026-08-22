// pattern: Functional Core
//
//! ATProto granular OAuth auth-scope grammar (proposal 0011 / the atproto
//! permission spec).
//!
//! This is the *functional core* of the granular-scope work: it parses,
//! validates, and canonically normalizes the scope grammar
//! `resource[:positional][?param=value...]` across the six resource types
//! (`repo`, `rpc`, `blob`, `account`, `identity`, `space`), the permission-set
//! reference (`include:`), and the fixed scopes (`atproto`, `transition:generic`,
//! `transition:email`, `transition:chat.bsky`).
//!
//! `space:` comes from Atproto Spaces (proposal 0016) rather than 0011, and is ported
//! from that branch's `SpacePermission` for the same round-tripping reason.
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

/// Every `space:` `action=` value, in the canonical order a normalized token emits them.
/// `read_self` sorts first, mirroring the reference's `SPACE_ACTIONS`.
const SPACE_ACTIONS: [&str; 5] = ["read_self", "read", "create", "update", "delete"];

/// The `action` set a `space:` grant carries when it names none. `read_self` is absent
/// because `read` already implies it, so spelling both would be redundant.
const SPACE_DEFAULT_ACTIONS: [&str; 4] = ["read", "create", "update", "delete"];

/// Every `space:` `manage=` verb, in canonical order. These act on the space itself rather
/// than its records; deliberately a separate list from `REPO_ACTIONS` despite the identical
/// spelling, because their default differs (no management capability unless asked for).
const SPACE_MANAGE_OPS: [&str; 3] = ["create", "update", "delete"];

/// A declarative summary of each granular resource-type prefix, for `scopes_supported` in
/// OAuth discovery metadata. Each prefix accepts further positional/query parameters per the
/// grammar above — the full grantable scope space is unbounded, so this summarizes it by
/// prefix rather than enumerating every concrete value.
const SCOPE_PREFIX_SUMMARY: [&str; 7] = [
    "repo:*",
    "rpc:*",
    "blob:*/*",
    "account:*",
    "identity:*",
    "space:*",
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
        "space" => "Spaces",
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
/// so narrowing it narrows subsequently minted assertions without re-registration, while the
/// result can never exceed what was stored at registration. The comparison is token-exact — both
/// inputs are the same canonical scope
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

/// Canonicalize a list of operator-configured agent scope tokens (`[agent_auth] granted_scopes` /
/// `pre_claim_scopes`), returning each token in its canonical form.
///
/// Because scope clamping (`intersect_scope_tokens`) matches tokens by exact canonical string, a
/// non-canonical-but-valid config token (e.g. reordered `action=` params) would silently fail to
/// match and drop the capability at mint time. Canonicalizing the config at startup removes that
/// hazard, and an unsupported/malformed token becomes a fail-fast startup error (naming the token)
/// rather than a silent loss of access.
pub fn canonicalize_agent_scopes(tokens: &[String]) -> Result<Vec<String>, String> {
    tokens
        .iter()
        .map(|token| {
            normalize_token(token)
                .ok_or_else(|| format!("unsupported or malformed scope token: {token:?}"))
        })
        .collect()
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
        "space" => normalize_space(&syntax),
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

// ── space (Atproto Spaces, proposal 0016) ─────────────────────────────────────

/// A parsed, validated `space:` grant — the reference's `SpacePermission`.
///
/// `space_type`/`authority`/`skey` select **which spaces** the grant covers (the first three
/// segments of a space URI); `action` + `collection` govern the records in them; `manage`
/// governs the spaces themselves.
pub(super) struct SpaceGrant {
    pub(super) space_type: String,
    pub(super) authority: String,
    pub(super) skey: String,
    /// Explicit `collection=` values. Empty means the grant named none — the space type
    /// declaration then supplies the write targets at match time. Empty is never "all".
    pub(super) collection: Vec<String>,
    pub(super) action: Vec<String>,
    pub(super) manage: Vec<String>,
}

/// Parse a whole `space:` scope token into its grant, for callers outside the grammar itself.
///
/// The consent renderer needs the same `(type, authority, collection, action, manage)` view the
/// matcher uses; routing it through this one parse is what keeps what the user is shown and what
/// the token actually authorizes from drifting apart. Returns `None` for any non-`space:` or
/// malformed token.
pub(super) fn parse_space_token(token: &str) -> Option<SpaceGrant> {
    let syntax = ScopeSyntax::parse(token);
    if syntax.prefix != "space" {
        return None;
    }
    parse_space_grant(&syntax)
}

/// Whether a grant's `action` set contains a verb that writes records — the only case in which
/// its `collection` set means anything (`read`/`read_self` are all-or-nothing at the space
/// boundary and ignore `collection` entirely).
pub(super) fn space_grant_writes_records(grant: &SpaceGrant) -> bool {
    grant
        .action
        .iter()
        .any(|a| a == "create" || a == "update" || a == "delete")
}

fn is_space_type_param(v: &str) -> bool {
    v == "*" || is_nsid(v)
}

/// A space authority: `self` (the granting account), `*` (any), or a concrete DID.
///
/// The reference accepts any syntactically valid DID here; this server narrows that to the
/// atproto DID methods it can actually resolve, the same line every other DID position in this
/// grammar draws. A `did:example:` authority would parse there and still be unreachable here.
fn is_space_authority_param(v: &str) -> bool {
    v == "*" || v == "self" || is_atproto_did(v)
}

fn is_space_skey_param(v: &str) -> bool {
    v == "*" || is_record_key(v)
}

/// Parse a `space:` token's syntax into a validated grant, or `None` if it is malformed.
///
/// Shared by normalization and matching so the two can never disagree about what a token
/// means — a token that fails to parse authorizes nothing.
fn parse_space_grant(syntax: &ScopeSyntax) -> Option<SpaceGrant> {
    if !keys_allowed(
        syntax,
        &[
            "type",
            "authority",
            "skey",
            "collection",
            "action",
            "manage",
        ],
    ) {
        return None;
    }

    // type (positional name; required, single)
    let space_type = collect_positional_single(syntax, "type")?;
    if !is_space_type_param(&space_type) {
        return None;
    }

    // authority (optional, single, default "self")
    let authority = match syntax.get_single("authority") {
        None => "self".to_string(),
        Some(Some(v)) if is_space_authority_param(v) => v.to_string(),
        Some(_) => return None,
    };

    // skey (optional, single, default "*")
    let skey = match syntax.get_single("skey") {
        None => "*".to_string(),
        Some(Some(v)) if is_space_skey_param(v) => v.to_string(),
        Some(_) => return None,
    };

    // collection (optional, multi, default empty)
    let mut collection: Vec<String> = syntax
        .get_multi("collection")
        .iter()
        .map(|s| s.to_string())
        .collect();
    if !collection.iter().all(|v| is_collection_param(v)) {
        return None;
    }
    if collection.iter().any(|c| c == "*") {
        collection = vec!["*".to_string()];
    } else {
        collection = dedupe_sorted(collection);
    }

    // action (optional, multi, default read + create + update + delete)
    let action: Vec<String> = match syntax.get_multi("action") {
        v if v.is_empty() => SPACE_DEFAULT_ACTIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        v => {
            if !v.iter().all(|a| SPACE_ACTIONS.contains(a)) {
                return None;
            }
            SPACE_ACTIONS
                .iter()
                .filter(|a| v.contains(a))
                .map(|s| s.to_string())
                .collect()
        }
    };

    // manage (optional, multi, default empty)
    let manage_values = syntax.get_multi("manage");
    if !manage_values.iter().all(|m| SPACE_MANAGE_OPS.contains(m)) {
        return None;
    }
    let manage: Vec<String> = SPACE_MANAGE_OPS
        .iter()
        .filter(|m| manage_values.contains(m))
        .map(|s| s.to_string())
        .collect();

    Some(SpaceGrant {
        space_type,
        authority,
        skey,
        collection,
        action,
        manage,
    })
}

fn normalize_space(syntax: &ScopeSyntax) -> Option<String> {
    let grant = parse_space_grant(syntax)?;

    // Param order mirrors the reference parser's schema order, and every param equal to its
    // default is omitted, so two spellings of the same grant land on one canonical string.
    let mut params: Vec<(String, String)> = Vec::new();
    if grant.authority != "self" {
        params.push(("authority".to_string(), grant.authority));
    }
    if grant.skey != "*" {
        params.push(("skey".to_string(), grant.skey));
    }
    for c in &grant.collection {
        params.push(("collection".to_string(), c.clone()));
    }
    if !grant
        .action
        .iter()
        .map(String::as_str)
        .eq(SPACE_DEFAULT_ACTIONS)
    {
        for a in &grant.action {
            params.push(("action".to_string(), a.clone()));
        }
    }
    for m in &grant.manage {
        params.push(("manage".to_string(), m.clone()));
    }

    Some(format_scope("space", Some(&grant.space_type), &params))
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

/// An atproto record key, which is also the syntax a space's `skey` takes: 1-512 characters
/// from `[A-Za-z0-9._~:-]`, excluding the relative-path spellings `.` and `..`. Mirrors
/// `@atproto/syntax`'s `ensureValidRecordKey`.
fn is_record_key(v: &str) -> bool {
    (1..=512).contains(&v.len())
        && v != "."
        && v != ".."
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b':' | b'-'))
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

/// Require that a non-legacy granular OAuth grant permits a space operation.
pub fn require_space(scope: &str, req: &SpaceRequest<'_>) -> Result<(), ApiError> {
    if scope == SCOPE_ACCESS || allows_space(scope, req) {
        Ok(())
    } else {
        Err(insufficient_scope(
            "token scope does not permit this space operation",
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
///
/// Unlike [`allows_email`]/[`allows_account`]/[`allows_repo`], this deliberately does **not**
/// treat `transition:generic` as sufficient. Per the atproto OAuth spec, `transition:generic`
/// is app-password-equivalent and grants "no account management actions: change handle, ...,
/// migrate account" — i.e. it must NOT authorize identity/PLC operations. Only a granular
/// `identity:*`/`identity:{attr}` grant (or a full `com.atproto.access` session, handled by the
/// `require_*` gate) may drive them. bsky.social enforces the same rule; this keeps Custos from
/// being the one lax counterparty that let insufficient-scope tokens slip through.
pub fn allows_identity(scope: &str, attr: &str) -> bool {
    scope
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

/// The operation a `space:` grant is being checked against.
///
/// `Manage` reuses [`RepoAction`] because the `manage=` verbs are spelled with the same three
/// words — but they act on the space itself, not on a record in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Record`/`Manage` are constructed by the space write and simplespace management routes,
// which land after the read seam.
#[allow(dead_code)]
pub enum SpaceOp<'a> {
    /// Whole-space read and sync, plus `getDelegationToken`. Ignores `collection`, because
    /// read access is all-or-nothing at the space boundary.
    Read,
    /// The holder's own repo only, and no delegation token. Also satisfied by a `read` grant.
    ReadSelf,
    /// A record write, additionally constrained by the grant's `collection`.
    Record {
        action: RepoAction,
        collection: &'a str,
    },
    /// An operation on the space itself, governed by `manage`.
    Manage(RepoAction),
}

/// A space operation to authorize, plus the context a grant's defaults resolve against.
///
/// The two context fields exist because a `space:` token is deliberately context-free — the
/// reference materializes them into the permission at token-issuance time, and this server
/// resolves them at match time instead so the canonical token string stays stable (agent
/// scope clamping compares tokens by exact string, so a rewritten `self` would stop matching
/// the operator's config).
pub struct SpaceRequest<'a> {
    /// The target space's type NSID.
    pub space_type: &'a str,
    /// The target space authority's concrete DID.
    pub authority: &'a str,
    /// The target space's key.
    pub skey: &'a str,
    pub op: SpaceOp<'a>,
    /// The authenticated account's DID — what an `authority=self` grant resolves to.
    pub account_did: &'a str,
    /// The space type declaration's `collections`: the write targets of a grant that names no
    /// `collection` of its own. Resolved per request rather than frozen at consent time, so a
    /// declaration that later adds a collection widens existing bare grants.
    pub declared_collections: &'a [String],
}

impl SpaceGrant {
    fn matches(&self, req: &SpaceRequest<'_>) -> bool {
        if self.space_type != "*" && self.space_type != req.space_type {
            return false;
        }
        let authority = if self.authority == "self" {
            req.account_did
        } else {
            self.authority.as_str()
        };
        if authority != "*" && authority != req.authority {
            return false;
        }
        if self.skey != "*" && self.skey != req.skey {
            return false;
        }

        match req.op {
            SpaceOp::Read => self.action.iter().any(|a| a == "read"),
            // `read` implies `read_self`, so either satisfies the narrower request.
            SpaceOp::ReadSelf => self.action.iter().any(|a| a == "read" || a == "read_self"),
            SpaceOp::Record { action, collection } => {
                self.action.iter().any(|a| a == action.as_str())
                    && self.collection_allows(collection, req)
            }
            SpaceOp::Manage(op) => self.manage.iter().any(|m| m == op.as_str()),
        }
    }

    /// Whether the grant's write targets cover `collection`.
    ///
    /// A grant naming no `collection` falls back to the space type declaration's — but only
    /// when it names a concrete space type. `space:*` has no declaration to draw from, so it
    /// confers read access without ever conferring a write target.
    fn collection_allows(&self, collection: &str, req: &SpaceRequest<'_>) -> bool {
        if self.collection.is_empty() {
            return self.space_type != "*"
                && req.declared_collections.iter().any(|c| c == collection);
        }
        self.collection.iter().any(|c| c == "*" || c == collection)
    }
}

/// Whether a granular OAuth grant permits a space operation.
///
/// Like [`allows_identity`], this deliberately does **not** honor `transition:generic`. That
/// scope is app-password-equivalent and predates Atproto Spaces entirely, so treating it as
/// covering permissioned data would hand every legacy client the user's private spaces.
pub fn allows_space(scope: &str, req: &SpaceRequest<'_>) -> bool {
    scope.split_whitespace().any(|token| {
        let syntax = ScopeSyntax::parse(token);
        syntax.prefix == "space"
            && parse_space_grant(&syntax).is_some_and(|grant| grant.matches(req))
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
        .is_some_and(|(_, value)| value == "*" || aud_did(value) == aud_did(aud))
}

/// The bare DID of a `did[#serviceId]` audience reference.
///
/// Clients are split on whether an `rpc:` scope's `aud` carries the `#serviceId` fragment
/// (the spec's examples use the bare DID; real client metadata in the wild parameterizes
/// with the fragment), and this server's two enforcement sites historically disagreed too —
/// the proxy path checked the raw `atproto-proxy` header (fragment included) while
/// `getServiceAuth` checked the stripped DID, so the same grant could pass one and fail the
/// other. The fragment selects an endpoint in the DID document for *routing*; the audience
/// a receiving service authenticates is its bare DID, so the privilege boundary is the DID
/// and coverage compares exactly that.
fn aud_did(aud: &str) -> &str {
    aud.split_once('#').map_or(aud, |(did, _)| did)
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

    // ── space ─────────────────────────────────────────────────────────────────

    /// A `did:plc` the grammar accepts (24 base32 characters).
    const AUTHORITY_DID: &str = "did:plc:abc234567abc234567abc234";
    const ACCOUNT_DID: &str = "did:plc:zzz234567zzz234567zzz234";
    const NO_COLLECTIONS: &[String] = &[];

    fn space_req<'a>(op: SpaceOp<'a>, declared: &'a [String]) -> SpaceRequest<'a> {
        SpaceRequest {
            space_type: "com.atmoboards.forum",
            authority: AUTHORITY_DID,
            skey: "default",
            op,
            account_did: ACCOUNT_DID,
            declared_collections: declared,
        }
    }

    #[test]
    fn space_bare_grant_and_omitted_defaults() {
        assert_eq!(
            norm("space:com.atmoboards.forum").as_deref(),
            Some("space:com.atmoboards.forum")
        );
        assert_eq!(norm("space:*").as_deref(), Some("space:*"));
        // Every default spelled out collapses back to the bare form.
        assert_eq!(
            norm("space:com.atmoboards.forum?authority=self&skey=*&action=read&action=create&action=update&action=delete")
                .as_deref(),
            Some("space:com.atmoboards.forum")
        );
    }

    #[test]
    fn space_params_emit_in_schema_order() {
        assert_eq!(
            norm("space:com.atmoboards.forum?manage=delete&action=create&collection=com.atmoboards.thread&skey=default&authority=did:plc:abc234567abc234567abc234")
                .as_deref(),
            Some("space:com.atmoboards.forum?authority=did:plc:abc234567abc234567abc234&skey=default&collection=com.atmoboards.thread&action=create&manage=delete")
        );
    }

    #[test]
    fn space_actions_take_canonical_order_with_read_self_first() {
        assert_eq!(
            norm("space:com.example.x?action=delete&action=read&action=read_self").as_deref(),
            Some("space:com.example.x?action=read_self&action=read&action=delete")
        );
        // `read_self` is not part of the default set, so naming it is never a no-op.
        assert_eq!(
            norm("space:com.example.x?action=read_self&action=read&action=create&action=update&action=delete")
                .as_deref(),
            Some("space:com.example.x?action=read_self&action=read&action=create&action=update&action=delete")
        );
    }

    #[test]
    fn space_manage_ops_are_canonically_ordered_and_default_empty() {
        assert_eq!(
            norm("space:com.example.x?manage=delete&manage=create").as_deref(),
            Some("space:com.example.x?manage=create&manage=delete")
        );
        assert_eq!(
            norm("space:com.example.x").as_deref(),
            Some("space:com.example.x")
        );
    }

    #[test]
    fn space_collections_dedupe_sort_and_collapse_on_wildcard() {
        assert_eq!(
            norm("space:com.example.x?collection=com.example.b&collection=com.example.a&collection=com.example.b")
                .as_deref(),
            Some("space:com.example.x?collection=com.example.a&collection=com.example.b")
        );
        assert_eq!(
            norm("space:com.example.x?collection=com.example.a&collection=*").as_deref(),
            Some("space:com.example.x?collection=*")
        );
    }

    #[test]
    fn space_skey_takes_record_key_syntax() {
        let long = "x".repeat(512);
        let too_long = "x".repeat(513);
        for skey in ["self", "3jui7kd54zh2y", "a.b-c_d~e:f", "*", long.as_str()] {
            assert!(
                norm(&format!("space:com.example.x?skey={skey}")).is_some(),
                "skey {skey:?} should be accepted"
            );
        }
        for skey in [
            "hello%20world",
            ".",
            "..",
            "a%2Fb",
            "a%23b",
            "",
            too_long.as_str(),
        ] {
            assert_eq!(
                norm(&format!("space:com.example.x?skey={skey}")),
                None,
                "skey {skey:?} should be rejected"
            );
        }
    }

    #[test]
    fn space_invalid_is_rejected() {
        assert_eq!(norm("space"), None);
        assert_eq!(norm("space:"), None);
        assert_eq!(norm("space:not_an_nsid"), None);
        assert_eq!(norm("space:com.example.x?authority=not-a-did"), None);
        assert_eq!(norm("space:com.example.x?authority=did:"), None);
        assert_eq!(norm("space:com.example.x?action=bogus"), None);
        assert_eq!(norm("space:com.example.x?manage=bogus"), None);
        assert_eq!(norm("space:com.example.x?collection=not_an_nsid"), None);
        assert_eq!(norm("space:com.example.x?unknown=1"), None);
        // The positional argument and its named spelling are the same parameter.
        assert_eq!(norm("space:com.example.x?type=com.example.y"), None);
        // A repeated single-valued param has no single value to take.
        assert_eq!(norm("space:com.example.x?authority=self&authority=*"), None);
    }

    // ── space matching ────────────────────────────────────────────────────────

    #[test]
    fn space_read_is_all_or_nothing_and_ignores_collection() {
        let scope =
            format!("atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}&action=read");
        assert!(allows_space(
            &scope,
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
        // No collection was named, and read never needs one.
        assert!(allows_space(
            &scope,
            &space_req(SpaceOp::ReadSelf, NO_COLLECTIONS)
        ));
        // ...but it confers no writes.
        assert!(!allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.thread",
                },
                &["com.atmoboards.thread".to_string()],
            )
        ));
    }

    #[test]
    fn space_read_self_is_narrower_than_read() {
        let scope = format!(
            "atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}&action=read_self"
        );
        assert!(allows_space(
            &scope,
            &space_req(SpaceOp::ReadSelf, NO_COLLECTIONS)
        ));
        assert!(!allows_space(
            &scope,
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
    }

    #[test]
    fn space_writes_are_collection_constrained() {
        let scope = format!(
            "atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}&collection=com.atmoboards.thread&action=create"
        );
        assert!(allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.thread",
                },
                NO_COLLECTIONS
            )
        ));
        assert!(!allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.reply",
                },
                NO_COLLECTIONS
            )
        ));
        assert!(!allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Delete,
                    collection: "com.atmoboards.thread",
                },
                NO_COLLECTIONS
            )
        ));
    }

    #[test]
    fn space_bare_grant_writes_the_declared_collections() {
        let scope = format!("atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}");
        let declared = ["com.atmoboards.thread".to_string()];
        assert!(allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Update,
                    collection: "com.atmoboards.thread",
                },
                &declared
            )
        ));
        // A collection the declaration does not list stays out of reach.
        assert!(!allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Update,
                    collection: "com.atmoboards.reply",
                },
                &declared
            )
        ));
    }

    #[test]
    fn space_wildcard_type_grant_confers_no_write_targets() {
        // There is no declaration to draw a default from, so a bare `space:*` reads but never
        // writes — even when the target type declares collections.
        let scope = format!("atproto space:*?authority={AUTHORITY_DID}");
        let declared = ["com.atmoboards.thread".to_string()];
        assert!(allows_space(&scope, &space_req(SpaceOp::Read, &declared)));
        assert!(!allows_space(
            &scope,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.thread",
                },
                &declared
            )
        ));
        // Naming the collection explicitly still works.
        let explicit =
            format!("atproto space:*?authority={AUTHORITY_DID}&collection=com.atmoboards.thread");
        assert!(allows_space(
            &explicit,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.thread",
                },
                &declared
            )
        ));
    }

    #[test]
    fn space_self_authority_resolves_to_the_account_did() {
        let scope = "atproto space:com.atmoboards.forum";
        // The default `authority=self` does not reach a space anchored on someone else.
        assert!(!allows_space(
            scope,
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));

        let own = SpaceRequest {
            authority: ACCOUNT_DID,
            ..space_req(SpaceOp::Read, NO_COLLECTIONS)
        };
        assert!(allows_space(scope, &own));
    }

    #[test]
    fn space_identifier_components_all_have_to_match() {
        let scope = format!(
            "atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}&skey=default&action=read"
        );
        assert!(allows_space(
            &scope,
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
        for wrong in [
            SpaceRequest {
                space_type: "com.atmoboards.other",
                ..space_req(SpaceOp::Read, NO_COLLECTIONS)
            },
            SpaceRequest {
                authority: ACCOUNT_DID,
                ..space_req(SpaceOp::Read, NO_COLLECTIONS)
            },
            SpaceRequest {
                skey: "other",
                ..space_req(SpaceOp::Read, NO_COLLECTIONS)
            },
        ] {
            assert!(!allows_space(&scope, &wrong));
        }
        // Wildcards on each component open it back up.
        assert!(allows_space(
            "atproto space:*?authority=*&action=read",
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
    }

    #[test]
    fn space_manage_is_separate_from_record_access() {
        let record_only = format!("atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}");
        assert!(!allows_space(
            &record_only,
            &space_req(SpaceOp::Manage(RepoAction::Update), NO_COLLECTIONS)
        ));

        let managing = format!(
            "atproto space:com.atmoboards.forum?authority={AUTHORITY_DID}&action=read_self&manage=update"
        );
        assert!(allows_space(
            &managing,
            &space_req(SpaceOp::Manage(RepoAction::Update), NO_COLLECTIONS)
        ));
        assert!(!allows_space(
            &managing,
            &space_req(SpaceOp::Manage(RepoAction::Delete), NO_COLLECTIONS)
        ));
        // ...and it did not quietly grant record writes.
        assert!(!allows_space(
            &managing,
            &space_req(
                SpaceOp::Record {
                    action: RepoAction::Create,
                    collection: "com.atmoboards.thread",
                },
                &["com.atmoboards.thread".to_string()]
            )
        ));
    }

    #[test]
    fn space_access_needs_a_granular_grant_not_a_transition_scope() {
        // `transition:generic` is app-password-equivalent and predates spaces entirely.
        assert!(!allows_space(
            "atproto transition:generic",
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
        assert!(require_space(
            "atproto transition:generic",
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        )
        .is_err());
        // A full `com.atproto.access` session is the account owner and passes the gate.
        assert!(require_space(SCOPE_ACCESS, &space_req(SpaceOp::Read, NO_COLLECTIONS)).is_ok());
    }

    #[test]
    fn space_malformed_token_authorizes_nothing() {
        // A token that would fail normalization must not match by accident.
        assert!(!allows_space(
            "atproto space:com.atmoboards.forum?action=bogus",
            &space_req(SpaceOp::Read, NO_COLLECTIONS)
        ));
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
        // ...with ONE exception: identity/PLC operations. `transition:generic` is
        // app-password-equivalent, which the atproto spec excludes from identity/account-management
        // actions. Custos must refuse it here, matching bsky.social.
        assert!(!allows_identity(scope, "handle"));
        assert!(!allows_identity(scope, "*"));
    }

    #[test]
    fn transition_generic_is_refused_for_identity_ops() {
        // Regression guard: no OAuth token bsky.social can mint (its max is
        // `transition:generic`) may drive PLC operations. `require_identity` still passes a full
        // `com.atproto.access` password session (short-circuit before `allows_identity`), so the
        // wallet's password-based claim flow is unaffected — this only closes the OAuth path.
        let scope = "atproto transition:generic";
        assert!(require_identity(scope, "*").is_err());
        assert!(require_identity(scope, "handle").is_err());
        // A granular identity grant still works, and a full session always works.
        assert!(require_identity("atproto identity:*", "*").is_ok());
        assert!(require_identity(SCOPE_ACCESS, "*").is_ok());
    }

    /// The `#serviceId` fragment on either side of an `rpc:` audience is a DID-document
    /// routing selector, not a narrower principal — receiving services authenticate the
    /// bare DID. Clients are split on which convention they write in scope strings, and
    /// the proxy path (raw `atproto-proxy` header, fragment included) and `getServiceAuth`
    /// (stripped DID) present different forms of the same target, so coverage must compare
    /// DIDs and ignore fragments in every combination.
    #[test]
    fn rpc_aud_matches_on_the_did_ignoring_service_fragments() {
        let bare_grant = "atproto rpc:app.bsky.feed.getFeedSkeleton?aud=did:web:api.bsky.app";
        let frag_grant =
            "atproto rpc:at.marque.partner.listPricing?aud=did:web:marque.at%23marque_registrar";

        // Bare-DID grant covers both target forms.
        assert!(allows_rpc(
            bare_grant,
            "app.bsky.feed.getFeedSkeleton",
            "did:web:api.bsky.app"
        ));
        assert!(allows_rpc(
            bare_grant,
            "app.bsky.feed.getFeedSkeleton",
            "did:web:api.bsky.app#bsky_appview"
        ));

        // Fragment-qualified grant (pckt.blog's convention) covers both target forms too.
        assert!(allows_rpc(
            frag_grant,
            "at.marque.partner.listPricing",
            "did:web:marque.at#marque_registrar"
        ));
        assert!(allows_rpc(
            frag_grant,
            "at.marque.partner.listPricing",
            "did:web:marque.at"
        ));

        // A different DID never matches, whatever the fragments say.
        assert!(!allows_rpc(
            bare_grant,
            "app.bsky.feed.getFeedSkeleton",
            "did:web:evil.example#bsky_appview"
        ));
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
    fn canonicalize_agent_scopes_normalizes_and_rejects_bad_tokens() {
        // A reordered-but-valid token is rewritten to canonical form so it matches at intersect time.
        assert_eq!(
            canonicalize_agent_scopes(&[
                "atproto".to_string(),
                "repo:*?action=update&action=create".to_string(),
            ])
            .unwrap(),
            vec![
                "atproto".to_string(),
                "repo:*?action=create&action=update".to_string(),
            ]
        );
        // An unsupported token fails fast, naming the offender.
        let err = canonicalize_agent_scopes(&["repo:not-an-nsid".to_string()]).unwrap_err();
        assert!(
            err.contains("repo:not-an-nsid"),
            "error should name the token: {err}"
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

    #[test]
    fn intersect_never_widens_into_an_uncovered_space() {
        let registered = vec![
            "atproto".to_string(),
            "space:com.atmoboards.forum".to_string(),
        ];
        // The operator's ceiling names a *different*, broader space grant. Clamping is
        // token-exact, so neither the broader token nor the registered one survives.
        let ceiling = vec![
            "atproto".to_string(),
            "space:*?authority=*".to_string(),
            "space:com.other.space".to_string(),
        ];
        assert_eq!(
            intersect_scope_tokens(&registered, &ceiling),
            vec!["atproto".to_string()]
        );
        // The same grant on both sides is kept.
        assert_eq!(intersect_scope_tokens(&registered, &registered), registered);
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
            "atproto space:com.atmoboards.forum",
            "atproto space:*?authority=*&action=read",
            "atproto space:com.atmoboards.forum?authority=did:plc:abc234567abc234567abc234&skey=default&collection=com.atmoboards.thread&action=create&manage=update",
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
