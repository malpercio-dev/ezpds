// pattern: Mixed (unavoidable)
//
// Turns the `space:` scope tokens of an authorization request into the user-legible text the
// consent screen shows: the space type declaration's `name` in place of the raw NSID, a named
// authority DID's bidirectionally-verified handle in place of the DID, the collections a bare
// grant actually covers, and the broad-grant warning. Real network I/O (DNS, HTTP) — like
// `auth/permission_sets.rs`, whose Lexicon resolution path this reuses, it can't be a pure
// Functional Core despite living in `auth/`.
//
// Unlike `include:` expansion, a failure here is not fatal to the page. An `include:` token is
// replaced by what it resolves to, so a display resolution that disagrees with the authoritative
// one silently changes the grant; a `space:` token is rendered as itself either way, and only its
// label degrades. So every lookup below falls back rather than failing the request, and the
// warning — derived from the token alone — never depends on the network at all.
//
use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::identity::resolution;

use super::oauth_scopes::{parse_space_token, space_grant_writes_records, SpaceGrant};
use super::permission_sets::{
    fetch_lexicon_schema, resolve_authority_endpoint, resolve_cached, ResolutionCache,
};

/// Upper bound on distinct space types resolved for one consent render. Each miss is a real
/// DNS-and-HTTP chain, and `GET /oauth/authorize` is unauthenticated, so this is the same
/// anti-amplification cap `permission_sets::MAX_INCLUDE_TOKENS_PER_REQUEST` puts on `include:`.
/// Types past the cap render under their raw NSID rather than failing the page.
const MAX_SPACE_TYPES_PER_REQUEST: usize = 5;

// ── Space type declarations ─────────────────────────────────────────────────────

/// A space type declaration's `main` def: the Lexicon shape a space-type NSID resolves to
/// (proposal 0016, "Space type declarations"). Only the consent-relevant fields are read;
/// `key` and `description` are for clients and developers respectively.
#[derive(Clone, Deserialize)]
pub(crate) struct SpaceTypeDecl {
    /// Human-readable name shown to users on consent screens.
    pub name: String,
    /// Localized `name` values by language code.
    #[serde(default, rename = "name:lang")]
    pub name_lang: HashMap<String, String>,
    /// Collections a space of this type is expected to hold — the default `collection` set for
    /// a `space:` grant of this type.
    #[serde(default)]
    pub collections: Vec<String>,
}

impl SpaceTypeDecl {
    /// The declaration's name in the best available language: an exact `name:lang` tag match
    /// first, then a primary-subtag match (`es-419` accepts an `es` entry), then the base `name`.
    fn localized_name(&self, langs: &[String]) -> &str {
        for tag in langs {
            if let Some(name) = self.name_lang.get(tag) {
                return name;
            }
            let primary = tag.split('-').next().unwrap_or(tag);
            if let Some(name) = self.name_lang.get(primary) {
                return name;
            }
        }
        &self.name
    }
}

/// TTL cache of resolved space type declarations, keyed by the type NSID. Held in `AppState`
/// alongside `PermissionSetCache`, and on the same TTLs — the spec gives space-type declarations
/// the permission-set dynamic-update semantics, so a widened `collections` propagates on the
/// same schedule a widened permission set does.
pub type SpaceTypeCache = ResolutionCache<SpaceTypeDecl>;

/// Create an empty `SpaceTypeCache`.
pub fn new_space_type_cache() -> SpaceTypeCache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Fetch and parse `nsid`'s space type declaration from its publishing authority.
async fn resolve_space_type(state: &AppState, nsid: &str) -> Result<SpaceTypeDecl, String> {
    let authority = resolve_authority_endpoint(state, nsid).await?;
    let record = fetch_lexicon_schema(&state.hardened_http_client, &authority, nsid).await?;

    let main = record
        .get("defs")
        .and_then(|defs| defs.get("main"))
        .ok_or_else(|| format!("\"{nsid}\" has no \"main\" definition"))?;
    if main.get("type").and_then(serde_json::Value::as_str) != Some("space") {
        return Err(format!("\"{nsid}\" is not a space type declaration"));
    }

    serde_json::from_value(main.clone())
        .map_err(|e| format!("\"{nsid}\"'s space type declaration is malformed: {e}"))
}

/// `resolve_space_type` behind the TTL cache.
pub(crate) async fn resolve_space_type_cached(
    state: &AppState,
    cache: &SpaceTypeCache,
    nsid: &str,
) -> Result<SpaceTypeDecl, String> {
    resolve_cached(
        cache,
        nsid.to_string(),
        || format!("\"{nsid}\" could not be resolved (cached failure)"),
        resolve_space_type(state, nsid),
    )
    .await
}

// ── Consent display ─────────────────────────────────────────────────────────────

/// How a `*` space type reads on the consent screen, since no declaration can name it.
pub const WILDCARD_TYPE_LABEL: &str = "Any kind of space";

/// What the consent screen renders for one `space:` token, in place of the raw token.
#[derive(Debug, Default, PartialEq)]
pub struct SpaceDisplay {
    /// The declaration's localized `name`; `WILDCARD_TYPE_LABEL` for a `*` type, and the raw
    /// NSID when a concrete type's declaration could not be resolved.
    pub type_label: String,
    /// How the grant's `authority` reads: `None` for `self` (the user's own account, which the
    /// spec says needs no presentation) and for `*` (covered by `broad` instead), otherwise a
    /// named DID's bidirectionally-verified handle, falling back to the DID itself.
    pub authority_label: Option<String>,
    /// Whether the grant covers spaces under any authority.
    pub any_authority: bool,
    /// The collections the grant can write, resolved: its own `collection=` values, or the
    /// declaration's `collections` when it names none. Empty when the grant writes no records
    /// at all (`read`/`read_self` ignore `collection`), and `["*"]` for an explicit widening.
    pub collections: Vec<String>,
    /// Whether the grant wildcards `spaceType` *and* `authority` — "every kind of space,
    /// under anyone", which the spec singles out for a prominent warning.
    pub broad: bool,
    /// `manage=` verbs, which act on the spaces themselves rather than their records.
    pub manage: Vec<String>,
}

/// Everything the consent page needs to render the request's `space:` tokens, keyed by the token
/// as it appears in the scope string. A token with no entry renders raw, which is also what the
/// empty map (the paths that resolve nothing) produces for every token.
pub type SpaceDisplayMap = HashMap<String, SpaceDisplay>;

/// Parse every `space:` token in `scope` into its grant, dropping any that don't parse.
fn parse_space_grants(scope: &str) -> Vec<(&str, SpaceGrant)> {
    scope
        .split_whitespace()
        .filter_map(|token| parse_space_token(token).map(|grant| (token, grant)))
        .collect()
}

/// Assemble the display map from already-resolved inputs. Pure: every field either comes from
/// the token itself or from a `decls`/`handles` entry a caller resolved, and a missing entry is
/// the degraded case rather than an error.
fn build_displays(
    grants: &[(&str, SpaceGrant)],
    decls: &HashMap<&str, SpaceTypeDecl>,
    handles: &HashMap<&str, String>,
    langs: &[String],
) -> SpaceDisplayMap {
    grants
        .iter()
        .map(|(token, grant)| {
            let decl = decls.get(grant.space_type.as_str());
            let any_authority = grant.authority == "*";

            let collections = if !space_grant_writes_records(grant) {
                Vec::new()
            } else if !grant.collection.is_empty() {
                grant.collection.clone()
            } else {
                // A bare grant's write targets come from the declaration as it stands now, not as
                // it stood at consent time — so this is what the grant covers today, and the page
                // must not present it as a list frozen at approval.
                decl.map(|d| d.collections.clone()).unwrap_or_default()
            };

            let display = SpaceDisplay {
                type_label: match decl {
                    Some(d) => d.localized_name(langs).to_string(),
                    // A `*` type has no declaration to name it and never will, so it gets words
                    // rather than the bare glyph — the raw token still shows on the row.
                    None if grant.space_type == "*" => WILDCARD_TYPE_LABEL.to_string(),
                    None => grant.space_type.clone(),
                },
                authority_label: match grant.authority.as_str() {
                    "self" | "*" => None,
                    did => Some(handles.get(did).cloned().unwrap_or_else(|| did.to_string())),
                },
                any_authority,
                collections,
                broad: grant.space_type == "*" && any_authority,
                manage: grant.manage.clone(),
            };
            ((*token).to_string(), display)
        })
        .collect()
}

/// The token-only half of the display map: everything derivable with no network I/O at all —
/// the broad-grant warning, explicit collections, and the raw NSID as the label.
///
/// For the paths that must not resolve. The password-error re-render is the one that matters:
/// it happens before the login rate-limit gate, and doing outbound DNS/HTTP there would hand an
/// unauthenticated caller unthrottled network amplification by varying the scope per submission.
/// The warning is the half that must never degrade, and it doesn't — it is derived from the
/// token.
pub fn space_displays_without_resolution(scope: &str) -> SpaceDisplayMap {
    build_displays(
        &parse_space_grants(scope),
        &HashMap::new(),
        &HashMap::new(),
        &[],
    )
}

/// Build the display map for every `space:` token in an already-normalized `scope`.
///
/// Best-effort throughout: an unresolvable declaration or handle degrades that field to the raw
/// NSID or DID rather than failing, because — unlike `include:` expansion — the rendered checkbox
/// value is the token itself, so a degraded label can't desync what the user approves from what
/// is granted.
///
/// `langs` are the request's preferred language tags, most-preferred first (see
/// `preferred_languages`).
pub async fn resolve_space_displays(
    state: &AppState,
    cache: &SpaceTypeCache,
    scope: &str,
    langs: &[String],
) -> SpaceDisplayMap {
    let grants = parse_space_grants(scope);

    // Resolve each distinct concrete type at most once, under the amplification cap.
    let mut decls: HashMap<&str, SpaceTypeDecl> = HashMap::new();
    for (_, grant) in &grants {
        if grant.space_type == "*" || decls.contains_key(grant.space_type.as_str()) {
            continue;
        }
        if decls.len() >= MAX_SPACE_TYPES_PER_REQUEST {
            tracing::debug!(
                space_type = %grant.space_type,
                "space type declaration not resolved for consent: per-request cap reached"
            );
            continue;
        }
        match resolve_space_type_cached(state, cache, &grant.space_type).await {
            Ok(decl) => {
                decls.insert(&grant.space_type, decl);
            }
            Err(e) => tracing::debug!(
                space_type = %grant.space_type,
                error = %e,
                "space type declaration could not be resolved for consent; showing the raw NSID"
            ),
        }
    }

    let mut handles: HashMap<&str, String> = HashMap::new();
    for (_, grant) in &grants {
        let did = grant.authority.as_str();
        if did == "self" || did == "*" || handles.contains_key(did) {
            continue;
        }
        handles.insert(did, authority_handle(state, did).await);
    }

    build_displays(&grants, &decls, &handles, langs)
}

/// A named authority DID's bidirectionally-verified handle, or the DID when none verifies.
///
/// "Bidirectional" is what `verified_handle_for_did` enforces: the DID document must claim the
/// handle *and* the handle must resolve back to this DID. A one-way claim is exactly the
/// spoofing a consent screen must not repeat back to the user as fact.
async fn authority_handle(state: &AppState, did: &str) -> String {
    let Ok(doc) = resolution::resolve_did_document(state, did).await else {
        return did.to_string();
    };
    match resolution::verified_handle_for_did(state, did, &doc).await {
        Ok(handle) if handle != resolution::INVALID_HANDLE => handle,
        _ => did.to_string(),
    }
}

/// Parse an `Accept-Language` header into preferred language tags, most-preferred first.
///
/// Deliberately small: q-values are honoured by order only (a re-sort would need a stable
/// tie-break to be worth anything, and this picks between translations of one short name).
pub fn preferred_languages(accept_language: Option<&str>) -> Vec<String> {
    accept_language
        .unwrap_or("")
        .split(',')
        .filter_map(|part| {
            let tag = part.split(';').next()?.trim();
            (!tag.is_empty() && tag != "*").then(|| tag.to_ascii_lowercase())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_state;
    use crate::auth::permission_sets::tests_support::{pds_doc, state_with_dns, AUTHORITY_DID};
    use crate::db::dids::seed_did_document;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn space_schema(nsid: &str, main: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "lexicon": 1, "id": nsid, "defs": { "main": main } })
    }

    fn forum_decl() -> serde_json::Value {
        serde_json::json!({
            "type": "space",
            "description": "A discussion forum",
            "key": "any",
            "name": "AtmoBoards Forum",
            "name:lang": { "es": "Foro AtmoBoards" },
            "collections": ["com.atmoboards.thread", "com.atmoboards.reply"],
        })
    }

    /// Mount a mock authority serving `main` as `nsid`'s Lexicon schema record.
    async fn state_serving(
        server: &MockServer,
        nsid: &str,
        main: serde_json::Value,
    ) -> crate::app::AppState {
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc(&server.uri())).await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .and(query_param("rkey", nsid))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": format!("at://{AUTHORITY_DID}/com.atproto.lexicon.schema/{nsid}"),
                "cid": "bafyreictest",
                "value": space_schema(nsid, main),
            })))
            .mount(server)
            .await;

        state
    }

    // ── Declaration resolution ───────────────────────────────────────────────

    #[tokio::test]
    async fn declaration_supplies_the_name_and_default_collections() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_serving(&server, nsid, forum_decl()).await;

        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto space:{nsid}"),
            &[],
        )
        .await;

        let d = &displays[&format!("space:{nsid}")];
        assert_eq!(d.type_label, "AtmoBoards Forum");
        assert_eq!(
            d.collections,
            vec!["com.atmoboards.thread", "com.atmoboards.reply"],
            "a bare grant's write targets come from the declaration"
        );
        assert!(!d.broad);
        assert_eq!(d.authority_label, None, "authority=self needs no display");
    }

    #[tokio::test]
    async fn localized_name_is_preferred_when_the_declaration_has_one() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_serving(&server, nsid, forum_decl()).await;
        let cache = new_space_type_cache();
        let scope = format!("atproto space:{nsid}");

        let es = resolve_space_displays(&state, &cache, &scope, &["es-419".to_string()]).await;
        assert_eq!(
            es[&format!("space:{nsid}")].type_label,
            "Foro AtmoBoards",
            "a regional tag falls back to its primary subtag's translation"
        );

        let de = resolve_space_displays(&state, &cache, &scope, &["de".to_string()]).await;
        assert_eq!(
            de[&format!("space:{nsid}")].type_label,
            "AtmoBoards Forum",
            "an untranslated language falls back to the base name"
        );
    }

    #[tokio::test]
    async fn explicit_collections_win_over_the_declaration() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_serving(&server, nsid, forum_decl()).await;

        let token = format!("space:{nsid}?collection=com.atmoboards.thread");
        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto {token}"),
            &[],
        )
        .await;

        assert_eq!(displays[&token].collections, vec!["com.atmoboards.thread"]);
    }

    /// `read`/`read_self` are all-or-nothing at the space boundary and ignore `collection`, so
    /// listing collections for a read-only grant would tell the user something untrue.
    #[tokio::test]
    async fn a_read_only_grant_lists_no_collections() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_serving(&server, nsid, forum_decl()).await;

        let token = format!("space:{nsid}?action=read");
        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto {token}"),
            &[],
        )
        .await;

        assert!(displays[&token].collections.is_empty());
    }

    /// A permission-set record is not a space type declaration; resolving one must not be
    /// mistaken for a space and must degrade to the raw NSID rather than fail the page.
    #[tokio::test]
    async fn a_non_space_definition_degrades_to_the_raw_nsid() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_serving(
            &server,
            nsid,
            serde_json::json!({ "type": "permission-set", "permissions": [] }),
        )
        .await;

        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto space:{nsid}"),
            &[],
        )
        .await;

        assert_eq!(displays[&format!("space:{nsid}")].type_label, nsid);
    }

    /// No DNS authority at all: the page still renders, under the raw NSID.
    #[tokio::test]
    async fn an_unresolvable_type_degrades_to_the_raw_nsid() {
        let state = state_with_dns(test_state().await, vec![]);
        let nsid = "com.atmoboards.forum";

        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto space:{nsid}"),
            &[],
        )
        .await;

        let d = &displays[&format!("space:{nsid}")];
        assert_eq!(d.type_label, nsid);
        assert!(d.collections.is_empty(), "no declaration, no default set");
    }

    #[tokio::test]
    async fn resolution_is_cached_across_renders() {
        let server = MockServer::start().await;
        let nsid = "com.atmoboards.forum";
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc(&server.uri())).await;

        // Exactly one fetch — wiremock panics on drop if the count is wrong.
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": format!("at://{AUTHORITY_DID}/com.atproto.lexicon.schema/{nsid}"),
                "cid": "bafyreictest",
                "value": space_schema(nsid, forum_decl()),
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = new_space_type_cache();
        let scope = format!("atproto space:{nsid}");
        let first = resolve_space_displays(&state, &cache, &scope, &[]).await;
        let second = resolve_space_displays(&state, &cache, &scope, &[]).await;
        assert_eq!(first, second);
    }

    /// The cap bounds outbound resolution on an unauthenticated render; capped types still
    /// render, under their raw NSID.
    #[tokio::test]
    async fn distinct_types_past_the_cap_are_not_resolved() {
        let state = state_with_dns(test_state().await, vec![]);
        let scope: String = std::iter::once("atproto".to_string())
            .chain((0..MAX_SPACE_TYPES_PER_REQUEST + 2).map(|i| format!("space:com.example.s{i}")))
            .collect::<Vec<_>>()
            .join(" ");

        let displays = resolve_space_displays(&state, &new_space_type_cache(), &scope, &[]).await;
        assert_eq!(displays.len(), MAX_SPACE_TYPES_PER_REQUEST + 2);
    }

    // ── Wildcards ────────────────────────────────────────────────────────────

    /// Wildcarding both axes is "every kind of space, under anyone" — the one grant the spec
    /// singles out for a prominent warning. It is derived from the token, so it holds with no
    /// network at all.
    #[tokio::test]
    async fn both_wildcards_flag_a_broad_grant() {
        let state = state_with_dns(test_state().await, vec![]);
        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            "atproto space:*?authority=*",
            &[],
        )
        .await;

        let d = &displays["space:*?authority=*"];
        assert!(d.broad);
        assert!(d.any_authority);
        assert_eq!(d.type_label, WILDCARD_TYPE_LABEL);
    }

    /// A forum client asking for every authority's forums is the *typical* grant, not a broad
    /// one — warning on it would train users to click through the warning that matters.
    #[tokio::test]
    async fn one_wildcard_alone_is_not_a_broad_grant() {
        let state = state_with_dns(test_state().await, vec![]);
        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            "atproto space:com.atmoboards.forum?authority=* space:*",
            &[],
        )
        .await;

        assert!(!displays["space:com.atmoboards.forum?authority=*"].broad);
        assert!(!displays["space:*"].broad);
    }

    // ── Authority handle ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_named_authority_falls_back_to_the_did_when_no_handle_verifies() {
        // A syntactically valid did:plc — the grammar drops a malformed authority outright, so a
        // fixture that isn't one would test nothing.
        const NAMED_AUTHORITY: &str = "did:plc:abc234abc234abc234abc234";
        let state = state_with_dns(test_state().await, vec![]);
        let token = format!("space:com.atmoboards.forum?authority={NAMED_AUTHORITY}");

        let displays = resolve_space_displays(
            &state,
            &new_space_type_cache(),
            &format!("atproto {token}"),
            &[],
        )
        .await;

        assert_eq!(
            displays[&token].authority_label.as_deref(),
            Some(NAMED_AUTHORITY),
            "an unverifiable handle must never be shown as if it were verified"
        );
    }

    // ── preferred_languages ──────────────────────────────────────────────────

    #[test]
    fn accept_language_parses_to_ordered_lowercase_tags() {
        assert_eq!(
            preferred_languages(Some("es-419,es;q=0.9,en;q=0.8,*;q=0.5")),
            vec!["es-419", "es", "en"]
        );
        assert!(preferred_languages(None).is_empty());
        assert!(preferred_languages(Some("")).is_empty());
    }
}
