// pattern: Mixed (unavoidable)
//
// Resolves `include:<nsid>[?aud=...]` OAuth scope references to Lexicon-published
// permission-set records (atproto proposal 0011 / atproto.com/specs/permission) and expands
// them into the canonical granular scope grammar `oauth_scopes.rs` already validates and
// enforces. Real network I/O (DNS, HTTP) — like `auth/dpop.rs`, this can't be a pure
// Functional Core despite living in `auth/`.
//
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::identity_resolution;

use super::oauth_scopes::{format_scope, normalize_scope_request, normalize_token, ScopeSyntax};

/// The Lexicon collection permission-set (and other Lexicon schema) records are published
/// under; the record key is the NSID itself.
const LEXICON_SCHEMA_COLLECTION: &str = "com.atproto.lexicon.schema";

// ── Cache ────────────────────────────────────────────────────────────────────

/// How long a successfully resolved permission set is served from cache before being
/// re-resolved — the finalized spec's 24h stale-refresh boundary. There is no background
/// refresh task; re-resolution happens inline the next time the set is requested past this TTL.
const POSITIVE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a failed resolution is negatively cached, so repeated submissions against the same
/// broken authority don't re-trigger the full resolution chain on every retry.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

pub(crate) enum CacheEntry {
    Resolved {
        scopes: Vec<String>,
        expires_at: Instant,
    },
    Failed {
        expires_at: Instant,
    },
}

/// In-memory cache of resolved permission sets, keyed on the full `include:` token (NSID + any
/// `aud` param — a different `aud` can change the expansion via `inheritAud` entries). Mirrors
/// `auth::dpop::DpopNonceStore`'s shape (`Arc<Mutex<HashMap<...>>>`); held in `AppState`.
pub type PermissionSetCache = Arc<Mutex<HashMap<String, CacheEntry>>>;

/// Create an empty `PermissionSetCache`.
pub fn new_permission_set_cache() -> PermissionSetCache {
    Arc::new(Mutex::new(HashMap::new()))
}

fn cache_key(nsid: &str, include_aud: Option<&str>) -> String {
    format!("{nsid}|{}", include_aud.unwrap_or(""))
}

/// Resolve and expand a single `include:<nsid>` reference, consulting `cache` first and
/// populating it (positively or negatively) after resolving. Fails closed exactly like
/// `resolve_permission_set`, whose outcome this wraps rather than replaces.
pub(crate) async fn resolve_permission_set_cached(
    state: &AppState,
    cache: &PermissionSetCache,
    nsid: &str,
    include_aud: Option<&str>,
) -> Result<Vec<String>, String> {
    let key = cache_key(nsid, include_aud);
    let now = Instant::now();

    {
        let map = cache.lock().await;
        match map.get(&key) {
            Some(CacheEntry::Resolved { scopes, expires_at }) if *expires_at > now => {
                return Ok(scopes.clone())
            }
            Some(CacheEntry::Failed { expires_at }) if *expires_at > now => {
                return Err(format!("\"{nsid}\" could not be resolved (cached failure)"));
            }
            _ => {}
        }
    }

    let result = resolve_permission_set(state, nsid, include_aud).await;
    let entry = match &result {
        Ok(scopes) => CacheEntry::Resolved {
            scopes: scopes.clone(),
            expires_at: now + POSITIVE_CACHE_TTL,
        },
        Err(_) => CacheEntry::Failed {
            expires_at: now + NEGATIVE_CACHE_TTL,
        },
    };
    cache.lock().await.insert(key, entry);
    result
}

/// Upper bound on distinct `include:` references processed per scope string. Each one can
/// trigger a real DNS + HTTP resolution chain (see `resolve_permission_set`), so without a cap
/// a single request — including the unauthenticated `GET /oauth/authorize` render path — could
/// carry an unbounded number of them, turning one request into unbounded outbound network calls.
const MAX_INCLUDE_TOKENS_PER_REQUEST: usize = 5;

/// Resolve every `include:<nsid>[?aud=...]` token in an already-normalized scope string to its
/// constituent granular scopes, leaving every other token untouched, then re-normalize the
/// whole result. This is the module's entry point, called from both the `GET` (render) and
/// `POST` (authoritative) paths of `routes::oauth_authorize`.
///
/// Fails closed: any `include:` resolution failure rejects the whole expansion, the same as a
/// malformed token would fail `normalize_scope_request` outright. Also fails closed — before
/// attempting any resolution — if the request carries more than `MAX_INCLUDE_TOKENS_PER_REQUEST`
/// `include:` references.
pub async fn expand_include_scopes(
    state: &AppState,
    cache: &PermissionSetCache,
    scope: &str,
) -> Result<String, String> {
    let tokens: Vec<&str> = scope.split_whitespace().collect();
    let include_count = tokens.iter().filter(|t| t.starts_with("include:")).count();
    if include_count > MAX_INCLUDE_TOKENS_PER_REQUEST {
        return Err(format!(
            "too many include: permission-set references in one request (max {MAX_INCLUDE_TOKENS_PER_REQUEST})"
        ));
    }

    let mut expanded_tokens: Vec<String> = Vec::new();

    for token in tokens {
        if token.starts_with("include:") {
            let syntax = ScopeSyntax::parse(token);
            let nsid = syntax.positional.clone().unwrap_or_default();
            let include_aud = syntax.get_single("aud").flatten().map(str::to_string);
            let resolved =
                resolve_permission_set_cached(state, cache, &nsid, include_aud.as_deref()).await?;
            expanded_tokens.extend(resolved);
        } else {
            expanded_tokens.push(token.to_string());
        }
    }

    normalize_scope_request(&expanded_tokens.join(" "))
}

/// A Lexicon authority's validated, SSRF-checked PDS service endpoint, ready to fetch from.
#[derive(Debug)]
pub(crate) struct AuthorityEndpoint {
    pub did: String,
    pub url: String,
    pub pinned: Option<identity_resolution::PinnedResolution>,
}

/// Reverse an NSID's authority segments into the domain that publishes it, per the atproto
/// Lexicon-publishing convention (`app.bsky.authFull` -> authority `app.bsky` -> domain
/// `bsky.app`). Returns `None` if `nsid` doesn't have at least an authority + name segment.
fn nsid_authority_domain(nsid: &str) -> Option<String> {
    let segments: Vec<&str> = nsid.split('.').collect();
    if segments.len() < 3 || segments.iter().any(|s| s.is_empty()) {
        return None;
    }
    let mut authority: Vec<&str> = segments[..segments.len() - 1].to_vec();
    authority.reverse();
    Some(authority.join("."))
}

/// Resolve a Lexicon authority domain to its publishing DID via `_lexicon.<domain>` DNS TXT,
/// mirroring `identity_resolution::resolve_handle_to_did`'s `_atproto.<handle>` lookup.
async fn resolve_authority_did(state: &AppState, domain: &str) -> Result<String, String> {
    let resolver = state
        .txt_resolver
        .as_ref()
        .ok_or_else(|| "DNS resolution is not configured on this server".to_string())?;

    let name = format!("_lexicon.{domain}");
    let records = resolver.txt_lookup(&name).await.map_err(|e| {
        tracing::warn!(
            error = %e,
            domain,
            "DNS TXT lookup failed while resolving a Lexicon authority"
        );
        format!("could not resolve the Lexicon authority for \"{domain}\"")
    })?;

    records
        .into_iter()
        .find_map(|record| record.strip_prefix("did=").map(|did| did.to_string()))
        .ok_or_else(|| format!("no Lexicon authority is published for \"{domain}\""))
}

/// Resolve `nsid`'s publishing authority to a validated, SSRF-checked PDS service endpoint.
pub(crate) async fn resolve_authority_endpoint(
    state: &AppState,
    nsid: &str,
) -> Result<AuthorityEndpoint, String> {
    let domain =
        nsid_authority_domain(nsid).ok_or_else(|| format!("\"{nsid}\" is not a valid NSID"))?;
    let authority_did = resolve_authority_did(state, &domain).await?;

    let doc = identity_resolution::resolve_did_document(state, &authority_did)
        .await
        .map_err(|_| format!("could not resolve the DID document for \"{authority_did}\""))?;

    let endpoint = doc
        .get("service")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| {
            matches!(
                entry.get("id").and_then(Value::as_str),
                Some("#atproto_pds")
            )
        })
        .and_then(|entry| entry.get("serviceEndpoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("\"{authority_did}\" does not advertise a PDS service endpoint"))?;

    let pinned =
        identity_resolution::validate_proxy_endpoint(endpoint, state.allow_loopback_proxy_targets)
            .await
            .map_err(|_| {
                format!("\"{authority_did}\"'s service endpoint is not a usable public address")
            })?;

    Ok(AuthorityEndpoint {
        did: authority_did,
        url: endpoint.to_string(),
        pinned,
    })
}

// ── Permission-set record shape ─────────────────────────────────────────────────

/// A resolved permission-set Lexicon record's `defs.main`.
#[derive(Deserialize)]
struct PermissionSetDef {
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    permissions: Vec<PermissionEntry>,
}

/// One entry in a permission-set's `permissions` array, tagged on `resource`.
///
/// `action`/`collection`/`lxm`/`accept` accept either a bare string or an array — permission-set
/// records in the wild aren't fully consistent on cardinality for single-vs-multi fields.
#[derive(Deserialize)]
#[serde(tag = "resource", rename_all = "lowercase")]
enum PermissionEntry {
    Repo {
        #[serde(deserialize_with = "string_or_vec")]
        collection: Vec<String>,
        #[serde(default, deserialize_with = "string_or_vec")]
        action: Vec<String>,
    },
    Rpc {
        #[serde(deserialize_with = "string_or_vec")]
        lxm: Vec<String>,
        #[serde(default)]
        aud: Option<String>,
        #[serde(default, rename = "inheritAud")]
        inherit_aud: bool,
    },
    Blob {
        #[serde(deserialize_with = "string_or_vec")]
        accept: Vec<String>,
    },
    Account {
        attr: String,
        #[serde(default, deserialize_with = "string_or_vec")]
        action: Vec<String>,
    },
    Identity {
        attr: String,
    },
}

/// Accept either a bare value or an array of values during deserialization — permission-set
/// records aren't fully consistent on cardinality for fields like `action`, and the
/// urlencoded-form deserializer used by `routes::oauth_authorize::ConsentForm` represents a
/// single repeated-key occurrence as a bare string rather than a one-element sequence. Shared
/// by both, since the generic `Deserializer` bound makes it format-agnostic.
pub(crate) fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }
    Ok(match StringOrVec::deserialize(deserializer)? {
        StringOrVec::One(s) => vec![s],
        StringOrVec::Many(v) => v,
    })
}

/// Render a permission entry into a raw candidate scope token (not yet validated/canonicalized —
/// the caller runs it through `normalize_token`). `include_aud` is the `aud` param on the
/// enclosing `include:` token, used by `Rpc { inherit_aud: true, .. }` entries.
fn render_permission_entry(entry: &PermissionEntry, include_aud: Option<&str>) -> String {
    match entry {
        PermissionEntry::Repo { collection, action } => {
            let mut params: Vec<(String, String)> = collection
                .iter()
                .map(|c| ("collection".to_string(), c.clone()))
                .collect();
            params.extend(action.iter().map(|a| ("action".to_string(), a.clone())));
            format_scope("repo", None, &params)
        }
        PermissionEntry::Rpc {
            lxm,
            aud,
            inherit_aud,
        } => {
            let resolved_aud = if *inherit_aud {
                include_aud.map(str::to_string)
            } else {
                aud.clone()
            };
            let mut params: Vec<(String, String)> =
                lxm.iter().map(|l| ("lxm".to_string(), l.clone())).collect();
            if let Some(aud) = resolved_aud {
                params.push(("aud".to_string(), aud));
            }
            format_scope("rpc", None, &params)
        }
        PermissionEntry::Blob { accept } => {
            let params: Vec<(String, String)> = accept
                .iter()
                .map(|a| ("accept".to_string(), a.clone()))
                .collect();
            format_scope("blob", None, &params)
        }
        PermissionEntry::Account { attr, action } => {
            let params: Vec<(String, String)> = action
                .iter()
                .map(|a| ("action".to_string(), a.clone()))
                .collect();
            format_scope("account", Some(attr), &params)
        }
        PermissionEntry::Identity { attr } => format_scope("identity", Some(attr), &[]),
    }
}

/// Whether a permission entry is a `blob` grant covering `*/*` — disallowed inside a
/// permission set (blob wildcard grants must always be requested explicitly).
fn is_blob_wildcard(entry: &PermissionEntry) -> bool {
    matches!(entry, PermissionEntry::Blob { accept } if accept.iter().any(|a| a == "*/*"))
}

/// Build a one-off HTTP client hardened for fetching from a caller-influenced Lexicon
/// authority endpoint — the NSID (and therefore the authority) comes from the client's
/// requested scope string. Delegates to the shared `identity_resolution::build_pinned_client`,
/// the same hardening `routes::service_proxy::build_header_proxy_client` uses for its own
/// caller-controlled target.
fn build_fetch_client(
    pinned: Option<&identity_resolution::PinnedResolution>,
) -> Result<reqwest::Client, String> {
    identity_resolution::build_pinned_client(pinned).map_err(|e| {
        tracing::error!(error = %e, "failed to build permission-set fetch client");
        "failed to prepare the permission-set fetch".to_string()
    })
}

#[derive(Deserialize)]
struct GetRecordResponse {
    value: Value,
}

/// Fetch `nsid`'s Lexicon schema record from `authority`'s PDS via `com.atproto.repo.getRecord`.
async fn fetch_lexicon_schema(authority: &AuthorityEndpoint, nsid: &str) -> Result<Value, String> {
    let client = build_fetch_client(authority.pinned.as_ref())?;
    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
        authority.url.trim_end_matches('/'),
        urlencoding::encode(&authority.did),
        urlencoding::encode(LEXICON_SCHEMA_COLLECTION),
        urlencoding::encode(nsid),
    );

    let response = client.get(&url).send().await.map_err(|e| {
        tracing::warn!(error = %e, nsid, "failed to fetch Lexicon schema record");
        format!("could not fetch the Lexicon record for \"{nsid}\"")
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "\"{nsid}\" could not be fetched (HTTP {})",
            response.status()
        ));
    }

    let body: GetRecordResponse = response.json().await.map_err(|e| {
        tracing::warn!(error = %e, nsid, "Lexicon schema response was not valid JSON");
        format!("\"{nsid}\"'s Lexicon record response was malformed")
    })?;

    Ok(body.value)
}

/// Resolve and expand a single `include:<nsid>` reference into its constituent canonical
/// granular scope tokens. `include_aud` is the `include:` token's own `?aud=` param, if any.
///
/// Fails closed: any resolution, fetch, parse, or validation failure rejects the whole
/// permission set rather than dropping just the offending entry.
pub(crate) async fn resolve_permission_set(
    state: &AppState,
    nsid: &str,
    include_aud: Option<&str>,
) -> Result<Vec<String>, String> {
    let authority = resolve_authority_endpoint(state, nsid).await?;
    let record = fetch_lexicon_schema(&authority, nsid).await?;
    let doc: std::collections::HashMap<String, PermissionSetDef> = record
        .get("defs")
        .cloned()
        .ok_or_else(|| format!("\"{nsid}\" has no \"defs\""))
        .and_then(|defs| {
            serde_json::from_value(defs)
                .map_err(|e| format!("\"{nsid}\"'s permission definitions are malformed: {e}"))
        })?;

    let main = doc
        .get("main")
        .ok_or_else(|| format!("\"{nsid}\" has no \"main\" definition"))?;
    if main.type_ != "permission-set" {
        return Err(format!("\"{nsid}\" is not a permission-set Lexicon"));
    }
    if main.permissions.iter().any(is_blob_wildcard) {
        return Err(format!(
            "\"{nsid}\" contains a blob:*/* grant, which permission sets may not include"
        ));
    }

    main.permissions
        .iter()
        .map(|entry| {
            let raw = render_permission_entry(entry, include_aud);
            normalize_token(&raw)
                .ok_or_else(|| format!("\"{nsid}\" contains an invalid permission entry"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use crate::app::{test_state, AppState};
    use crate::db::dids::seed_did_document;
    use crate::dns::{DnsError, TxtResolver};

    use super::*;

    // ── nsid_authority_domain ────────────────────────────────────────────────

    #[test]
    fn reverses_authority_segments_into_a_domain() {
        assert_eq!(
            nsid_authority_domain("app.bsky.authFull").as_deref(),
            Some("bsky.app")
        );
        assert_eq!(
            nsid_authority_domain("com.example.foo.bar").as_deref(),
            Some("foo.example.com")
        );
    }

    #[test]
    fn rejects_nsids_without_enough_segments() {
        assert_eq!(nsid_authority_domain("foo"), None);
        assert_eq!(nsid_authority_domain("foo.bar"), None);
        assert_eq!(nsid_authority_domain("foo..bar"), None);
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    struct FixedTxtResolver {
        records: Vec<String>,
    }

    impl TxtResolver for FixedTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            let records = self.records.clone();
            Box::pin(async move { Ok(records) })
        }
    }

    struct ErrTxtResolver;

    impl TxtResolver for ErrTxtResolver {
        fn txt_lookup<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsError>> + Send + 'a>> {
            Box::pin(async move { Err(DnsError("connection refused".to_string())) })
        }
    }

    fn state_with_dns(state: AppState, records: Vec<String>) -> AppState {
        AppState {
            txt_resolver: Some(Arc::new(FixedTxtResolver { records })),
            ..state
        }
    }

    const AUTHORITY_DID: &str = "did:plc:authoritydidxxxxxxxxxxxxx";

    fn pds_doc(endpoint: &str) -> serde_json::Value {
        serde_json::json!({
            "id": AUTHORITY_DID,
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": endpoint,
            }],
        })
    }

    // ── resolve_authority_endpoint: AC1.1-1.4 ───────────────────────────────

    #[tokio::test]
    async fn ac1_1_resolves_nsid_to_a_validated_service_endpoint() {
        // An IP literal (rather than a domain) so `validate_proxy_endpoint` doesn't need to
        // perform a live DNS resolution in this test — same convention as
        // identity_resolution.rs's own SSRF tests.
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc("http://93.184.216.34")).await;

        let resolved = resolve_authority_endpoint(&state, "app.bsky.authFull")
            .await
            .expect("should resolve");
        assert_eq!(resolved.url, "http://93.184.216.34");
    }

    #[tokio::test]
    async fn ac1_2_missing_txt_record_fails_resolution() {
        let state = state_with_dns(test_state().await, vec![]);
        let err = resolve_authority_endpoint(&state, "app.bsky.authFull")
            .await
            .unwrap_err();
        assert!(err.contains("no Lexicon authority"), "got: {err}");
    }

    #[tokio::test]
    async fn ac1_2_dns_transport_error_fails_resolution() {
        let state = AppState {
            txt_resolver: Some(Arc::new(ErrTxtResolver)),
            ..test_state().await
        };
        assert!(resolve_authority_endpoint(&state, "app.bsky.authFull")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ac1_3_did_document_with_no_matching_service_fails_resolution() {
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(
            &state.db,
            AUTHORITY_DID,
            serde_json::json!({ "id": AUTHORITY_DID, "service": [] }),
        )
        .await;

        let err = resolve_authority_endpoint(&state, "app.bsky.authFull")
            .await
            .unwrap_err();
        assert!(err.contains("does not advertise"), "got: {err}");
    }

    #[tokio::test]
    async fn ac1_4_endpoint_pointing_at_metadata_address_is_rejected() {
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc("http://169.254.169.254")).await;

        let err = resolve_authority_endpoint(&state, "app.bsky.authFull")
            .await
            .unwrap_err();
        assert!(err.contains("not a usable public address"), "got: {err}");
    }

    #[tokio::test]
    async fn invalid_nsid_fails_before_any_lookup() {
        let state = test_state().await;
        let err = resolve_authority_endpoint(&state, "notanauthority")
            .await
            .unwrap_err();
        assert!(err.contains("not a valid NSID"), "got: {err}");
    }

    // ── resolve_permission_set: AC2.1-2.5 ───────────────────────────────────

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Mount a mock authority: seeds the DID document pointing at `server`, and mounts a
    /// `getRecord` response serving `schema` for `nsid`.
    async fn state_with_mock_authority(
        server: &MockServer,
        nsid: &str,
        schema: serde_json::Value,
    ) -> AppState {
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc(&server.uri())).await;

        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .and(query_param("repo", AUTHORITY_DID))
            .and(query_param("collection", "com.atproto.lexicon.schema"))
            .and(query_param("rkey", nsid))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": format!("at://{AUTHORITY_DID}/com.atproto.lexicon.schema/{nsid}"),
                "cid": "bafyreictest",
                "value": schema,
            })))
            .mount(server)
            .await;

        state
    }

    fn permission_set_schema(nsid: &str, permissions: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "lexicon": 1,
            "id": nsid,
            "defs": {
                "main": {
                    "type": "permission-set",
                    "permissions": permissions,
                }
            }
        })
    }

    #[tokio::test]
    async fn ac2_1_well_formed_record_expands_to_canonical_scopes() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([
                { "type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"], "action": ["create"] },
                { "type": "permission", "resource": "identity", "attr": "handle" },
            ]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;

        let mut tokens = resolve_permission_set(&state, nsid, None)
            .await
            .expect("should expand");
        tokens.sort();
        assert_eq!(
            tokens,
            vec![
                "identity:handle".to_string(),
                "repo:app.bsky.feed.post?action=create".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn ac2_2_malformed_record_fails_closed() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        // "defs" is a string, not an object — fails to deserialize.
        let schema = serde_json::json!({ "lexicon": 1, "id": nsid, "defs": "not an object" });
        let state = state_with_mock_authority(&server, nsid, schema).await;

        let err = resolve_permission_set(&state, nsid, None)
            .await
            .unwrap_err();
        assert!(err.contains("malformed"), "got: {err}");
    }

    #[tokio::test]
    async fn ac2_3_blob_wildcard_entry_fails_closed() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([
                { "type": "permission", "resource": "blob", "accept": ["*/*"] },
            ]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;

        let err = resolve_permission_set(&state, nsid, None)
            .await
            .unwrap_err();
        assert!(err.contains("blob:*/*"), "got: {err}");
    }

    #[tokio::test]
    async fn ac2_4_inherit_aud_takes_audience_from_include_token() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([
                { "type": "permission", "resource": "rpc", "lxm": ["app.bsky.feed.getTimeline"], "inheritAud": true },
            ]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;

        let tokens = resolve_permission_set(&state, nsid, Some("did:web:api.bsky.app"))
            .await
            .expect("should expand");
        assert_eq!(
            tokens,
            vec!["rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app".to_string()]
        );
    }

    #[tokio::test]
    async fn ac2_5_inherit_aud_with_no_audience_available_fails_closed() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([
                { "type": "permission", "resource": "rpc", "lxm": ["app.bsky.feed.getTimeline"], "inheritAud": true },
            ]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;

        // No include_aud supplied, and the entry has no literal aud either.
        let err = resolve_permission_set(&state, nsid, None)
            .await
            .unwrap_err();
        assert!(err.contains("invalid permission entry"), "got: {err}");
    }

    // ── resolve_permission_set_cached: AC3.1-3.3 ────────────────────────────

    #[tokio::test]
    async fn ac3_1_cache_hit_within_ttl_skips_resolution() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([{ "type": "permission", "resource": "identity", "attr": "handle" }]),
        );
        let state = state_with_dns(test_state().await, vec![format!("did={AUTHORITY_DID}")]);
        seed_did_document(&state.db, AUTHORITY_DID, pds_doc(&server.uri())).await;

        // Exactly one fetch is expected — wiremock panics on drop if the count is wrong.
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.getRecord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uri": format!("at://{AUTHORITY_DID}/com.atproto.lexicon.schema/{nsid}"),
                "cid": "bafyreictest",
                "value": schema,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = new_permission_set_cache();
        let first = resolve_permission_set_cached(&state, &cache, nsid, None)
            .await
            .expect("first resolution should succeed");
        let second = resolve_permission_set_cached(&state, &cache, nsid, None)
            .await
            .expect("second call should be served from cache");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn ac3_2_expired_entry_triggers_fresh_resolution() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([{ "type": "permission", "resource": "identity", "attr": "handle" }]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;

        let cache = new_permission_set_cache();
        // Manually seed an already-expired cache entry so the lookup must fall through to a
        // fresh resolution rather than serving stale data indefinitely.
        {
            let mut map = cache.lock().await;
            let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            map.insert(
                cache_key(nsid, None),
                CacheEntry::Resolved {
                    scopes: vec!["stale:token".to_string()],
                    expires_at: past,
                },
            );
        }

        let resolved = resolve_permission_set_cached(&state, &cache, nsid, None)
            .await
            .expect("should re-resolve past expiry");
        assert_eq!(resolved, vec!["identity:handle".to_string()]);
    }

    #[tokio::test]
    async fn ac3_3_failed_resolution_is_negatively_cached() {
        // No DNS resolver configured at all — resolution fails immediately, before any
        // network fetch, so a second call within the negative-TTL window must return the
        // same cached failure without attempting resolution again.
        let state = test_state().await;
        let cache = new_permission_set_cache();
        let nsid = "app.bsky.authFull";

        let first = resolve_permission_set_cached(&state, &cache, nsid, None)
            .await
            .unwrap_err();
        let second = resolve_permission_set_cached(&state, &cache, nsid, None)
            .await
            .unwrap_err();
        assert!(first.contains("DNS resolution is not configured"));
        assert!(second.contains("cached failure"), "got: {second}");
    }

    // ── expand_include_scopes ────────────────────────────────────────────────

    #[tokio::test]
    async fn expands_include_token_alongside_literal_tokens() {
        let server = MockServer::start().await;
        let nsid = "app.bsky.authFull";
        let schema = permission_set_schema(
            nsid,
            serde_json::json!([{ "type": "permission", "resource": "identity", "attr": "handle" }]),
        );
        let state = state_with_mock_authority(&server, nsid, schema).await;
        let cache = new_permission_set_cache();

        let expanded = expand_include_scopes(&state, &cache, &format!("atproto include:{nsid}"))
            .await
            .expect("should expand");
        assert_eq!(expanded, "atproto identity:handle");
    }

    #[tokio::test]
    async fn legacy_scope_with_no_include_token_passes_through_unchanged() {
        let state = test_state().await;
        let cache = new_permission_set_cache();
        let expanded = expand_include_scopes(&state, &cache, "atproto transition:generic")
            .await
            .expect("should pass through");
        assert_eq!(expanded, "atproto transition:generic");
    }

    #[tokio::test]
    async fn rejects_scope_with_too_many_include_tokens_before_resolving_any() {
        // No txt_resolver configured — if any resolution were attempted, this would fail with a
        // different (DNS-related) error message. The cap must reject before that point.
        let state = test_state().await;
        let cache = new_permission_set_cache();
        let scope = format!(
            "atproto {}",
            (0..MAX_INCLUDE_TOKENS_PER_REQUEST + 1)
                .map(|i| format!("include:app.bsky.set{i}.perm"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let err = expand_include_scopes(&state, &cache, &scope)
            .await
            .unwrap_err();
        assert!(err.contains("too many"), "got: {err}");
    }
}
