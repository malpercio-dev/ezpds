# OAuth Granular Scopes — Permission Sets, Consent UI, Metadata — Design

Linear: [MM-237](https://linear.app/malpercio/issue/MM-237) (Wave 7: Hardening)

## Summary

This design closes the final gap in ezpds's granular OAuth scopes work: today, a client can request an `include:<nsid>` scope token (a reference to a reusable "permission set" published as a Lexicon record) and the existing parser accepts its syntax, but nothing actually resolves it — it passes through unexpanded. This design adds that resolution step end-to-end, using the same identifier-to-network-endpoint resolution machinery the PDS already relies on for handles and DIDs: reverse the NSID into a domain, look up its publishing authority via DNS, follow that to a DID document and a validated service endpoint, then fetch and parse the permission-set record over XRPC. The result is expanded into the same canonical granular-scope strings the rest of the OAuth stack already understands, cached in memory to avoid repeat network round-trips, and treated as fail-closed at every step — any resolution failure rejects the whole authorization request rather than silently granting a smaller set of permissions than what was asked for.

Two smaller, independent pieces round out the ticket alongside resolution. First, the consent screen is upgraded from a flat list of raw scope strings to permissions grouped by resource type, with checkboxes so a user can deny individual permissions before approving — the reduced, user-approved set (not the originally requested one) is what actually gets stored on the issued token. Second, the two OAuth metadata endpoints stop hardcoding a two-scope list and instead advertise the real, now much larger, supported scope grammar. Legacy clients that only ever request the original `atproto`/`transition:generic` scopes are unaffected by any of this — the new resolution and UI logic only activates when an `include:` token is actually present.

## Definition of Done

- A client requesting `include:<nsid>` (e.g. `include:app.bsky.authFull?aud=...`) has it resolved via the real Lexicon-publishing protocol (DNS TXT authority → DID document → XRPC fetch) and expanded to its constituent granular scopes before an authorization code is issued.
- An unresolvable, malformed, or disallowed (e.g. embedded `blob:*/*`) permission-set reference fails the whole authorization request the same way a malformed scope token does today (`invalid_scope`) — never a partial grant.
- The consent screen groups requested permissions by resource/permission-set instead of a flat list of raw scope tags, showing the *expanded* form of any `include:` reference.
- The user can uncheck individual permissions before approving; the reduced set — not the originally requested set — is what gets granted and stored on the issued token.
- `scopes_supported` in both `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource` reflects the real supported grammar, not the hardcoded two-element list.
- Legacy clients requesting only `atproto`/`transition:generic` continue to work unchanged.

## Acceptance Criteria

### oauth-scopes-permission-sets.AC1: NSID authority resolves to a validated PDS service endpoint
- **oauth-scopes-permission-sets.AC1.1 Success:** An NSID with a valid `_lexicon.<domain>` TXT record resolves to its authority DID, which resolves to a DID document containing a matching PDS service endpoint.
- **oauth-scopes-permission-sets.AC1.2 Failure:** An NSID whose authority domain has no `_lexicon.<domain>` TXT record fails resolution (treated as unresolvable, not a crash).
- **oauth-scopes-permission-sets.AC1.3 Failure:** An authority DID whose document has no service entry matching the expected PDS service ID fails resolution.
- **oauth-scopes-permission-sets.AC1.4 Failure:** An authority DID document advertising a loopback, private, link-local, or cloud-metadata service endpoint is rejected before any fetch is attempted (SSRF guard).

### oauth-scopes-permission-sets.AC2: Permission-set records expand to canonical granular scopes
- **oauth-scopes-permission-sets.AC2.1 Success:** A well-formed permission-set record with `repo`/`rpc`/`blob`/`account`/`identity` entries expands to the exact canonical scope string those entries represent.
- **oauth-scopes-permission-sets.AC2.2 Failure:** A permission-set record that fails to deserialize (malformed/unexpected JSON shape) fails resolution.
- **oauth-scopes-permission-sets.AC2.3 Failure:** A permission-set record containing a `blob:*/*`-equivalent entry fails resolution.
- **oauth-scopes-permission-sets.AC2.4 Success:** An `rpc` permission entry marked `inheritAud: true` receives the audience supplied by the `include:` token's own `?aud=` parameter when expanded.
- **oauth-scopes-permission-sets.AC2.5 Failure:** An `rpc` permission entry marked `inheritAud: true` with no `aud` available (neither a literal one on the entry nor one supplied on the `include:` token) fails resolution.

### oauth-scopes-permission-sets.AC3: Resolved permission sets are cached
- **oauth-scopes-permission-sets.AC3.1 Success:** A second request for the same `include:` token within the positive TTL window returns the cached result with no additional network calls.
- **oauth-scopes-permission-sets.AC3.2 Edge:** A cached entry past its TTL triggers a fresh resolution rather than being served stale indefinitely.
- **oauth-scopes-permission-sets.AC3.3 Success:** A failed resolution is negatively cached for 60s, so an immediately-repeated request against the same broken authority doesn't re-trigger the full resolution chain.

### oauth-scopes-permission-sets.AC4: `include:` scopes are expanded end-to-end in the authorization flow
- **oauth-scopes-permission-sets.AC4.1 Success:** A `POST /oauth/authorize` approval carrying an `include:<nsid>` scope stores an authorization code whose `scope` column holds the fully expanded granular scopes, not the raw `include:` token.
- **oauth-scopes-permission-sets.AC4.2 Failure:** A `POST /oauth/authorize` approval whose `include:` token cannot be resolved redirects with `error=invalid_scope`, before any credential check runs.
- **oauth-scopes-permission-sets.AC4.3 Success:** `GET /oauth/authorize` renders the expanded form of a resolvable `include:` token on the consent page.

### oauth-scopes-permission-sets.AC5: Consent screen supports grouped display and per-scope opt-out
- **oauth-scopes-permission-sets.AC5.1 Success:** The consent page renders requested permissions grouped by resource type, not as a flat list of raw scope strings.
- **oauth-scopes-permission-sets.AC5.2 Success:** Unchecking one permission before submitting approval results in a granted/stored scope that excludes exactly that permission.
- **oauth-scopes-permission-sets.AC5.3 Failure:** The `atproto` base permission cannot be unchecked/removed via the consent form.

### oauth-scopes-permission-sets.AC6: Metadata reflects the real scope surface
- **oauth-scopes-permission-sets.AC6.1 Success:** `GET /.well-known/oauth-authorization-server`'s `scopes_supported` reflects the real supported grammar, not the hardcoded two-element list.
- **oauth-scopes-permission-sets.AC6.2 Success:** `GET /.well-known/oauth-protected-resource`'s `scopes_supported` reflects the same.

### oauth-scopes-permission-sets.AC7: Cross-cutting / backward compatibility
- **oauth-scopes-permission-sets.AC7.1 Success:** A legacy client requesting only `atproto transition:generic` (no `include:` tokens) completes the authorization flow exactly as it does today, with no behavior change.

## Glossary

- **NSID (Namespaced Identifier)**: The dotted, reverse-domain-style identifier AT Protocol uses to name Lexicon schemas (e.g., `app.bsky.authFull`). Its leading segments, reversed, indicate the domain of the entity that published/authorizes it.
- **Lexicon**: AT Protocol's schema definition language/format, used here to define both API methods and the "permission set" records this design resolves.
- **Permission set**: A Lexicon-published record that bundles multiple granular OAuth permissions (e.g., specific repo/rpc/blob/account/identity access) under a single reusable reference, so a client can request one `include:<nsid>` token instead of enumerating every granular scope.
- **`include:` scope token**: The OAuth scope syntax (`include:<nsid>[?aud=...]`) a client uses to request a permission set by reference rather than listing its expanded scopes directly.
- **Granular scope**: The fully expanded, individually-enforceable OAuth scope form (e.g., a specific repo/rpc/blob permission string) that `oauth_scopes.rs` already validates and enforces at runtime.
- **DID (Decentralized Identifier)**: AT Protocol's persistent identifier for an account or authority, resolvable to a DID document.
- **DID document**: The document a DID resolves to, listing (among other things) service endpoints — used here to find the authority's PDS.
- **PDS (Personal Data Server)**: The server that hosts an account's (or, in this design, a Lexicon authority's) repository and serves its API; ezpds is itself a PDS implementation.
- **Service endpoint**: A URL published in a DID document identifying where a particular service (here, a PDS) can be reached.
- **`_lexicon.<domain>` TXT record**: A DNS TXT record convention (analogous to `_atproto.<handle>`) used to look up the DID that authors/publishes Lexicons under a given domain.
- **XRPC**: AT Protocol's RPC-over-HTTP convention for calling named Lexicon methods (e.g., `com.atproto.repo.getRecord`, used here to fetch the permission-set record).
- **`com.atproto.repo.getRecord`**: The standard AT Protocol XRPC method for fetching a single record from a repository by collection/rkey — used here to fetch the permission-set's Lexicon record from the resolved PDS.
- **SSRF (Server-Side Request Forgery) guard**: A defensive check (`validate_proxy_endpoint`) that rejects resolved network targets pointing at loopback, private, link-local, or cloud-metadata addresses before the server fetches them — necessary here because the fetch target is derived from attacker-controlled input (the client's requested scope string).
- **`atproto` / `transition:generic` scopes**: The two original, coarse-grained OAuth scopes ezpds supported before granular scopes existed; retained for backward compatibility.
- **DPoP (Demonstrating Proof-of-Possession)**: An OAuth extension binding tokens to a client-held key; referenced here only as the existing module (`auth/dpop.rs`) whose in-memory TTL cache pattern this design reuses, not because DPoP itself is part of this feature.
- **`scopes_supported`**: A field in OAuth server/resource metadata documents listing which scopes the server accepts — currently hardcoded, and updated by this design to reflect the real grammar.
- **`/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`**: The two standard OAuth metadata discovery endpoints this design updates.
- **Fail-closed**: A design principle where any ambiguity or error in a security-relevant decision results in denial/rejection rather than a partial or best-effort success — applied here so a partially-resolvable `include:` token rejects the whole request rather than silently granting less than requested.
- **Functional Core / Imperative Shell**: The architectural pattern separating pure business logic from side-effecting I/O; referenced here to explain why the new `permission_sets.rs` module is tagged "Mixed (unavoidable)" rather than a pure core.
- **TTL (Time-To-Live) cache**: A cache that expires entries after a fixed duration; this design uses one to avoid re-resolving the same permission set on every authorization request.

## Architecture

This is the third and final leg of ezpds's granular OAuth auth-scopes work. Legs 1–2 (MM-235/MM-236, merged) built the scope grammar parser/normalizer and runtime enforcement in `crates/pds/src/auth/oauth_scopes.rs`. That module already validates `include:<nsid>` syntax but passes it through unexpanded — this design adds the missing resolution step, plus the two independent pieces that round out MM-237: consent-screen presentation and metadata advertisement.

**Permission-set resolution — new module `crates/pds/src/auth/permission_sets.rs`** (pattern `Mixed (unavoidable)`, matching `auth/dpop.rs` — real network I/O, so it can't be a pure Functional Core despite living in `auth/`). Public entry point:

```rust
pub async fn expand_include_scopes(
    state: &AppState,
    scope: &str,
) -> Result<String, PermissionSetError>
```

Takes an already-normalized scope string, replaces every `include:<nsid>[?aud=...]` token with its resolved granular scopes, re-normalizes the result, and leaves every other token untouched.

Resolution chain per `include:` token, reusing existing identity-resolution primitives rather than duplicating them:

1. **NSID → authority domain**: reverse the NSID's authority segments (`app.bsky.authFull` → authority `app.bsky` → domain `bsky.app`).
2. **Authority DID**: `state.txt_resolver.txt_lookup("_lexicon.<domain>")`, parsing the first `did=<did>` value — same shape as `identity_resolution::resolve_handle_to_did`'s `_atproto.<handle>` lookup. No `TxtResolver` trait changes.
3. **DID → DID document**: `identity_resolution::resolve_did_document(state, &authority_did)`, reused unmodified.
4. **Service endpoint**: extract the PDS `serviceEndpoint` from the document's `service` array, same lookup shape as `resolve_atproto_proxy_target`.
5. **SSRF guard**: the resolved endpoint is attacker-influenced (the NSID comes from the client's requested scope string), so it goes through `identity_resolution::validate_proxy_endpoint` before any fetch — the same guard the moderation-proxy branch uses for its caller-supplied target.
6. **XRPC fetch**: `com.atproto.repo.getRecord` against that (pinned) endpoint via `state.http_client`, with `collection: "com.atproto.lexicon.schema"` and `rkey: <nsid>` — the confirmed convention for fetching a Lexicon schema record once its authority is known.

**Permission-set parsing & expansion.** The fetched record's `defs.main.permissions[]` array is walked; each entry (`resource: repo/rpc/blob/account/identity` + its fields) is rendered into the same canonical scope-string form `oauth_scopes.rs::format_scope` already produces, then the reconstructed set is fed back through `normalize_scope_request` for validation — reusing existing grammar code rather than re-deriving it. An `rpc` entry marked `inheritAud: true` takes its `aud` from the `include:` token's own `?aud=` parameter rather than a literal value on the entry (confirmed: `include:` composition, not a JSON field, is how atproto expresses nesting — there is no separate "nested permission set" shape to recurse into). One fail-closed rule on the whole resolved set (not per-entry skip): a `blob:*/*`-equivalent entry is invalid inside a permission set (per spec) and rejects the set.

**Caching.** In-memory only, held in `AppState`, shaped like the DPoP nonce store (`auth/dpop.rs`): `Mutex<HashMap<String, CacheEntry>>` keyed on the full `include:` token (NSID + `aud`), where `CacheEntry` is `Resolved { scopes, resolved_at }` or `Failed { failed_at }`. TTL policy follows the finalized spec: serve a `Resolved` entry for up to 24h before re-resolving; hard-expire at 90 days; never resolve more often than an access token's lifetime requires. A `Failed` entry is cached for 60s to absorb repeated submissions against a broken authority without hammering it. No background refresh task — resolution happens synchronously inline in the request path, matching how DID/PLC-directory resolution already works inline in this same request.

**Integration — `crates/pds/src/routes/oauth_authorize.rs`.** `expand_include_scopes` is called in two places: on `GET` (render-only, so the consent screen shows real expanded permissions instead of an opaque `include:` reference) and on `POST` (authoritative — hidden form fields are attacker-controllable, so this must re-run regardless of what the GET already showed), immediately after the existing `normalize_scope_request` call and before `store_authorization_code`. Any `PermissionSetError` on the `POST` path redirects with `error=invalid_scope`, identical to the existing malformed-token path. `oauth_authorization_codes.scope` therefore always holds a fully expanded, flat, ready-to-enforce string — `oauth_token.rs` and `oauth_scopes.rs`'s `allows_*` functions require no changes.

**Consent UI — `crates/pds/src/routes/oauth_templates.rs`.** `render_consent_page`'s flat `scope_tags` list is replaced with permissions grouped by resource type (repo/rpc/blob/account/identity/transition), each rendered as a labeled checkbox (checked by default) rather than a static tag. The POST form now submits the user-selected subset; `post_authorization` builds the granted scope string from exactly the checked boxes (still always including `atproto`, which cannot be unchecked) before running it through the same normalize → expand → store pipeline.

**Metadata — `oauth_server_metadata.rs` / `oauth_protected_resource.rs`.** The hardcoded `vec!["atproto", "transition:generic"]` is replaced with the real supported-scope surface (the five resource-type prefixes, `include:`, and the four fixed/transition scopes), described declaratively rather than enumerated per concrete scope value (an unbounded space).

## Existing Patterns

- **Three-tier resolution chain.** `identity_resolution::resolve_handle_to_did` (local DB → DNS TXT → HTTP well-known) is the direct template for the NSID authority lookup — same DNS-TXT-with-`did=`-prefix parsing, same "log and fall through" treatment of infrastructure errors.
- **DID/service-endpoint resolution reused verbatim.** `resolve_did_document` and the service-array lookup pattern in `resolve_atproto_proxy_target` need no changes — permission-set resolution is a new caller, not a new resolution mechanism.
- **SSRF guard reused verbatim.** `validate_proxy_endpoint` (rejects loopback/private/link-local/cloud-metadata addresses, pins the resolved IP) already exists precisely because the moderation-proxy branch faces the same "attacker names the resolution target" shape this design has.
- **In-memory TTL cache.** `auth/dpop.rs`'s nonce store (`Mutex<HashMap<String, Instant>>`, lazy cleanup) is the template for the permission-set cache — ephemeral, restart-safe-by-recomputation, no migration.
- **Shared HTTP client.** `AppState.http_client` (10s timeout, already used by `identity_resolution.rs` for plc.directory/did:web fetches) is reused for the permission-set XRPC fetch — no new client construction.
- **Canonical scope formatting reused.** `oauth_scopes.rs::format_scope`/`normalize_scope_request` are called, not reimplemented, so a permission-set expansion can never diverge from what a client-supplied granular scope would normalize to.

No divergences from existing patterns — every load-bearing piece of this design composes primitives that already exist for a structurally identical problem (resolve an attacker-influenced identifier to a network endpoint, fetch, cache with TTL).

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: `scopes_supported` metadata advertisement
**Goal:** Both metadata documents advertise the real supported scope grammar instead of the hardcoded two-element list.

**Components:**
- `crates/pds/src/routes/oauth_server_metadata.rs` — replace the hardcoded `scopes_supported` vec.
- `crates/pds/src/routes/oauth_protected_resource.rs` — same.

**Dependencies:** None (first phase; independent of the rest of this design).

**Done when:** Existing `scopes_supported_are_atproto_scopes` tests in both files are updated and pass; `oauth-scopes-permission-sets.AC6.1`, `AC6.2`.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Lexicon authority + DID resolution chain
**Goal:** Given an NSID, resolve the publishing authority's DID, its DID document, and a validated/pinned PDS service endpoint — with no permission-set-specific logic yet.

**Components:**
- `crates/pds/src/auth/permission_sets.rs` (new) — NSID-to-domain reversal, `_lexicon.<domain>` TXT lookup via the existing `TxtResolver` trait, and orchestration calling `identity_resolution::resolve_did_document` + the service-endpoint extraction + `validate_proxy_endpoint`.

**Dependencies:** None (uses only existing `identity_resolution.rs`/`dns.rs` primitives).

**Done when:** Unit tests (mocked `TxtResolver`) pass for: successful authority resolution to a service endpoint; missing TXT record; DID document with no matching service; an endpoint pointing at a loopback/private/link-local address is rejected. `oauth-scopes-permission-sets.AC1.1`–`AC1.4`.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Permission-set fetch, parsing, and expansion
**Goal:** Fetch the resolved endpoint's Lexicon schema record and expand it into a canonical granular-scope string.

**Components:**
- `crates/pds/src/auth/permission_sets.rs` — XRPC `com.atproto.repo.getRecord` fetch via `state.http_client` (`collection: "com.atproto.lexicon.schema"`, `rkey: <nsid>`); schema deserialization (`defs.main.permissions[]`); per-entry rendering via `oauth_scopes::format_scope`; `inheritAud` handling for `rpc` entries (audience comes from the `include:` token's `?aud=`, not a literal on the entry); whole-set validation via `oauth_scopes::normalize_scope_request`; `blob:*/*` rejection.

**Dependencies:** Phase 2 (resolution chain).

**Done when:** Unit tests pass for: a well-formed permission-set record expands to the expected canonical scope string; malformed/unparseable schema JSON fails closed; a `blob:*/*` entry fails closed; an `inheritAud` entry correctly takes its audience from the `include:` token; an `inheritAud` entry with no audience available fails closed. `oauth-scopes-permission-sets.AC2.1`–`AC2.5`.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: TTL cache
**Goal:** Avoid re-resolving the same permission set on every authorization request within its validity window.

**Components:**
- `crates/pds/src/auth/permission_sets.rs::PermissionSetCache` — `Mutex<HashMap<String, CacheEntry>>`, added to `AppState`; positive TTL (24h stale-refresh boundary, 90-day hard expiry) and negative TTL (60s) per the design's TTL policy.
- `expand_include_scopes` becomes the cache-checking public entry point wrapping Phases 2–3's resolution.

**Dependencies:** Phase 3.

**Done when:** Unit tests pass for: a cache hit within TTL skips resolution (verifiable via a resolver call-count assertion); an expired entry triggers re-resolution; a failed resolution is negatively cached for the shorter window. `oauth-scopes-permission-sets.AC3.1`–`AC3.3`.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: `oauth_authorize.rs` integration
**Goal:** Wire expansion into both the consent-rendering (`GET`) and authoritative (`POST`) paths, with fail-closed error handling.

**Components:**
- `crates/pds/src/routes/oauth_authorize.rs::get_authorization` — call `expand_include_scopes` for rendering only; on failure, render with the original (unexpanded) scope rather than blocking the page (the `POST` remains authoritative).
- `crates/pds/src/routes/oauth_authorize.rs::post_authorization` — call `expand_include_scopes` immediately after `normalize_scope_request`; on `Err`, redirect with `error=invalid_scope` before any credential check; on `Ok`, pass the expanded string to `store_authorization_code` in place of the raw normalized one.

**Dependencies:** Phase 4.

**Done when:** Integration tests (extending the existing `post_authorize`/`get_authorize` suite, mocked resolver) pass for: an `include:` request issues a code whose stored `scope` is the expanded set; an unresolvable `include:` redirects with `error=invalid_scope`; a legacy `atproto`/`transition:generic`-only request is unaffected. `oauth-scopes-permission-sets.AC4.1`–`AC4.3`, `AC7.1`.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Consent UI grouping and per-scope opt-out
**Goal:** Replace the flat scope-tag list with grouped, checkbox-based permissions the user can selectively deny.

**Components:**
- `crates/pds/src/routes/oauth_templates.rs::render_consent_page` — group the (expanded) scope tokens by resource type; render each as a checked-by-default checkbox instead of a static tag; `atproto` renders unconditionally without a checkbox (cannot be denied).
- `crates/pds/src/routes/oauth_authorize.rs::post_authorization` — build the granted scope from the submitted checked boxes (plus mandatory `atproto`) instead of trusting `form.scope` verbatim, then run that reduced set through the same normalize → expand → store pipeline.

**Dependencies:** Phase 5 (needs the expanded form to group/render).

**Done when:** Integration tests pass for: the consent page renders permissions grouped by resource type; unchecking a permission before submitting yields a token/stored scope without it; `atproto` cannot be removed. `oauth-scopes-permission-sets.AC5.1`–`AC5.3`.
<!-- END_PHASE_6 -->

## Additional Considerations

**Fail-closed is set-wide, not entry-wide.** Every failure mode in resolution, fetch, or parsing rejects the *entire* `include:` reference (and therefore the whole authorization request, since `normalize_scope_request` already requires all tokens to be valid) rather than silently dropping just the unresolvable piece. This matches the existing malformed-token behavior and avoids ever granting a smaller-than-requested permission set without the user knowing.

**Correction from initial design (2026-07-05): no nested `include:` recursion.** The original design assumed a permission-set record could contain a nested `include:`-type entry and proposed a depth-capped recursive resolver for it. Verification against the finalized spec found this premise wrong: `include:` is exclusively a client-facing OAuth scope-string syntax, never a field inside a permission-set's own JSON. Composition instead happens via `inheritAud` on `rpc` entries, which take their audience from whatever `?aud=` the *including* scope token supplies rather than from a literal value baked into the set. This is a simplification, not a scope increase — there is no recursion to implement.

**Correction from code review (2026-07-06): GET-path expansion failure now redirects with an error instead of falling back to the raw token.** The original design let a GET-time resolution failure render the raw unexpanded `include:<nsid>` token rather than blocking the page, reasoning that `POST`'s authoritative re-expansion made this safe (narrowing-only, never over-granting). An external review (CodeRabbit) identified a real, if narrow, consequence of that fallback: if the failure is transient and clears before the user submits, `POST`'s authoritative expansion produces granular tokens that don't match the raw `include:<nsid>` checkbox value the page rendered, and the grant-reduction filter then silently drops everything from that permission set — a real desync between what the user saw/approved and what gets granted, not just a less-informative preview. `get_authorization` now redirects with `error=invalid_scope` on expansion failure instead of falling back, closing the desync class entirely at the cost of requiring a retry on a transient blip.
