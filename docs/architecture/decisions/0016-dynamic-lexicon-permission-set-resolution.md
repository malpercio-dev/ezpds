# ADR-0016: Dynamic Lexicon-based permission-set resolution, not a static scope table

- **Status:** Accepted
- **Date:** 2026-07-05
- **Deciders:** ezpds maintainers
- **Related:** [MM-237](https://linear.app/malpercio/issue/MM-237) · [docs/archive/design-plans/2026-07-05-oauth-scopes-permission-sets.md](../../archive/design-plans/2026-07-05-oauth-scopes-permission-sets.md)

## Context

ezpds's granular OAuth scopes support (`crates/pds/src/auth/oauth_scopes.rs`, MM-235/MM-236) already parses and enforces individual `repo:`/`rpc:`/`blob:`/`account:`/`identity:` scopes. The remaining piece is `include:<nsid>` — a reference to a reusable "permission set" (e.g. `include:app.bsky.authFull`) published as a Lexicon record elsewhere on the network, per atproto proposal 0011 and the now-finalized `atproto.com/specs/permission`.

Two ways to support `include:` exist. A static table hardcodes a handful of known NSIDs to their expanded scopes as Rust constants: no network dependency, ships immediately, but only covers sets we anticipate in advance and needs a code change and redeploy for every new one an authority publishes. The alternative is to resolve `include:` references live, following the real Lexicon-publishing protocol (DNS TXT `_lexicon.<domain>` → DID → DID document → XRPC fetch of the schema record).

This choice was initially deferred pending verification that the feature was real: an early research pass found only an August 2025 discussion calling permission sets "in progress, not finalized," which would have made building against it a bet on a moving target. A follow-up pass confirmed the spec is now finalized, `app.bsky.authFull` is live and resolvable via `did:web:api.bsky.app`, and the reference ecosystem expects the authorization server to do this resolution itself — settling the question.

## Decision

We resolve `include:<nsid>` scope references via the real atproto Lexicon-publishing protocol at authorization time — DNS TXT authority lookup, DID/DID-document resolution, and an XRPC fetch of the schema record — rather than a hardcoded table. Resolved sets are cached with a TTL (see the design plan) rather than re-resolved on every request.

## Consequences

- Any legitimately-published permission set works without a code change or redeploy, including ones that don't exist yet.
- OAuth consent approval (`POST /oauth/authorize`) now has a real, attacker-influenceable network dependency: DNS and HTTP reachability of a client-named authority. Resolution failures must fail closed (reject the whole authorization request), never grant a partial or best-guess set.
- New SSRF-relevant attack surface: the fetch target is derived from client-controlled input (the requested scope string's NSID). Mitigated by reusing the existing `validate_proxy_endpoint` guard (`identity_resolution.rs`), the same one protecting the moderation-proxy branch's caller-supplied target.
- We are now tracking an external, still-young spec. The resolution *mechanism* (DNS TXT + XRPC) is stable, but the permission-set record schema could still evolve; a schema change would require an ezpds update to keep resolving correctly.
- No dependency on plc.directory or DNS uptime for scopes clients don't use — resolution only runs when a request actually contains an `include:` token, so legacy and purely-granular clients are unaffected either way.

## Alternatives considered

- **Static known-set table.** Rejected: brittle (a code change + redeploy per new published set), and defeats the point of permission sets being independently publishable by any authority, not just ones ezpds anticipates.
- **Defer the whole leg.** Considered when the spec initially looked unfinished/unadopted (per the stale August 2025 research). Rejected once corrected research confirmed the spec is finalized and `app.bsky.authFull` is live in production — there is no longer a moving target to wait out.
