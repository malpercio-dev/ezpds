# ADR-0038: Hand-written XRPC methods over lexicon codegen

- **Status:** Accepted
- **Date:** 2026-09-06
- **Deciders:** ezpds maintainers
- **Related:** [`crates/custos-client/AGENTS.md`](../../../crates/custos-client/AGENTS.md)

## Context

`crates/custos-client` hand-writes its typed XRPC methods (`identity.rs`,
`app_passwords.rs`, `migration.rs`, and auth.md's own `agents.rs`) rather than
generating them from lexicon JSON. The workspace already depends on
`atrium-api` (via `repo-engine`), which ships codegen'd types for the
`com.atproto.*` lexicons, so adopting it here — instead of maintaining a
second, hand-written client surface — was investigated as this crate's
extraction wound down.

## Decision

Keep the typed methods hand-written. `atrium-api` was investigated and
rejected, for five independent reasons, any one of which would have been
enough on its own:

1. **Missing extension fields.** `atrium-api`'s generated types have no field
   for Custos's own lexicon extensions — `createAppPassword`'s
   `personalDetails`, `describeServer`'s `custos` capabilities block — because
   neither exists in the reference lexicons `atrium-codegen` generates from.
   Adopting it would mean losing those fields or forking the generated output
   to patch them back in: more ongoing maintenance than hand-writing, not
   less.
2. **Newtype ripple.** Its `Did`/`Handle` newtypes and `Object<T>` wrapper
   would ripple into `IdentityStore`/Keychain naming and Tauri IPC JSON
   wherever a value crosses that boundary, for no functional gain.
3. **Narrower error classification.** Its per-method `Error` enums cover only
   a lexicon's *named* errors — not a replacement for `PdsClientError`'s
   HTTP-status classification tail (429/401/other-non-2xx), which every
   caller in this crate depends on.
4. **No DPoP.** Its `XrpcClient`/`HttpClient` traits carry no RFC 9449 DPoP
   proof construction. `OAuthClient`'s DPoP/nonce-retry logic would stay
   exactly as hand-written as it is today regardless of which client library
   issues the request.
5. **No lexicon at all for a third of the surface.** auth.md's own endpoints
   (`agents.rs`) are not `com.atproto.*` XRPC and have no upstream lexicon —
   codegen could never reach `agents.rs`'s 9 methods (of the crate's 26 total
   typed methods across `identity.rs`/`app_passwords.rs`/`migration.rs`/
   `agents.rs`), so a codegen migration would still leave this crate
   maintaining a hand-written tier alongside a generated one.

A supporting, not independently decisive, observation: `git log` on the
hand-written XRPC methods shows churn from *new methods being added* over the
crate's history, not from an existing lexicon's shape drifting underneath
already-written code — the risk codegen exists to close has not been this
crate's actual failure mode so far.

**Trigger (the one signal that reopens this):** a third party ships a lexicon
whose shape drifts out from under a hand-written method here, causing a real
bug — i.e., codegen's actual risk case shows up in practice, not just in
theory. Reconsider per-lexicon (start with whichever endpoint broke), not as a
wholesale rewrite.

## Consequences

- `identity.rs`/`app_passwords.rs`/`migration.rs`/`agents.rs` keep their
  hand-written request/response types indefinitely; no new dependency on
  `atrium-api`'s XRPC layer.
- `crates/custos-client/AGENTS.md`'s Boundaries section points here for the
  full rationale instead of restating it.
- Reopening this later is scoped to the endpoint whose lexicon actually
  drifted, not a full-crate migration decision.

## Alternatives considered

- **Adopt `atrium-api` wholesale for the `com.atproto.*` subset, hand-write
  only `agents.rs`.** Rejected: splits the crate's request/response types
  across two conventions (generated newtypes vs. plain structs) for a partial
  win, while `PdsClientError`'s classification tail and `OAuthClient`'s DPoP
  layer would still wrap every call either way — the maintenance saved on the
  `com.atproto.*` half does not offset the split.
- **Fork `atrium-codegen`'s output to add Custos's extension fields.**
  Rejected: turns this crate's dependency into a vendored, hand-patched copy
  of generated code — strictly more maintenance than the current hand-written
  methods, not less.
