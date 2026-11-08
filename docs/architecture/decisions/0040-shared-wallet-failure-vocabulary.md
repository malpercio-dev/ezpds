# ADR-0040: One shared failure vocabulary for wallet command errors

- **Status:** Accepted
- **Date:** 2026-11-07
- **Deciders:** malpercio
- **Related:** MM-603; amends [ADR-0031](0031-user-facing-error-seam.md); `crates/obsign-core/src/failure.rs`, `apps/identity-wallet/src/lib/ipc/errors.ts`

## Context

ADR-0031 made the typed IPC error the seam between Rust and the screens. It left
each command's enum to map the lower-layer failures (session resolution, identity
store reads, PDS discovery, plc.directory reads) on its own, and it rejected a
re-taxonomy of the session mapping as eight enums' worth of wire churn, leaning on
`SERVER_ERROR { status: None }` to mark the local-failure bucket instead.

The per-enum mappers drifted. By 2026-10-22 there were 22 hand-copied functions,
and they disagreed: a Keychain failure surfaced as
`SERVER_ERROR` in five ceremonies, `UNKNOWN` in one, and `KEYCHAIN_ERROR` in one;
a malformed plc.directory response read as `NETWORK_ERROR` in four and
`PLC_DIRECTORY_ERROR` in one. The five `SERVER_ERROR` cases were the
false-attribution defect ADR-0031 names. The session pre-flight
(`ensure_identity_session`) used its own vocabulary (`NEEDS_UNLOCK`, `OFFLINE`,
`SERVER_FAILURE`, `KEYCHAIN`), so screens checked two codes for one condition.

## Decision

We classify those four lower-layer failures once, into `SharedFailure`
(`obsign-core/src/failure.rs`), and the 14 command enums those mappers fed embed it as
`#[serde(untagged)] Shared(#[from] SharedFailure)`. A command never redeclares a
shared code. The session pre-flight returns `SharedFailure` directly.

The codes are `SESSION_LOCKED`, `RATE_LIMITED`, `IDENTITY_NOT_FOUND`,
`NETWORK_ERROR`, `SERVER_ERROR { status }`, `UNSUPPORTED_HOST`,
`INVALID_RESPONSE`, `KEYCHAIN_ERROR`, and `PLC_DIRECTORY_ERROR`. Two rules make
them honest:

- `SERVER_ERROR` always carries a real HTTP status. A response this client could
  not use is `INVALID_RESPONSE`; a local Keychain failure is `KEYCHAIN_ERROR`.
  In the enums that embed `SharedFailure`, the `status: None` bucket ADR-0031
  relied on no longer exists.
- Every shared `message` is diagnostic. A command that carries server-quoted text
  (ADR-0031 rule 4) uses its own code for it, so diagnostic and quoted text never
  share a code. The password unlock's quoted variant is `SERVER_REJECTED` for
  this reason.

The seam itself is unchanged: errors still serialize flat as `{ code, …fields }`,
and screens still choose the sentence by `code`.

## Consequences

- The deletion test holds: the mapper functions are gone, the decision lives in
  one module with one test module, and `$lib/ipc` has one `SharedFailure` type
  that each command union includes.
- Wire codes changed for a few commands: `NEEDS_UNLOCK` and `SESSION_REQUIRED`
  became `SESSION_LOCKED`; `TRANSPORT_FAILURE`, `OFFLINE`, `KEYCHAIN_FAILURE`,
  `KEYCHAIN`, and `SERVER_FAILURE` became their shared names; the agents API's
  session failures are no longer `UNKNOWN`. Screens without a sentence for a newly
  reachable code fall to their default sentence.
- `IDENTITY_NOT_FOUND` carries no `message`. A failed device-key lookup now goes
  through the store classification, so a Keychain fault there reads as
  `KEYCHAIN_ERROR` rather than "identity not found".
- `custos-client`'s `sovereign_login` passes discovery failures up unclassified
  (`SovereignLoginError::Discovery`), so that classification also happens once.
- Not yet migrated, because none of them held one of the copied mappers: `repo_backup`
  (its own `RATE_LIMITED`/`NETWORK_ERROR`/`PLC_DIRECTORY_ERROR`/`KEYCHAIN_ERROR` and a
  `SERVER_ERROR { status: null }`), `endpoint_repair`'s directory mapping, the
  `SERVER_ERROR` variants in `claim`, `migration_orchestrator`, and `create_flow`, and
  the per-module `PerDidSignError` match. A device key the Secure Enclave reports
  unusable still reaches most ceremonies as `KEYCHAIN_ERROR` rather than its own code.
  Each should move onto `SharedFailure` (or gain its own code) when next touched.

## Alternatives considered

- **Keep per-enum mappers and fix the five wrong arms.** Smallest diff, but the
  drift came from copying, and copies would keep drifting.
- **A trait each enum implements with one constructor per shared code.** One
  decision function, but a dozen trait impls reappear in place of the mappers,
  and the codes stay declared once per enum on both sides of the wire.
- **Keep the pre-flight's own codes.** Leaves two near-identical enums and the
  screens' double check of `NEEDS_UNLOCK` and `SESSION_LOCKED`.
