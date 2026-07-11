# ADR-0021: Identity/PLC operations require a full session, not a `transition:generic` OAuth grant

- **Status:** Accepted
- **Date:** 2026-07-11
- **Deciders:** Malpercio
- **Related:** [MM-289](https://linear.app/malpercio/issue/MM-289), [MM-288](https://linear.app/malpercio/issue/MM-288), [ADR-0001](0001-client-held-rotation-key-custody.md) (client-held rotation key), [ADR-0002](0002-wallet-authorized-account-migration.md) (migration), `crates/pds/src/auth/oauth_scopes.rs`, `apps/identity-wallet/src-tauri/src/claim.rs`

## Context

The wallet's **claim flow** (inbound migration — importing an existing identity into the wallet's custody) inserts the device key at `rotationKeys[0]` by driving two PLC (identity) operations on the identity's current PDS: `com.atproto.identity.requestPlcOperationSignature` and `signPlcOperation`.

The atproto OAuth spec defines `transition:generic` as **app-password-equivalent**: it explicitly grants "no account management actions: change handle, change email, delete or deactivate account, migrate account." bsky.social's `scopes_supported` tops out at `transition:generic` — there is no granular `identity:*` scope a third-party wallet can request — so **no OAuth token bsky.social can issue may authorize a PLC operation.** A full session (legacy `com.atproto.server.createSession` with the account password) is the only credential class that can; this is why `goat account migrate` asks for the password.

Custos (our PDS) was the lax counterparty. `oauth_scopes::allows_identity` short-circuited to `true` for `transition:generic`, so the wallet's OAuth-based claim flow validated green against our own PDS while being un-runnable against bsky.social — the same "we're laxer than the spec, so our tests miss it" gap that produced MM-288. The tension: keep the divergence (convenient, but hides the wall until the first spec-strict counterparty) or conform (and give the wallet a full-session path for identity ops).

## Decision

We will **gate identity/PLC operations on full-session authority**, matching the spec and bsky.social:

1. **Custos tightening.** `allows_identity` no longer treats `transition:generic` as sufficient. An identity operation requires either a granular `identity:*`/`identity:{attr}` grant or a full `com.atproto.access` session (`require_identity` short-circuits on the latter before consulting `allows_identity`). `allows_email`/`allows_account`/`allows_repo`/`allows_blob`/`allows_rpc` are **unchanged** — `transition:generic` remains app-password-equivalent for everything except identity ops.
2. **Wallet claim flow.** The claim flow's source-PDS login is now a one-shot password `createSession` → full-session Bearer client (`claim::authenticate_source_pds` → `OAuthClient::new_bearer`), replacing the OAuth PKCE+DPoP login. The password is sent only to the user's PDS, used once, and never stored. OAuth remains the auth for everything else the wallet does.

## Consequences

- **The wallet's claim flow works against any spec-compliant PDS**, bsky.social included — the MM-289 wall is gone.
- **Custos matches spec** for identity-op authorization; a third-party OAuth client can no longer perform identity ops with a `transition:generic` token (it gets `insufficient_scope`). This is a deliberate, if small, breaking change to the OAuth surface. The wallet is unaffected because it no longer relies on it; the outbound-migration orchestrator is unaffected because its OAuth source token only drives repo/blob/status ops (`allows_account`/`allows_repo`), and its identity leg is device-key-self-signed (ADR-0002).
- **A security wallet now asks for the source PDS password** — an anti-pattern unless justified. The claim screen states why (the protocol offers no delegated grant for this one action) and that the password is used once and never stored. An app password is correctly refused (lesser scope).
- **Error honesty.** An `insufficient_scope` refusal on a PLC op now surfaces as such (`ClaimError::InsufficientScope`) instead of the misleading "failed to send verification email" — the MM-288/MM-289 error-surfacing follow-up.
- Follow-on: if we ever want a *fully delegated* claim (no password), it needs a granular `identity:*` grant, which the atproto OAuth ecosystem does not yet offer for third-party clients.

## Alternatives considered

- **Keep Custos lax; add password only for spec-strict servers.** Rejected: two source-login code paths plus server-capability detection, and it leaves Custos permanently diverging from the spec — the exact gap that hid this wall until a live bsky.social run.
- **Keep OAuth for the claim source login and probe scope.** Rejected: `transition:generic` is the *maximum* bsky.social grants, so probing can only ever conclude "insufficient" — there is nothing to fall forward to except a password session. Better to ask for the password directly, honestly.
- **Broaden the tightening to `allows_email`/`allows_account` too (full spec conformance).** Deferred: out of scope for MM-289 and higher-risk — the outbound-migration orchestrator's OAuth source token relies on `allows_account` (deactivate) and repo/blob access. Tightening those needs its own migration to full-session and its own ADR.
