# ADR-0033: App-password personal-details grant

- **Status:** Accepted
- **Date:** 2026-08-19
- **Deciders:** malpercio
- **Related:** ADR-0021 (password source logins), `crates/pds/src/routes/preference_scope.rs`,
  `apps/identity-wallet/src-tauri/src/app_passwords.rs`

## Context

The reference PDS gates a small set of preference `$type`s — today exactly
`app.bsky.actor.defs#personalDetailsPref`, which carries the account's birth date — to
full-access sessions. An app-password session, privileged or not, can neither read nor
write them. Custos mirrors that behavior (`preference_scope.rs`).

For a Custos **sovereign passwordless account** this mirror is a lockout, not a safeguard.
The account has no main password, so an app password minted in the wallet is the only
credential the official Bluesky app can consume (it speaks `createSession`, not OAuth or
the sovereign-session flow). Age-assurance regulation now makes the birth date mandatory:
the app prompts for it on sign-in, the `putPreferences` write is refused
(`do not have authorization to set preference type …personalDetailsPref`), and the user
cannot proceed past the gate. There is no break-glass full-access login to fall back to —
that absence is the point of the sovereign model. The reference posture therefore renders
the official app permanently unusable for these accounts.

The reference gate exists because app passwords are handed to arbitrary third-party
clients, and a birth date is sensitive personal data no throwaway client should see by
default. That rationale is sound and worth keeping as the default.

## Decision

We diverge from the reference deliberately, in the same shape as the existing `privileged`
(DM access) flag: a per-app-password, opt-in **`personalDetails` grant**, chosen at mint
time and immutable thereafter.

- `com.atproto.server.createAppPassword` accepts an off-lexicon boolean input field
  `personalDetails` (lexicon objects are open; the reference ignores it) and echoes it in
  the create and list responses. The grant is stored on the `app_passwords` row (V063).
- Sessions opened with a granted app password carry a `personal_details` claim in the
  access JWT. The scope string stays reference-shaped (`com.atproto.appPass[Privileged]`)
  — the grant is orthogonal to DM privilege, and new scope strings would ripple through
  every scope match. Like `privileged`, the stored grant is re-checked from the DB at
  session issuance and on every `refreshSession`, so revocation is never raced.
- `getPreferences` and `putPreferences` admit a granted app-password session to the
  full-access-only preference types — **read and write both**. Write-only would not help:
  the client decides whether to prompt for a birth date by reading it, so a grant that
  hides the stored value re-opens the nag loop it exists to close.
- The capability is advertised as `appPasswordPersonalDetails` in `describeServer`'s
  `custos` extension, so the wallet shows the mint-time checkbox only on hosts where
  checking it actually grants something.

## Alternatives considered

- **Extend the existing `privileged` flag to cover these preferences.** Smallest diff and
  the official app wants DMs anyway, but it silently widens every already-minted
  privileged app password and welds two unrelated consents ("read my DMs" / "manage my
  birth date") into one checkbox. Separate grants keep each consent legible.
- **Set the birth date out of band with a full-access token.** Works once, but the
  app-password session still cannot *read* it, so the official app keeps prompting and
  failing. Not a fix.
- **Give sovereign accounts a password path as break glass.** Reintroduces exactly the
  phishable, escrow-less credential the sovereign model removes, to serve one preference
  write. Rejected outright.

## Consequences

- A user can knowingly hand the official Bluesky app (or any password client) the ability
  to read and set their birth date. Unchecked, behavior is byte-identical to the
  reference; the divergence is invisible until opted into per credential.
- The grant covers whatever `is_full_access_only_pref` covers. If the reference adds
  types to that set, granted app passwords gain access to them here too — acceptable,
  because the set is by definition "personal-details-class preference data".
- Third-party PDSes ignore the extra input field and mint an ungranted app password; the
  response then lacks the echo field, so clients can detect a grant that didn't take. The
  wallet additionally hides the checkbox behind the capability advertisement.
