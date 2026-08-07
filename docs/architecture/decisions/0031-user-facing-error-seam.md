# ADR-0031: The user-facing error seam (Rust → screen)

- **Status:** Accepted
- **Date:** 2026-08-07
- **Deciders:** mal
- **Related:** MM-501; [docs/writing-style.md](../../writing-style.md) (the screens
  error rule); admin-companion's `src/lib/errors.ts` (the existing embodiment);
  wallet `pds_client.rs` (`classify_xrpc_error`, the honest lower layer)

## Context

Both mobile apps front a Rust backend through Tauri `invoke()`, and every command
can reject. The wire contract was already typed — errors serialize as
`{ code: "SCREAMING_SNAKE_CASE", …camelCase fields }` — but nothing declared
*which strings are for people*. Three defect classes grew in the gap:

1. **Diagnostics rendered as prose.** Screens interpolated `message` payload
   fields into their error sentences (`` `Signing failed: ${err.message}` ``),
   so wrapped error chains, Keychain internals, and module-flavored text like
   `Failed to cache updated PLC log in Keychain: …` reached screens verbatim.
2. **False attribution.** The shared session-error mapping flattens *local*
   failures (Keychain writes, malformed responses) into the same `SERVER_ERROR`
   shape whose `message` some screens render behind "Your PDS reported: …" —
   blaming the user's server for a failure on their device.
3. **Prose split across the boundary.** Some Rust variants carry finished user
   sentences (`source_login.rs` shipped "The PDS did not accept that password."
   in a `message` field the screen doesn't even read), so the same sentence has
   two owners and the style guide can't be applied — or reviewed — in one place.

The style guide's screens rule is the constraint to satisfy: error copy answers
what happened / what it means / what to do next, and internal detail stays out
of the user's sentence. That rule is only reviewable if the boundary between
"reaches a screen" and "reaches a log" is declared.

Meanwhile the codebase already contained the right pattern twice: admin-companion's
`errors.ts` owns every operator-facing sentence keyed by `code` (with one
deliberate, documented render of relay-supplied text), and the wallet's newer
screens (ChangeHandle, RekeyReview, RotateRepoKey) map `code → sentence` without
touching `message`. The decision is to make that pattern the law of the seam
rather than a local habit.

## Decision

The typed IPC error — `{ code, …fields }` — is the seam. Four rules:

1. **Every command rejects with a typed error enum.** No `Result<T, String>`
   rejections: a raw string has no code for the frontend to key on and no
   declared audience. (A command documented as never rejecting may keep a
   nominal error type.)

2. **The user's sentence is frontend-owned, selected by `code`.** Screens (or
   shared helpers like `claim-errors.ts` / admin's `errors.ts`) write one
   sentence per code, styled per writing-style.md. Rust does not author screen
   prose; a variant that needs a different sentence is a new `code`, not a new
   `message` string.

3. **`message` fields are diagnostic by default.** They exist for logs,
   `console.error`, and the exported diagnostics — never inside the user's
   sentence. A screen may render one only in a visually subordinate,
   explicitly-diagnostic detail slot (the MigrationProgressScreen pattern:
   generic headline per code, carried detail beneath it in the data register).

4. **Server-quoted variants are the one attribution exception.** A variant whose
   doc comment declares its `message` carries the remote server's own error
   text (the atproto error envelope, a relay's stated reason) may be rendered
   behind explicit attribution ("Your PDS reported: …"). The declaration is a
   contract on the *producer*: nothing but server-supplied text may flow into
   that field, so local failures can never surface under a server's name.
   Renders of server-quoted text are length-bounded — an 8 KB gateway HTML page
   is not a message. The bound is **240 characters, measured on the trimmed
   server text before the attributing lead is prepended**, with the overflow
   replaced by a single `…`; empty text falls back to a fixed sentence rather
   than rendering an empty quote. Bounding before attribution keeps the limit a
   property of the server's text, so changing the lead can never change what
   counts as oversized. Both apps implement it independently — the wallet's
   `claim-errors.ts` (`MAX_QUOTED_SERVER_TEXT`) and the console's `errors.ts`
   (`MAX_QUOTED_RELAY_TEXT`), which render the two declared server-quoted
   fields. The apps share no code, so the constant is duplicated rather than
   imported across an app boundary; a third server-quoted field anywhere means
   a third renderer that must satisfy this rule.

   Attribution is not decoration. A declared server-quoted field renders behind
   a lead naming the source ("Your PDS reported: …", "The relay reported: …")
   because the operator's pairing set can include a server they do not run:
   unattributed remote text reads as the app's own voice, which is a stronger
   claim than the app can make for someone else's string.

Every **message-bearing** variant gets classified under rule 3/4 in its doc
comment. Unit variants (`RecoveryWindowExpired`, `TwoFactorRequired`) carry no
text to classify — their `code` is the whole payload, and rules 1/2 already
govern them. That makes the seam reviewable: a `format!("…: {e}")` flowing into
a server-quoted field, or a screen interpolating a diagnostic field, is now a
violation with a citable rule.

## Consequences

- The style guide's error rule becomes enforceable at review time: prose changes
  happen in the frontend mapping layer, message-field changes are diagnostics
  work, and the two can't silently trade places.
- Screens can no longer lie about where a failure happened. The session-mapped
  `SERVER_ERROR { status: None }` bucket (a local session-layer failure) renders
  a non-attributing sentence; only a real server verdict gets server attribution.
- Rust sheds its embedded user prose over time. `source_login.rs` is the worked
  example: `SourceAuthFailed { message }` used to carry the screen's sentence
  ("The PDS did not accept that password."), and the same change that declares
  the seam **reclassifies** it as a diagnostic — the field stays on the wire,
  but its content is now a log line ("createSession rejected the credentials
  (401)") and the sentence moved to the screens. Reclassifying rather than
  deleting keeps the variant's shape stable for `claim.rs` and
  `migration_orchestrator.rs`; wire payloads shrink toward codes + structured
  facts as variants are revisited, not in one sweep.
- Diagnostic detail is not lost: it still flows to `tracing`, `console.error`,
  and the redacted diagnostics export — the log, where the style guide says it
  belongs.
- Cost: ~a dozen wallet screens and helpers needed a mapping pass, and future
  error variants must decide their classification up front. That is the point.
- Tolerated legacy, named here so it doesn't read as precedent:
  `migration-errors.ts` regex-parses two Rust `format!` shapes to attribute
  blob-transfer failures. Its structured twin (`BlobLoss`) is the model; the
  regex path should migrate to structured fields when the orchestrator's error
  shape next changes.

## Alternatives considered

- **Rust-owned user sentences** (a `userMessage` field on every variant, or a
  per-crate messages module): keeps prose next to the failure, but doubles the
  sentence across ~25 enums' variants, puts copy edits behind a Rust rebuild,
  and leaves the frontend free to keep interpolating. The frontend already owns
  layout, tone context (which surface is everyday vs operator), and the
  harness; sentences live with their surface.
- **A structural wire split** (`{ user: …, diagnostic: … }` on every error):
  honest by construction, but a breaking change to every enum, every `$lib/ipc`
  type, and every harness handler — for information the `code` + declared
  classification already carry.
- **Per-enum re-taxonomy of the session mapping** (distinct `KEYCHAIN` /
  `INVALID_RESPONSE` codes everywhere, as `password_unlock.rs` already does):
  the cleanest end state, and new enums should do this — but retrofitting eight
  enums churns the wire for codes whose screens would all render the same
  "couldn't restore the session" sentence. The `status: None` discriminant
  already separates the bucket; the ADR makes that load-bearing instead.
