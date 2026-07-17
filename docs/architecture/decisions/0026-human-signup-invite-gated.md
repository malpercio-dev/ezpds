# ADR-0026: Human signup is invite-gated by construction (operator-issued claim codes)

- **Status:** Accepted
- **Date:** 2026-07-17
- **Deciders:** Malpercio
- **Related:** [MM-284](https://linear.app/malpercio/issue/MM-284), [MM-280](https://linear.app/malpercio/issue/MM-280) (labeler-flag monitoring), [ADR-0017](0017-multi-relay-admin-pairings.md) (admin pairings), [ADR-0018](0018-admin-signed-request-envelope.md) (admin signed-request envelope), `crates/pds/src/routes/create_mobile_account.rs`, `crates/pds/src/routes/create_account_xrpc.rs`, `crates/pds/src/routes/standard_signup.rs`, `crates/pds/src/routes/claim_codes.rs`, `crates/pds/src/db/claim_codes.rs`, `crates/pds/src/db/migrations/V004__claim_codes_invite.sql`, `crates/common/src/config.rs` (`invite_code_required`), `apps/admin-companion/src/routes/codes/`

## Context

The [PDS-Operator](https://tangled.org/brookie.blog/pds-operator) discussion surfaced a
recurring failure mode for open ATProto deployments: spam accounts **created by hand**, which
captchas do not stop. The lever operators reported as actually holding was **invite gating** —
requiring an operator-issued code to create an account. It is also the precondition that makes
labeler-flag monitoring ([MM-280](https://linear.app/malpercio/issue/MM-280)) a manageable
review queue rather than a firehose.

MM-284 raised this as *decision-shaped first*: is human signup on our staging/production
deployments open, invite-gated, or closed? — and it was never written down, only implied by a
config default. Recording the posture explicitly (per the "Capture before close" discipline)
is the point of this ADR.

Two facts about ezpds's existing plumbing frame the decision:

1. **"Claim codes" *are* the human-signup invite primitive** — not an agent mechanism.
   Every human signup path redeems an operator-minted row from the `claim_codes` table
   (`V004__claim_codes_invite.sql`: *"operator-generated invite codes issued prior to account
   creation"*). The mobile signup route requires a `claimCode` and redeems it under a
   guarded `UPDATE` (`create_mobile_account.rs`); `create_account_xrpc.rs` enforces the same
   codes when `invite_code_required`; and the stock `com.atproto.server.createInviteCode`
   XRPC route is a thin alias that calls `mint_claim_codes` (`standard_signup.rs`). There is
   **no un-gated human-signup code path** in the server.

   (The similarly-named agent *claim ceremony* `user_code` is unrelated — it is owner-confirmed
   at claim time, never operator-minted; see [ADR-0019](0019-authmd-agent-authentication.md).
   The two "codes" share a word, not a mechanism.)

2. **The Brass Console already surfaces this** — mint on Home, inventory + revoke on the Codes
   screen (`apps/admin-companion/src/routes/codes/`), biometric-gated, shareable — backed by
   `POST`/`GET /v1/accounts/claim-codes` and `POST /v1/accounts/claim-codes/revoke`. The screen
   already describes an outstanding code as "a live signup credential."

So the config toggle `invite_code_required` defaults to `true`
(`crates/common/src/config.rs`; `pds.dev.toml` sets `true`; env
`EZPDS_INVITE_CODE_REQUIRED`), and the codebase has no open-signup path to turn on. The
decision to make explicit is: keep it that way.

## Decision

We will treat **human signup as invite-gated on both staging and production**, ratifying the
existing `invite_code_required = true` default. An account is created only by redeeming an
operator-issued claim/invite code; there is no open-registration path, and we do not intend to
add one.

We further record that in ezpds **claim codes and human-signup invite codes are one primitive**
(the `claim_codes` table). MM-284's scope note asking the UI to keep "claim codes (agents)" and
"invite codes (humans)" visibly distinct was premised on a terminology mismatch — there is no
operator-minted agent code to distinguish from — so **no UI change is made**. The existing Codes
surface is the human-signup invite management the issue asked for.

## Consequences

- **The anti-spam lever is on by default and cannot be silently left off** — creating an account
  structurally requires a code, so a fresh deployment is invite-gated without any operator action.
- **MM-280's labeler monitoring stays a bounded queue** — every new account entered through an
  operator-issued code, so flagged-account review scales with deliberate onboarding, not with an
  open firehose.
- **MM-284's feature deliverable (item 2) is already shipped** — the Brass Console Codes screen +
  the `/v1/accounts/claim-codes` mint/list/revoke surface. MM-284 closes as already-implemented;
  this ADR is item 1 (the decision).
- **Two stock invite endpoints remain intentionally unimplemented:** `com.atproto.admin.getInviteCodes`
  and `com.atproto.server.disableInviteCodes`. ezpds substitutes its own operator-signed
  `GET`/`POST /v1/accounts/claim-codes[/revoke]` (ADR-0018 envelope), which the console already
  uses; `getAccountInviteCodes` returns an empty list because ezpds codes are operator-issued, not
  per-account. Adding the stock endpoints is only warranted if a standard third-party admin client
  needs them.
- **Cost accepted:** onboarding a human always requires an out-of-band code hand-off. For a
  grandma-approved, deliberately-small PDS this is the intended posture, not friction to remove.
- **Reversibility:** flipping `invite_code_required = false` would *not* open signup on its own —
  the mobile signup route still requires a `claimCode`. Genuinely opening registration would be a
  code change with its own ADR (and would re-open the spam exposure this decision closes).

## Alternatives considered

- **Open signup (no code required).** Rejected: it is exactly the configuration the PDS-Operator
  thread reported losing to hand-created spam, and it would make MM-280's review queue unbounded.
  It also does not exist in the code today — there is no open-signup path to enable.
- **Closed signup (operator-only, no codes).** Rejected: too restrictive for the product's intent
  (inviting friends/family onto a self-hosted PDS). Invite codes give the operator exactly the
  gate they want without foreclosing growth.
- **Add a distinct "invite code" UI separate from "claim codes."** Rejected: they are the same
  underlying primitive in ezpds. A second surface would imply a distinction that does not exist and
  invite the same confusion this ADR untangles.
- **Implement the stock `admin.getInviteCodes` / `disableInviteCodes` XRPC endpoints now.**
  Deferred: no current client needs them; the operator surface is the signed `/v1/accounts/claim-codes`
  routes. Revisit if a standard admin client is introduced.
