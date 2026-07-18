# Wallet-Confirmed OAuth Consent (Passwordless Sign-In to OAuth Apps)

Status: **design exploration** — extends the passwordless-auth exploration
([2026-07-12-passwordless-auth.md](2026-07-12-passwordless-auth.md), MM-312) by deciding
the concrete cross-device mechanism it left open: device-code entry (Netflix-style) vs
number matching (GitHub-style) vs QR vs push. Captures the discussion of 2026-07-18.

## Problem

A sovereign account cannot sign in to OAuth apps at all. The consent handler maps a NULL
or empty `password_hash` unconditionally to `WrongPassword`
(`crates/pds/src/routes/oauth_authorize.rs:560-564`, covered by
`post_approve_with_mobile_account_rerenders_consent_page`), and wallet-created /
migrated-in accounts store NULL by design (MM-306). So the account that *most* embodies
the product's identity model is the one locked out of the ATProto OAuth app ecosystem.
There is no push infrastructure yet, but the design must leave a clean slot for it
(notification relay, MM-311).

## The framing: one primitive, several channels

"Device code vs number matching" is not an architecture choice — it is a choice of
**discovery channel** onto a single server-side primitive. Decide the primitive once, and
every channel (typed code, same-device handoff, QR, push) becomes a thin variant:

> **Pending authorization request** — created by the consent page in place of the
> password check; approved out-of-band by the wallet with a device-key-signed envelope;
> observed by the consent page until it can complete the normal redirect.

Nearly all of this already exists in the tree:

| Piece | Existing machinery |
|---|---|
| Pending-request state machine + "approved elsewhere" polling | agent claim ceremony: `agent_claim_attempts` (V037/V038), `routes/oauth_token/claim_polling.rs` (`authorization_pending` / `slow_down` / success, poll throttling, race re-read) |
| Passwordless approval credential | sovereign session: `routes/sovereign_session.rs` — canonical envelope signed by a key in the account's **authoritative PLC `rotationKeys`**, nonce anti-replay, timestamp window |
| Canonical signed-envelope pattern | ADR-0018 admin envelope (`auth/guards.rs::verify_admin_device_request`, `apps/admin-companion/src-tauri/src/signing.rs`) |
| Wallet approval UX (enter code → preview grants → biometric → confirm) | `AgentClaimApprovalScreen.svelte` + `agents.rs` IPC (claim-preview / claim-confirm) |
| Consent page + per-scope checkboxes | `oauth_templates.rs::render_consent_page`, MM-237 scope reduction |
| Push envelope for a future `login-approval` type | notification relay design ([2026-07-10-notification-relay.md](2026-07-10-notification-relay.md)) already names `{type: "login-approval", request_id, client_name, origin, code}` |

The genuinely new pieces are one table, one approval route, one status route, a second
path through `oauth_authorize.rs`, and one wallet screen variant.

## Channel analysis

The security-relevant property is **who carries the binding between the login surface and
the wallet**:

- **Wallet-initiated** channels (user types a code from the page into the wallet, taps a
  link on the page, or scans the page's QR): the *user* carries the binding from the
  thing they are logging into. Blind approval is impossible — the wallet has nothing to
  show until the user brings it a request.
- **Wallet-notified** channels (push, or the wallet polling for pending requests): the
  request finds the user. This is where MFA-fatigue / blind-tap attacks live, and where
  **number matching** earns its keep — it forces the approver to prove they can see the
  login surface.

| Channel | Needs push? | Same-device? | Camera? | Phishing profile |
|---|---|---|---|---|
| Typed short code (Netflix) | no | yes (clunky but works) | no | RFC 8628-style code phishing: attacker starts a login, socially engineers the victim into entering the attacker's code. Mitigated by the wallet preview (client, origin, scopes) before biometric confirm |
| Same-device handoff (link on consent page opens wallet with `request_id`) | no | **the** same-device answer | no | same as typed code, minus transcription |
| QR scan (page shows QR of `request_id` + origin) | no | no (can't scan own screen) | yes | strongest cross-device: user starts from the page, no transcription, wallet verifies origin from the request server-side |
| Push + number match (GitHub/MS Authenticator) | **yes** (MM-311) | yes | no | blind-tap risk is the failure mode; number matching + origin display are the standard mitigations |

Two observations that settle the ordering:

1. **Number matching is a mitigation for the push channel, not an alternative to the
   code.** In every wallet-initiated channel it is redundant — the user already carried
   the binding. Building GitHub-style matching *without* push would require the wallet to
   discover pending requests by polling, which in turn requires the consent page to
   pre-bind a typed handle to the request. That creates an unauthenticated surface where
   anyone typing a victim's handle at any Custos consent page makes a prompt appear in
   the victim's wallet — importing the MFA-fatigue problem *before* gaining push's
   convenience. Rejected as a v1.
2. **Same-device is the common case for a mobile-only PDS** (the OAuth client app is on
   the same phone as the wallet), and it is exactly the case QR cannot serve. The typed
   code always works as the universal fallback (no camera, no push, accessibility-safe,
   cross-device and same-device alike) — which is why it ships first.

## Shape

### The pending request

New table (name illustrative) `pending_oauth_authorizations`:

- `request_id` (random, high-entropy — used in QR / handoff link / push payload)
- `user_code` (short, human-typeable, e.g. 8 chars grouped — the Netflix path; formatted
  distinctly from the agent claim code and the operator claim code; ADR-0026 already
  warns these "share a word, not a mechanism")
- client_id + resolved client metadata snapshot, requested scopes, PAR linkage
- requesting origin/IP/user-agent (for wallet display)
- optional `login_hint` DID (pre-bound account, if the client supplied one)
- status: `pending` / `approved` / `denied` / `expired`; granted-scope set on approval
- created/expires (~5 min), single-use

### Consent-page flow (`oauth_authorize.rs`, second path)

1. `GET /oauth/authorize` for a passwordless-capable flow renders the wallet path
   (alongside the password form while passworded accounts exist): creates the pending
   request, shows the `user_code`, an "Open in Obsign" handoff link carrying
   `request_id` (Phase A), and later a QR (Phase B).
2. The page observes `GET /oauth/authorize/status?request_id=…` (JS poll with the same
   `slow_down` throttling discipline as `claim_polling.rs`; no-JS fallback: an
   "I've approved — continue" button).
3. On `approved`, the page completes through the **existing** tail of
   `post_authorization`: scope reduction already decided, `store_authorization_code`,
   303 to `redirect_uri?code=…&state=…&iss=…`. The token endpoint (PKCE + DPoP) is
   untouched.

### Wallet approval

Reuses the agent-claim screen shape: enter code (or arrive via handoff/QR/push with
`request_id`) → **preview** (client name, origin, requesting IP/geo, scope list —
reusing the scope-preview treatment from `AgentClaimApprovalScreen.svelte`, and the
per-scope uncheck moves here: the wallet is the trusted UI for this path, so the granted
set is chosen in the wallet, not on the page) → biometric gate → sign → submit.

Approval credential: a **device-key-signed canonical envelope** in the
`sovereign_session.rs` mold — domain-versioned string binding server DID, account DID,
signing key, `request_id`, `client_id`, a hash of the granted scope set, timestamp,
nonce; verified against the **authoritative current PLC `rotationKeys`** (same
authoritative-fetch discipline, same nonce anti-replay pattern). This keeps consent
strictly key-sovereign: the thing that can approve a login is the thing that owns the
identity, sessions optional. (The alternative — authenticate the approval route with
`authenticate_account_owner` and skip the envelope — is less code but binds approval to
session state instead of the key; the envelope also gives per-approval non-repudiation
for the audit log.) Passkeys/WebAuthn remain the complementary *browser-native* factor
from the MM-312 open question — additive later, not a competitor to this path.

Account binding: if the request carries a `login_hint`, the approving wallet's DID must
match. Otherwise the approving wallet binds its DID at approval time (exactly like the
agent claim confirm), and the wallet screen states it explicitly: "Sign in to
**{client}** at **{origin}** as **@{handle}**".

### The push slot (Phase C, after MM-311)

Push adds only a delivery path: Custos seals `{type: "login-approval", request_id,
client_name, origin, code}` to the device (the relay design's exact payload), the wallet
deep-links into the same approval screen — with **number matching now mandatory**: the
consent page displays a 2-digit number for push-delivered prompts and the wallet requires
the user to enter/select it before the biometric gate, plus origin display. Nothing about
the primitive, the envelope, or the completion path changes.

## Suggested phasing

- **Phase A — code + handoff (no push, no camera).** The pending-request table/routes,
  the second consent-page path, typed `user_code` entry in the wallet (clone of the
  agent-claim screen), the same-device handoff link. Depends on nothing unbuilt.
- **Phase B — QR.** Encode `request_id` + origin on the consent page; wallet scan screen
  feeding the same approval flow. Camera plumbing is the only new work.
- **Phase C — push + number matching.** After the notification relay (MM-311) lands:
  `login-approval` notification type, deep-link approve/deny, number-match UX.

Prerequisite note: the 2026-07-12 exploration named the Shamir **reconstruction**
ceremony a hard prerequisite for removing the password escape hatch; both reconstruction
ceremonies (escrow-assisted and sovereign) have since landed (`share_recovery.rs`;
[identity-and-key-custody.md](../architecture/identity-and-key-custody.md), verified
2026-07-18), so that gate is satisfied.

## Security invariants (all channels)

- Wallet approval screen always shows client name, origin/redirect host, requested
  scopes, and requesting IP/geo before the biometric gate; approval is impossible
  without the preview render.
- `user_code`/`request_id` single-use, ~5-minute expiry, rate-limited creation per
  client and per IP; status endpoint throttled like `claim_polling.rs`.
- The signed envelope binds the specific request (`request_id`, `client_id`, granted
  scope hash) — an approval cannot be replayed onto a different request or a widened
  scope set.
- Approval verification consults authoritative PLC state, never the cached DID doc
  (matching `sovereign_session.rs`).
- Denials and approvals both terminate the request; audit rows in the mold of
  `agent_audit`.

## Open questions

- **Same-device handoff mechanics on iOS.** ADR-0006 established that *server-initiated*
  redirects cannot launch the wallet from a browser context; a *user-tapped* universal
  link from inside another app's `ASWebAuthenticationSession`/`SFSafariViewController`
  is a different case but needs on-device validation. The typed code is the guaranteed
  fallback either way, so this only gates polish, not the phase.
- **Return-trip UX after same-device approval**: the user must app-switch back to the
  client app whose consent page then completes — acceptable (this is how bank-app
  confirmation flows feel) but worth prototyping.
- **Does the wallet-path consent page still render the password form?** Proposal:
  render the password form only for accounts that have one (requires the identifier
  first, or render both paths side by side as today's form does with checkboxes).
- **Number format for the Phase C match code**: 2-digit select-from-three (Microsoft
  style) vs type-the-number (GitHub style). Type-the-number is stronger against
  guess-taps; decide with the push UX.
