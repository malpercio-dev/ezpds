# Passwordless Authentication for Custos + Obsign

Status: **design exploration** — not yet scheduled into a wave. Captures the auth
discussion of 2026-07-12 so it survives the session (capture-before-close). Follow-up
tracked in [MM-312](https://linear.app/malpercio/issue/MM-312).

## Problem

Custos accounts carry an argon2id password, but in this architecture the password is
already a second-class credential. The wallet authenticates via OAuth 2.1 + PKCE + DPoP
and retains no password; the root of trust is the Secure-Enclave device key, which holds
`rotationKeys[0]` on the DID ([ADR-0001](../architecture/decisions/0001-client-held-rotation-key-custody.md)).
The question explored here: can we drop the password entirely — forcing account creation
through the wallet (already the de facto reality) — and what does that actually cost?

The phase-0.1 review docs already point in this direction: "promote the device/biometric
to a first-class session factor" ([gap analysis](../2026-06-30-pds-phase-0.1-gap-and-competitive-analysis.md),
citing cirrus's passwordless passkey auth; reiterated as passkey/WebAuthn session auth in
the [review update](../2026-07-01-pds-phase-0.1-review-update.md)). This exploration turns
that note into a concrete shape.

## What the password actually gates today

Mapped against the current tree; the surface is smaller than it looks.

1. **The OAuth consent form** (`crates/pds/src/routes/oauth_authorize.rs`). The one place
   the wallet's own login still needs a password. Notably, an account with a NULL
   `password_hash` *cannot* pass OAuth consent at all today — the handler explicitly
   rejects it.
2. **`createSession` for standard clients** (Bluesky app, goat). Already
   passwordless-ready: a NULL main password falls through to **app-password**
   verification (`create_session.rs`), and the wallet can mint app passwords. Third-party
   client access survives password removal with zero server changes.
3. **Account creation.** A non-empty password is required by the `/v1/dids` wallet
   ceremony (`create_did.rs`) and `createAccount`'s new-account mode
   (`create_account_xrpc.rs`). But `accounts.password_hash` has been **nullable since
   V008**, and migration-mode accounts already store NULL ("OAuth-only"). The schema is
   passwordless-ready; only the input validation isn't.
4. **`deleteAccount`** (`delete_account.rs`). Takes password + email token in the body —
   no session auth.

Everything else (repo writes, service proxy, admin surface, device transfer) runs on
tokens, service-auth JWTs, or signed device requests already.

## The "recovery factor" objection, examined

The instinctive cost of going passwordless — losing a recovery factor — turns out to be
mostly illusory here:

- **The password never recovered the identity.** Identity recovery is the device key's
  2-of-3 Shamir split (iCloud Keychain / PDS escrow / user copy) plus the 72-hour PLC
  override window ([identity-and-key-custody.md](../architecture/identity-and-key-custody.md)).
  The password only ever gated PDS *sessions*.
- **Password reset is dead code in practice.** Outbound email is stubbed (MM-211):
  `requestPasswordReset` logs the token instead of sending it. A forgotten password is
  already unrecoverable — the password is a liability posing as a factor.

The *real* gap passwordless opens is different: **a lost or dead phone currently means no
way to mint app passwords or approve anything**, and the Shamir *reconstruction* ceremony
is still future work (share generation runs during the DID ceremony; reconstruction does
not exist yet). Removing the password promotes that ceremony from nice-to-have to **hard
prerequisite**. Alternatively (or additionally), iCloud-synced passkeys would quietly
restore a synced recovery factor.

## Shape

### Login surfaces, passwordless

| Surface | Today | Passwordless |
|---|---|---|
| Wallet → own PDS (OAuth consent) | identifier + password form | device-key-signed approval or passkey (WebAuthn) — **the only genuinely new auth path** |
| Third-party ATProto clients | `createSession` password | app passwords minted in the wallet (works today for NULL-main-password accounts) |
| Cross-device / web login | password | Phase 2: QR-scan approval, then push-to-approve |
| Migrated-in interop accounts | `createSession` password | unchanged — keep the password branch for accounts that arrive with one |
| Account deletion | password + email token | email token or wallet-signed request |

For the consent factor, the server-side verification pattern already exists: the
admin-companion's signed-request envelope (`auth/guards.rs::verify_admin_device_request` —
per-device P-256 key, canonical envelope over method/path/timestamp/nonce/body-hash, nonce
anti-replay). Generalizing that to user devices is incremental, not greenfield. The
passkey/WebAuthn route is more standard and gives iCloud-synced recovery for free;
deciding between them (or layering them) is the first open question below.

### Push-to-approve and the notification relay

"Send a push to launch the app for login requests" is the natural cross-device endgame,
and it now has a foundation: the
[E2E-encrypted notification relay](2026-07-10-notification-relay.md) (PR
[#207](https://github.com/malpercio-dev/ezpds/pull/207)) defines how a self-hosted Custos
instance pushes to the official apps through a relay that is untrusted for everything
except availability — HPKE-sealed payloads, per-device notification keys, opaque push
handles, iroh transport.

A login-approval push slots into that design as one more notification type: Custos seals
`{type: "login-approval", request_id, client_name, origin, code}` to the device, the
wallet deep-links into an approve/deny screen, and the approval returns over the normal
authenticated channel (device-key-signed). The relay never learns that a login is
happening, let alone for whom — consistent with the relay's metadata-minimization goals.

Two cautions, so the dependency ordering stays honest:

- **Push-approve is the phishing-weak variant.** MFA-fatigue attacks (spam approvals
  until the user taps yes) are the known failure mode. Any push-approve implementation
  needs origin display and number matching (the consent page shows a code; the wallet
  makes the user confirm it). A **wallet-initiated QR scan** on the authorize page is
  inherently more phishing-resistant — the user starts from the thing they're logging
  into — and needs no push infrastructure at all. QR ships first; push is the
  convenience layer on top.
- **The relay is a dependency, not a blocker, for passwordless itself.** Phase 1 (below)
  removes the password with no push involvement; only the cross-device convenience story
  waits on the relay.

## Suggested phasing (when scheduled)

1. **Passwordless core.** Make the password optional in `/v1/dids` and
   `createAccount` new-account mode (the lexicon already treats it as optional); wallet
   ceremony stops collecting it. Add the device-key/passkey factor to OAuth consent.
   Rework `deleteAccount` to email-token-or-wallet-signature for passwordless accounts.
   Keep the interop surface (password branch of `createSession`, app passwords, standard
   `createAccount`) for migrated-in accounts. Mostly deletions plus one new consent path.
2. **Cross-device approval.** QR-scan approval on the authorize page (wallet scans,
   reviews origin, approves with a device-key signature). No push required.
3. **Push-to-approve.** Once the notification relay (PR #207) lands: the login-approval
   notification type, deep-link approve/deny screen, number-matching UX. Push also
   unblocks background PLC-tamper alerts (ADR-0013 deferred these), which may be the
   better *first* consumer of the relay.

**Hard prerequisite, in parallel with Phase 1:** the Shamir reconstruction ceremony (or
iCloud-synced passkeys), so lost-device ≠ total PDS lockout before the password escape
hatch is removed.

## Open questions

- **Consent factor: passkey/WebAuthn vs device-key-signed envelope.** Passkeys are
  standard, browser-native, and iCloud-synced (recovery for free); the signed-envelope
  route reuses proven in-repo machinery and keeps the factor in the Secure Enclave
  (non-syncable — which is either a feature or a bug depending on the recovery story).
  Possibly both: passkey for browser consent, signed envelope for wallet-native flows.
- **What do migrated-in accounts without a wallet do?** An account that migrates in via
  standard tooling has a password and no device key. They keep the password branch — but
  is there a promotion path (enroll a wallet, then drop the password)?
- **`describeServer` / client signaling.** How does a standard client learn that this PDS
  prefers app-password login for passwordless accounts? (Today it just gets a 401 on the
  main password.)
- **Does Phase 1 remove password *support* or password *requirement*?** This exploration
  assumes requirement-removal only: existing passworded accounts keep working, new
  wallet-created accounts simply never set one.
