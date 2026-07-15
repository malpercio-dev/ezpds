---
title: Moderation
description: Takedown, restore, credential revocation, and account repair from the operator console.
---

The operator console (the "Brass Console" companion app) exposes the moderation
actions an operator needs. Every action reports exactly what it did — the console
does not soften or hide the effect.

## Actions

On the **Moderation** screen (look up an account by DID first):

- **Takedown** — stop serving an account: logins, writes, and sync are refused
  until it is restored.
- **Restore** — reverse a takedown (the account resumes serving unless it is also
  suspended or deactivated).
- **Credential revocation** — the incident-response follow-up for a compromised
  account: in one sweep it revokes the account's **sessions, app passwords, OAuth
  grants and pending authorization codes, and transfer-device tokens**, and reports
  the literal per-family counts. The account's **main password is untouched**, and
  any already-issued access tokens lapse on their own within minutes. Every holder
  — including the owner — is signed out and must log in again.

On the **Account detail** screen (reached by tapping an account in the list):

- **Correct an email** — fix an account's email address; this resets it to
  unconfirmed.
- **Issue a password-reset token** — mint a single-use, one-hour reset token for
  out-of-band delivery. This is **refused for a passwordless / key-sovereign
  account** — those recover through their escrowed key share, not a reset.

Both takedown and credential revocation are destructive, so the console arms them
behind a two-tap confirmation that restates the target, then a biometric gate,
before anything is signed.

:::caution[Takedown is server-scoped, not identity-scoped]
A takedown affects what _your_ server serves. Because the user holds
`rotationKeys[0]`, they can migrate their identity elsewhere. Moderation is your
control over your infrastructure, not custody over their identity — keep that
distinction clear when you communicate an action.
:::

## Accountability

Moderation actions are shown with their subject, the operator device that signed
them, and the result — status carried in text, not by color alone. Pair any
externally visible action with a clear, honest explanation to the affected user;
the tooling reports the literal truth, and so should you.

:::note[Per-device operator keys]
Operator actions are signed by a per-device key (Secure-Enclave-backed on real
devices). Revoking a device revokes its ability to act, per relay, without
disturbing the others.
:::
