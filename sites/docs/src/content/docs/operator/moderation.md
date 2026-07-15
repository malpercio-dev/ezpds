---
title: Moderation
description: Takedown, restore, and credential-revocation from the operator console.
---

The operator console (the "Brass Console" companion app) exposes the moderation
actions an operator needs. Every action reports exactly what it did — the console
does not soften or hide the effect.

## Actions

- **Takedown** — make an account's content unavailable from your server.
- **Restore** — reverse a takedown.
- **Credential revocation** — invalidate credentials for an account (for example
  after a compromise report).

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
