---
title: Getting started
description: Create a new identity or bring an existing one into Obsign.
---

When you open Obsign, you're offered two options:

- **Add an identity** — create a brand-new identity.
- **Move an identity to another PDS** — bring an identity you already have onto a
  server you control (see [Migrating your identity](/user/migration/)).

If you already have identities in the wallet, tap **Add an identity** at the
bottom of your identity list to reach the same screen.

## Add an identity

1. Open Obsign and choose **Add an identity**.
2. Follow the prompts to pick a handle on an available domain and set up your
   account.
3. Obsign generates your identity key **on your device** and seals it. The key
   never leaves your device unencrypted.
4. As part of setup, Obsign walks you through **backing up your recovery key** and
   won't let you finish until you've saved your share — see
   [2-of-3 Shamir backup](/user/backup/).

:::tip
Backup isn't a separate step you do later — it's built into adding your identity,
which is exactly the right time. Save your share somewhere durable when Obsign
prompts you, not after you've lost a device.
:::

## Move an identity to another PDS

If you already have an ATProtocol identity, you can move it to a server you
control without losing your handle or history. That flow has its own page:
[Migrating your identity](/user/migration/).

## The custody model, briefly

Your identity is anchored by two rotation keys, in order of precedence:

- `rotationKeys[0]` — **yours**, held by Obsign on your device.
- `rotationKeys[1]` — the server's, used only for routine operations.

Because your key outranks the server's, you can always override the server. That
ordering is what makes _credible exit_ a property of the keys, not a promise.
