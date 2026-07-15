---
title: Getting started
description: Create a new identity or bring an existing one into Obsign.
---

When you open Obsign, you're offered two options:

<figure>
  <img src="/screenshots/wallet/welcome.png" alt="Obsign's first screen, offering 'Add an identity' and 'Move an identity to another PDS'" width="280" />
  <figcaption>The first screen: create a new identity, or move one you already have.</figcaption>
</figure>

- **Add an identity** — create a brand-new identity.
- **Move an identity to another PDS** — bring an identity you already have onto a
  server you control (see [Migrating your identity](/user/migration/)).

If you already have identities in the wallet, tap **Add an identity** at the
bottom of your identity list to reach the same screen.

<figure>
  <img src="/screenshots/wallet/home-multi.png" alt="Obsign home screen listing two identities, each with a root-key status badge, and an 'Add an identity' button at the bottom" width="280" />
  <figcaption>The identity list. One wallet holds several identities; each shows whether your device holds its root key.</figcaption>
</figure>

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

You can see both on an identity's DID document screen — `#rotation-0` is your
device key, `#rotation-1` is the server's.

<figure>
  <img src="/screenshots/wallet/identity-detail.png" alt="Obsign DID document screen showing the identifier, handle, and verification keys including #rotation-0 and #rotation-1" width="280" />
  <figcaption>The DID document, decoded: your device key sits at <code>#rotation-0</code>, above the server's <code>#rotation-1</code>.</figcaption>
</figure>

Because your key outranks the server's, you can always override the server. That
ordering is what makes _credible exit_ a property of the keys, not a promise.
