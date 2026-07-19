---
title: Getting started
description: Create a new identity or bring an existing one into Obsign.
---

When you open Obsign, you're offered three options:

<figure>
  <img src="/screenshots/wallet/welcome.png" alt="Obsign's first screen, offering 'Add an identity', 'Move an identity to another PDS', and 'Recover from backup shares'" width="280" />
  <figcaption>The first screen: create a new identity, move one you already have, or recover one from its backup shares.</figcaption>
</figure>

- **Add an identity** — create a brand-new identity.
- **Move an identity to another PDS** — bring an identity you already have onto a
  server you control (see [Migrating your identity](/user/migration/)).
- **Recover from backup shares** — bring an identity back onto a new device using
  any two of its three backup shares (see
  [Recovering with two shares](/user/backup/#recovering-with-two-shares)).

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

## Advanced: anchor to a domain you control (did:web)

By default, a new identity is a **did:plc** — an entry in ATProtocol's public
PLC directory. That is the right choice for almost everyone, and everything
else in these docs assumes it.

If you already run a domain, Obsign also offers **did:web**: your identity
becomes `did:web:your-domain.example`, anchored to a DID document served from
that domain rather than to the PLC directory. The wallet walks you through
composing the document, proves you control the domain by requiring the exact
reviewed document to be live at its authoritative HTTPS URL before the server
accepts it, and can either let your server host the document for you or leave
you hosting it yourself.

The trade is real, which is why it sits behind an "Advanced" link:

- **You gain** an identity rooted in something you already own. No directory,
  and no server, sits between you and it.
- **You take on** the domain as part of your security perimeter. A did:web
  identity has no PLC rotation keys, so the
  [tamper monitoring and 72-hour override](/user/recovery/) and the
  [2-of-3 share backup](/user/backup/) do not apply — recovery is controlling
  the domain (plus your device key), and losing the domain means losing the
  identity.

## The custody model, briefly

Your identity is anchored by rotation keys, in order of precedence:

- `rotationKeys[0]` — **yours**, held by Obsign on your device.
- `rotationKeys[1]` — your **recovery key**, derived from the secret your
  [2-of-3 Shamir backup](/user/backup/) protects. Your device creates it; the
  server never sees it.
- `rotationKeys[2]` — the server's, used only for routine operations.

You can see them on an identity's DID document screen — `#rotation-0` is your
device key, and the server's key always sits last.

<figure>
  <img src="/screenshots/wallet/identity-detail.png" alt="Obsign DID document screen showing the identifier, handle, and verification keys including #rotation-0 and #rotation-1" width="280" />
  <figcaption>The DID document, decoded: your device key sits at <code>#rotation-0</code>, above the server's. (An identity from before recovery keys — newer identities show a third <code>#rotation</code> entry.)</figcaption>
</figure>

Because your key outranks the server's, you can always override the server. That
ordering is what makes _credible exit_ a property of the keys, not a promise.
