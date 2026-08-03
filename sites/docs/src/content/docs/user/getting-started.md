---
title: Getting started
description: Create a new identity or bring an existing one into Obsign.
---

When you open Obsign, it asks one question: **what's your situation?** Pick the
answer that fits and the app walks you through the right steps.

<figure>
  <img src="/screenshots/wallet/welcome.png" alt="Obsign's first screen, 'Add an identity — what's your situation?', listing 'Starting fresh', 'I have an account somewhere', 'I lost access to my wallet', and 'My server is gone'" width="280" />
  <figcaption>The first screen asks what you're trying to do and routes you from there.</figcaption>
</figure>

- **Starting fresh** — create a brand-new identity on a server you choose.
- **I have an account somewhere** — you already have a Bluesky (or other
  ATProto) account. Obsign puts your device in charge of it; the account stays
  where it is.
- **I lost access to my wallet** — bring an identity back onto a new device
  using two of its three backup shares (see
  [Recovering with two shares](/user/backup/#recovering-with-two-shares)).
- **My server is gone** — your server has disappeared and you need your
  identity somewhere else.

Already have identities in the wallet? Tap **Add an identity** at the bottom of
your identity list to reach this screen again.

<figure>
  <img src="/screenshots/wallet/home-multi.png" alt="Obsign home screen listing two identities, each with a root-key status badge, and an 'Add an identity' button at the bottom" width="280" />
  <figcaption>The identity list. One wallet holds several identities, and each shows whether your device holds its keys.</figcaption>
</figure>

## Create a new identity

1. Choose **Starting fresh**.
2. Follow the prompts to pick a handle on an available domain and set up your
   account.
3. Obsign generates your identity key on your device and seals it there. The
   key never leaves your device unencrypted.
4. Before you finish, Obsign walks you through saving your recovery share. You
   can't skip this step. See [2-of-3 Shamir backup](/user/backup/).

:::tip
Save your share somewhere durable when the app asks: a password manager, or a
printed copy in a safe place. If you wait until a device is lost, it's too
late.
:::

:::note
Creating a new identity needs a **Custos** server. A standard server can only
create accounts where the server holds the keys, and Obsign's job is to keep
the keys with you. If you point Obsign at a server that can't do this, it tells
you on the server screen, before you fill anything in, and offers to import an
existing account there instead.
:::

## Bring in an existing account

If you already have an account — on
[bsky.social](https://bsky.social), a self-hosted server, anywhere — choose
**I have an account somewhere**. Obsign makes this device the account's master
key. That's what turns on tamper monitoring, the 72-hour reversal window, and
your own backups.

Your account doesn't move. It keeps the same server and the same handle. This
works with any spec-compliant server, Custos or not.

Moving the account to a different server is a separate decision you can make
later, from the identity's own screen. See
[Migrating your identity](/user/migration/).

## Who holds the keys

Your identity is controlled by a ranked list of keys. Higher entries outrank
lower ones:

1. **Your device key**, sealed on your phone and held by Obsign.
2. **Your recovery key**, protected by your
   [2-of-3 Shamir backup](/user/backup/). Your device creates it; the server
   never sees it.
3. **The server's key**, used for routine operations.

Because your keys outrank the server's, no server can take the identity from
you, and you can always leave. You can see the list on an identity's DID
document screen, where the entries are labeled `#rotation-0`, `#rotation-1`,
and so on.

<figure>
  <img src="/screenshots/wallet/identity-detail.png" alt="Obsign DID document screen showing the identifier, handle, and verification keys including #rotation-0 and #rotation-1" width="280" />
  <figcaption>The DID document screen: your device key sits above the server's. (This identity predates recovery keys; newer identities show a third entry.)</figcaption>
</figure>

## Advanced: anchor your identity to a domain you own (did:web)

By default, a new identity is a **did:plc**: an entry in ATProtocol's public
PLC directory. That's the right choice for almost everyone, and the rest of
these docs assume it.

If you run your own domain, Obsign can instead anchor your identity to it, as
`did:web:your-domain.example`. The wallet helps you compose the identity
document, confirms it's live on your domain before the server accepts it, and
can either host the document for you or leave the hosting to you.

Know the trade before choosing it:

- **You gain** an identity rooted in something you already own. No directory
  and no server sits between you and it.
- **You give up** the safety net. Tamper monitoring, the
  [72-hour reversal window](/user/recovery/), and the
  [2-of-3 share backup](/user/backup/) don't apply to a did:web identity.
  Recovery means controlling the domain, and losing the domain means losing
  the identity.
