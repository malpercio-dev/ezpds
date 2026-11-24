---
title: How Spaces proves a record came from you
description: What the Spaces key in your identity does, why Obsign asks you to add it, and why the proof it gives only convinces the app that asked.
---

A space is a shared, permissioned place on the network: a group's posts, a
private collection, anything that isn't meant for everyone. When an app reads a
record from a space, it needs to know the record really came from your server
and wasn't swapped or forged on the way.

Spaces answers that with a key your server holds, the **Spaces key**. Your
identity lists its public half so apps can find it. If your identity doesn't
list it, your server can't prove anything, and it won't let you write to spaces
until that's fixed.

## Adding the key to your identity

Accounts made before Spaces existed don't list the key yet. Obsign adds it with
**Update identity for Spaces**, under **Manage identity → Advanced**. If an app
tells you a space write was refused because the key isn't published, its link
opens the same screen.

The update never runs on its own. You'll see exactly what changes, and you
approve it with Face ID or your passcode:

- **Your server's Spaces key is added.** Nothing else in your identity moves:
  not your device key, not your handle, not the server your account lives on.
- **Two old, unused Spaces entries are removed** if your identity has them.
  They came from an earlier draft of Spaces and do nothing today.

If your identity lives on **your own domain** (a `did:web` you host yourself),
Obsign can't change the file for you. It shows the updated `did.json`; you
export it, replace the file on your domain, and tap **I've uploaded this file**.
Your server checks the live copy and finishes only when it lists the new key.

You can run the update again later to replace the key. Nothing breaks while
other servers catch up: an app that sees the old key fetches your identity
again and retries.

## Why the proof only convinces the app that asked

Most proofs are meant to be shown around. This one isn't. If someone leaks a
record from a private space, they shouldn't be able to prove to the world that
you wrote it.

So the proof is a shared secret between two parties: the app reading the
record, and your server. The app could have produced the same proof itself, so
it means nothing to anyone else. It tells the app the record is genuine, and it
tells a third party nothing.

## Advanced: what happens on the wire

For readers who want the mechanism:

1. **A throwaway key per request.** The app makes a fresh P-256 key pair for
   each read and sends the public half with an `Accept-Signature` header.
2. **Both sides reach the same secret.** Your server combines the private half
   of your Spaces key with the app's throwaway public key. The app combines its
   throwaway private key with your Spaces key's public half, which it reads from
   your identity as `#atproto_kem`. Both arrive at the same value
   (elliptic-curve Diffie-Hellman).
3. **A MAC key from that secret.** HPKE's secret export (RFC 9180, DHKEM P-256
   with HKDF-SHA256, `info = "atproto-mac"`) turns it into a 32-byte key.
4. **A MAC over the response.** Your server answers with an
   `Atproto-Space-Commit` (or `-Record`) header and an `hmac-sha256` HTTP
   Message Signature (RFC 9421) under that key. The app computes the same value
   and compares.

"KEM" is HPKE's name for the key-agreement half; nothing is encrypted. The
Spaces key never signs anything and has no say over who controls your identity,
so replacing it changes nothing about your repository or your recovery keys.
