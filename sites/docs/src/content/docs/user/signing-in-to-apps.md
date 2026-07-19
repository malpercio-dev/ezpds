---
title: Signing in to apps
description: Approve sign-in to a third-party ATProtocol app with your wallet — no password.
---

Obsign identities don't have a password. The keys that prove who you are live on
your device, not on a server, so there's no password for an app to check. That
used to mean sovereign and migrated-in identities couldn't sign in to third-party
OAuth apps at all. Now they can — you approve the sign-in in the wallet, with your
device key, and no password is ever involved.

## How it works

When you sign in to an ATProtocol app with an Obsign identity, the app sends you
to your server's sign-in page. Instead of a password box, that page shows three
ways to hand the request to your wallet:

- a short **typed code**,
- a **QR code**, and
- an **Open in Obsign** link (when the app is on the same phone as your wallet).

Bring the request into Obsign by any one of them. The wallet then shows you
exactly what you're about to approve:

- the **app** asking to sign in,
- the **origin** it's running on,
- the identity you'd sign in **as**, and
- the **permissions** it's requesting.

Check that preview, drop any permissions you don't want to grant, and confirm with
Face ID or Touch ID. That's the sign-in. The app's page notices the approval and
finishes on its own.

### Bring the request in three ways

**Typed code.** Read the short code off the sign-in page and enter it in Obsign.
This always works — no camera, no second device, and it reads cleanly for screen
readers. It's the fallback the other two fall back to.

**QR code.** Point the phone camera at the QR beside the code. Best when the app
is on a different screen from your wallet — a laptop, say — because you can't scan
your own phone's screen.

**Open in Obsign.** When the app and the wallet are on the same phone, tap the
link and it opens Obsign straight to the approval. No typing, no scanning.

## Why this is safe

The QR and the handoff link carry only a request id — never the app name, origin,
or permissions. Obsign takes that id and fetches the real details **from your own
server**, then shows you those. So a doctored QR can't trick you into approving
something other than what your server actually recorded. What you see in the
preview is the source of truth, not what the code claimed.

A few more guarantees hold on every path:

- **Your key approves, not a session.** The confirmation is a signature from your
  device key, checked against your identity's authoritative rotation keys — the
  same keys that anchor the identity itself. Approving a login is something only
  the holder of the identity can do.
- **One use, then it's spent.** Each request works once and expires in about five
  minutes.
- **No replay, no scope creep.** The signature is bound to that specific request
  and to the exact set of permissions you granted. It can't be replayed onto a
  different sign-in or a wider set of permissions.
- **Approvals and denials are both recorded.** If you deny a request, that ends
  it, and the decision is written to your identity's audit trail either way.

:::note[Reducing what you grant]
The permission checkboxes live in the wallet, not on the web page — the wallet is
the trusted surface for this decision. Uncheck anything the app asked for that you
don't want to hand over before you confirm; the app only gets what you approved.
:::

## What's not here yet

Today you start every sign-in from the app's page and carry it to the wallet.
Push notifications — where the wallet asks you to approve a sign-in the moment one
is requested — aren't wired up yet. When they land, they'll come with number
matching (you'll confirm a number shown on the sign-in page) so a stray prompt
can't be approved by a reflexive tap.
