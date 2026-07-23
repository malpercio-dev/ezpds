---
title: Migrating your identity
description: Move between servers without losing your handle, posts, or followers.
---

Your identity is yours, so you can move it to a different server whenever you
want. You don't need the old server's permission — that's the whole point.

## What comes with you

- Your **handle** (your @-name stays the same).
- Your **posts, follows, and likes**.
- Your **followers** — they keep following the same you, no re-adding needed.

## How a move works

Obsign walks you through it. In plain terms:

1. Choose the server you want to move to (or set up your own).
2. Obsign copies your posts and data over to it.
3. Obsign points your identity at the new server, approved right on your device.
4. Obsign double-checks the new server really has everything before it finishes.

:::caution[Don't shut down the old server too early]
Leave the old server running until Obsign says the move is done. That final check
is what turns a copy into a finished move.
:::

:::note[This really works]
The move has been tested all the way through on the real network, including moving
an identity to a big provider and back. Operators can read the server side in
[Running a relay](/operator/running-a-relay/).
:::

## If some media can't come along

Occasionally the server you're leaving can't hand over a piece of media — a file
it lost, or one it refuses to serve. A single stuck file no longer parks the
whole move. Obsign retries each one on its own and collects any it still can't
transfer into a **loss list** that names exactly what's affected: which media,
which post references it, and whether your old server couldn't serve it or the
new one refused it. You decide, with the facts in front of you, whether to finish
the move without those files rather than abandon the run.

You can often avoid the choice entirely. If you've kept a
[media backup](/user/media-backup/) in iCloud, Obsign fills the gap from your own
copy: it checks the backed-up file still matches its content address and uploads
that to your new server. The substitution is exact, so a file your old server
dropped comes off the loss list instead of being left behind.
