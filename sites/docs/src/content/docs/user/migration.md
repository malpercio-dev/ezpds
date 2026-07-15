---
title: Migrating your identity
description: Move between servers without losing your handle, posts, or followers.
---

Because your identity is anchored by keys you hold, moving it to a different
server is a supported operation — not a favor the old server has to grant. This
is _credible exit_: the ability to leave is a property of the keys.

## What moves with you

- Your **handle** and DID.
- Your **repository** — posts, follows, likes, and the rest of your records.
- Your **followers' view of you** — because your DID is stable, others keep
  following the same identity.

## The shape of a migration

1. Stand up (or choose) the destination server.
2. Obsign exports your repository and blobs from the source.
3. Your identity document is updated to point at the new server — signed with
   **your** device key.
4. Obsign verifies the destination serves your repository before finishing.

:::caution[Keep the source reachable until verified]
Do not tear down the old server until Obsign confirms the destination is serving
your repository. The verification step is what turns a hopeful copy into a
completed move.
:::

:::note[Round-trip proven]
The migration flow has been validated end-to-end against the live ATProtocol
network, including a round trip with a major provider. See the operator side in
[Running a relay](/operator/running-a-relay/) for the server's part.
:::
