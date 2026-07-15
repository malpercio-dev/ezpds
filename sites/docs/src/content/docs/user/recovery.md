---
title: Tamper monitoring & recovery
description: How Obsign watches your identity for unexpected changes, and the 72-hour override.
---

Obsign continuously checks that your identity document (your DID) still says what
it should. If something changes that you did not initiate, Obsign tells you — in
words, with an icon and a place in the list, never by color alone.

## Reading a status

Every identity shows a status. The status is always carried by **text + icon +
position**, so it is legible without relying on color:

:::note[Monitoring]
Nothing unexpected. Obsign is watching and the identity document matches what you
last approved.
:::

:::caution[Change detected]
The identity document changed in a way you did not initiate. You have a window to
review and, if needed, override it.
:::

:::danger[Action needed]
An override window is closing, or a change would remove your ability to recover.
This state is paired with an explicit label and a persistent banner, not a red
dot alone.
:::

## The 72-hour override

ATProtocol gives the higher-precedence rotation key a **72-hour window** to
contest a change. Because your key is `rotationKeys[0]` (see
[Getting started](/user/getting-started/)), you hold that power:

1. Obsign detects a contested change and starts the countdown.
2. You review what changed, in plain language.
3. If it was not you, you sign an override with your device key, and the change
   is reversed within the window.

:::tip
The countdown is shown as a time remaining, not just a color. If you have backup
set up, an override needs only your device — no scramble to reassemble anything.
:::
