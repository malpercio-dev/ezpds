---
title: Getting started
description: Create a new identity or bring an existing one into Obsign.
---

There are two ways to begin: create a brand-new identity, or bring one you
already have.

## Create a new identity

1. Open Obsign and choose **Create identity**.
2. Pick a handle on an available domain.
3. Obsign generates your identity key **on your device** and seals it. The key
   never leaves your device unencrypted.
4. Set up recovery before you post anything — see
   [2-of-3 Shamir backup](/user/backup/).

:::tip
Do the backup step _first_. Recovery you set up before you need it is the whole
point; recovery you set up after losing a device is too late.
:::

## Bring an existing identity

If you already have an ATProtocol account, you can migrate it into a server you
control without losing your handle or history. That flow has its own page:
[Migrating your identity](/user/migration/).

## The custody model, briefly

Your identity is anchored by two rotation keys, in order of precedence:

- `rotationKeys[0]` — **yours**, held by Obsign on your device.
- `rotationKeys[1]` — the server's, used only for routine operations.

Because your key outranks the server's, you can always override the server. That
ordering is what makes _credible exit_ a property of the keys, not a promise.
