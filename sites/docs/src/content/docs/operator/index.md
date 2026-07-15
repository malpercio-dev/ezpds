---
title: Running Custos
description: The operator's view — what Custos runs and how to run it.
---

Custos is the server side: the PDS that hosts identities and the operator console
that manages it. This surface reports the literal truth of what the machine is
doing — it does not hide the machinery.

If you are _using_ an identity rather than running a server, you want
[Using Obsign](/user/) instead — a different audience, a different register.

## What you run

- **[Running a relay](/operator/running-a-relay/)** — stand up the PDS, its
  health, and what you are (and aren't) responsible for.
- **[Configuration](/operator/configuration/)** — the config and environment
  surface that tunes a deployment.
- **[Moderation](/operator/moderation/)** — takedown, restore, credential
  revocation, and account repair from the operator console.

## Which key you hold

The one thing to internalize before running Custos: you hold the **second**
rotation key, not the first.

```text
rotationKeys[0]  →  the user's device key   (higher precedence)
rotationKeys[1]  →  the server's key        (yours, lower precedence)
```

The user can always override you. That is by design: it is what lets a user
leave your server without your permission, and it is the property that makes
hosting trustworthy rather than custodial.
