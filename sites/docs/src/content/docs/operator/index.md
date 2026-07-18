---
title: Running Custos
description: The operator's view — what Custos runs and how to run it.
---

Custos is the server side: the PDS that hosts identities and the operator console
that manages it. This surface reports the literal truth of what the machine is
doing — it does not hide the machinery.

If you are _using_ an identity rather than running a server, you want
[Using Obsign](/user/) instead.

<figure>
  <img src="/screenshots/admin/home.png" alt="Custos operator console home screen for minting a device-signed account claim code" width="280" />
  <figcaption>The operator console — minting a device-signed claim code for the active relay. See every console screen in the <a href="/operator/screens/">tour</a>.</figcaption>
</figure>

## What you run

- **[Running a relay](/operator/running-a-relay/)** — stand up the PDS, its
  health, and what you are (and aren't) responsible for.
- **[Configuration](/operator/configuration/)** — the config and environment
  surface that tunes a deployment.
- **[Moderation](/operator/moderation/)** — takedown, restore, credential
  revocation, and account repair from the operator console.
- **[Master-key disaster runbook](/operator/master-key-runbook/)** — what to
  do if the KEK is lost or compromised.

## Which key you hold

The one thing to internalize before running Custos: you hold the **last**
rotation key, not the first.

```text
rotationKeys[0]  →  the user's device key     (highest precedence)
rotationKeys[1]  →  the user's recovery key   (from their 2-of-3 backup)
rotationKeys[2]  →  the server's key          (yours, lowest precedence)
```

Accounts created before on-device recovery keys carry two entries — the user's
device key, then yours — until their wallet adds the recovery key; your key is
last either way. The user can always override you. That is by design: it is what lets a user
leave your server without your permission, and it is the property that makes
hosting trustworthy rather than custodial.
