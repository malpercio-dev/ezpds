---
title: 2-of-3 Shamir backup
description: Split your recovery secret so no single lost device can lock you out.
---

Obsign backs up your recovery secret using **Shamir's Secret Sharing**, split
2-of-3: three shares are created, and any **two** of them reconstruct the secret.
No single share reveals anything on its own.

## Why 2-of-3

- **Lose one share** — a stolen phone, a wiped laptop — and you can still recover
  with the remaining two.
- **A single leaked share is useless** — one share alone cannot reconstruct
  anything.

It is the balance between "one lost device locks me out forever" and "one leaked
secret is game over."

## Setting it up

1. In Obsign, choose **Set up recovery**.
2. Obsign generates three shares on your device.
3. Distribute them to places that will not all fail together — for example your
   device keychain, a trusted person, and offline storage.

:::caution[Do not co-locate shares]
Two shares in the same place is the same as one share for a thief and one point
of failure for you. Spread them across independent failure domains.
:::

## Recovering with two shares

When you need to recover, bring any two shares back together in Obsign. It
reconstructs the secret **on your device** and re-seals your identity key locally.
The shares never travel to a server.

:::tip
Test recovery once, deliberately, before you are relying on it — the same way you
would test a fire alarm rather than assume it works.
:::
