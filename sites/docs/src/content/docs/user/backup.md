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

## Where the three shares live

Backup is **built into creating your identity** — there is no separate menu
option to turn it on. Right after your identity is created, Obsign shows the
**Back up your recovery key** step, and the three shares already have their homes:

- **Share 1 of 3** — saved to your **iCloud Keychain** automatically.
- **Share 2 of 3** — held in your **server's escrow**.
- **Share 3 of 3** — **you** save this one. Obsign shows it as text and a QR code
  with a Copy button; keep it somewhere durable.

You confirm you've saved Share 3 before you can continue. Obsign already holds two
shares for you (iCloud + your server), so saving Share 3 anywhere independent of
your phone gives you a second, self-controlled path back in.

:::tip[Good homes for Share 3]
Save it to a password manager (1Password, Bitwarden, …), print it and store it
somewhere safe, or write it down and keep it **separate from your device**. Do not
leave it only on the phone that also holds Share 1.
:::

## Recovering with two shares

When you need to recover, Obsign brings any two shares back together and
reconstructs the recovery key **on your device**. In the common case that means
your iCloud Share 1 plus either your server's Share 2 or the Share 3 you saved —
any two of the three is enough, and no single share ever reveals anything on its
own.
