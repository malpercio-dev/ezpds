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
- **Share 3 of 3** — **you** save this one. Obsign shows it as a numbered
  **word phrase** (with a QR form for machines) and a Copy button; keep it
  somewhere durable.

The split happens **on your device**: your phone generates the recovery secret
and hands the server Share 2 and nothing else, so no server database — and no
backup of one — can ever reconstruct your secret.

You confirm you've saved Share 3 before you can continue. Obsign already holds two
shares for you (iCloud + your server), so saving Share 3 anywhere independent of
your phone gives you a second, self-controlled path back in.

:::tip[Good homes for Share 3]
Save it to a password manager (1Password, Bitwarden, …), print it and store it
somewhere safe, or write it down and keep it **separate from your device**. Do not
leave it only on the phone that also holds Share 1.
:::

## Recovering with two shares

Lost the phone entirely? On a new device, choose **Recover from backup shares**
on Obsign's first screen. Any two of your three shares bring the identity back:

- **The common path** — your iCloud Share 1 loads automatically, and Obsign asks
  your server to release its escrowed Share 2. The release is deliberately slow:
  a single-use code is emailed to your account address, and after you enter it
  the share stays **pending for a delay window** before it can be collected. The
  wait is shown honestly, and a pending release can be cancelled — so a stolen
  mailbox alone cannot quietly drain your escrow.
- **The sovereign path** — your iCloud Share 1 plus the Share 3 word phrase you
  saved. This path reconstructs everything locally and asks your server for
  nothing.

Obsign verifies the reconstructed key against your identity's public record
before anything is allowed to sign, and tells you in plain words if a share is
corrupted or belongs to an older backup generation.

Recovery always ends with a **rotation**: the recovered identity gets a fresh
recovery secret and a fresh set of three shares, so every share the lost device
ever touched is void. Saving the new Share 3 is part of finishing, and the
rotation resumes where it left off if it's interrupted.

:::note[Created your identity a while ago?]
Identities created before on-device recovery keys show a calm **Add a recovery
key** prompt on the home screen. Accepting it re-runs the split with your device
doing the generating — the server receives only Share 2 — and walks you through
saving a new Share 3. Every step is additive and resumable; your device key
never moves, so an interrupted upgrade never leaves you worse off than before.
:::

Your other safety net is unchanged: because your identity key sits on your
device as the highest-priority key, you can
[override an unexpected change](/user/recovery/) within a 72-hour window without
reassembling any shares.

:::note[This page describes did:plc identities]
The 2-of-3 split backs the recovery key of a **did:plc** identity — the default.
A [did:web identity](/user/getting-started/#advanced-anchor-to-a-domain-you-control-didweb)
carries no shares and no escrow; its recovery model is control of its domain.
:::
