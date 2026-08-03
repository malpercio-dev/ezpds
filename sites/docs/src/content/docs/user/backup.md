---
title: 2-of-3 Shamir backup
description: Split your recovery secret so no single lost device can lock you out.
---

Obsign backs up your recovery secret using **Shamir's Secret Sharing**, split
2-of-3: three shares are created, and any **two** of them reconstruct the
secret. No single share reveals anything on its own.

## Why 2-of-3

- **Lose one share** (a stolen phone, a wiped laptop) and you can still recover
  with the remaining two.
- **A single leaked share is useless.** One share alone cannot reconstruct
  anything.

The split balances the two ways a backup can fail: one lost device locking you
out forever, and one leaked secret being game over.

## Where the three shares live

Backup is built into creating your identity; there is no separate menu option
to turn it on. Right after your identity is created, Obsign shows the
**Back up your recovery key** step, and the three shares already have their
homes:

- **Share 1 of 3** is saved automatically to your device's **Keychain** and
  marked for **iCloud Keychain** sync, so it can reach your other Apple
  devices. Obsign can confirm it wrote the share; only Apple can deliver it,
  and with iCloud Keychain switched off it stays on this device.
- **Share 2 of 3** is held in your **server's escrow**.
- **Share 3 of 3** is **yours to save**. Obsign shows it as a numbered
  **word phrase** (with a QR form for machines) and a Copy button; keep it
  somewhere durable.

The split happens **on your device**: your phone generates the recovery secret
and hands the server Share 2 and nothing else. No server database, and no
backup of one, can ever reconstruct your secret.

You confirm you've saved Share 3 before you can continue. Obsign already holds
two shares for you (one in this device's Keychain, one in your server's
escrow), so saving Share 3 anywhere independent of your phone gives you a
second, self-controlled path back in.

:::tip[Good homes for Share 3]
Save it to a password manager (1Password, Bitwarden, …), print it and store it
somewhere safe, or write it down and keep it **separate from your device**. Do
not leave it only on the phone that also holds Share 1.
:::

## Recovering with two shares

Lost the phone entirely? On a new device, choose **I lost access to my wallet**
on Obsign's first screen. Any two of your three shares bring the identity back:

- **The common path.** Share 1 loads automatically if iCloud Keychain carried
  it to the new device, and Obsign asks your server to release its escrowed
  Share 2. The release is slow on purpose: a single-use code is emailed to your
  account address, and after you enter it the share stays **pending for a delay
  window** before it can be collected. The wait is shown in the app, and a
  pending release can be cancelled, so a stolen mailbox alone cannot quietly
  drain your escrow.
- **The sovereign path.** Share 1 plus the Share 3 word phrase you saved. This
  path reconstructs everything locally and asks your server for nothing.
- **Share 2 + Share 3.** The escrowed share plus your word phrase. This works
  with no Share 1 at all, which is why saving Share 3 is not optional.

:::caution[When Share 1 won't be waiting for you]
Obsign marks Share 1 for iCloud Keychain sync, but it cannot see whether Apple
delivered it. Two cases leave a new device without it:

- **iCloud Keychain is switched off** on your Apple account. Turning it on
  later lets the share sync with no further action in Obsign, but only from a
  device that still holds it.
- **The identity was set up by an older version of Obsign**, which kept Share 1
  on a single device. Updating and opening the app on a device that still holds
  that share fixes it from then on. If that device is already gone, nothing can
  reach back and repair it; that identity stays on Share 2 + Share 3 for good.

In both cases your saved Share 3 is the way back in.
:::

Obsign verifies the reconstructed key against your identity's public record
before anything is allowed to sign, and tells you in plain words if a share is
corrupted or belongs to an older backup generation.

Recovery always ends with a **rotation**: the recovered identity gets a fresh
recovery secret and a fresh set of three shares, so every share the lost device
ever touched is void. Saving the new Share 3 is part of finishing, and the
rotation resumes where it left off if it's interrupted.

:::note[Created your identity a while ago?]
Identities created before on-device recovery keys show a calm **Add a recovery
key** prompt on the home screen. Accepting it re-runs the split with your
device doing the generating (the server receives only Share 2) and walks you
through saving a new Share 3. Every step is additive and resumable; your device
key never moves, so an interrupted upgrade never leaves you worse off than
before.
:::

Your other safety net is unchanged: because your device key sits at the top of
your identity's key list, you can
[override an unexpected change](/user/recovery/) within a 72-hour window
without reassembling any shares.

:::note[This page describes did:plc identities]
The 2-of-3 split backs the recovery key of a **did:plc** identity — the
default. A
[did:web identity](/user/getting-started/#advanced-anchor-your-identity-to-a-domain-you-own-didweb)
carries no shares and no escrow; its recovery model is control of its domain.
:::
