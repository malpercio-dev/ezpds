---
title: Console screens
description: A visual tour of the Custos operator console — claim codes, accounts, devices, moderation, transfers, and server status.
---

A tour of the Custos operator console (the admin companion app). Every image here is
generated automatically from the app's own browser test harness across named scenarios,
including a degraded relay, so the pictures track the real UI and cannot quietly drift.

:::note[These are browser renders, not device captures]
These screenshots come from running the app frontend in a browser (the test harness),
not from an iPhone. Layout, copy, and states are faithful, but device-only details are
**not** pictured: the biometric (Face ID / Touch ID) gate that precedes every signing
action, the Secure Enclave-held admin key, camera QR scanning on the Pair screen, the
system share sheet, and iOS safe-area insets and font rendering. Treat these as accurate
diagrams, not pixel-exact device photos.
:::

## Home — mint a claim code

The console opens on the active relay, ready to mint a single-use, device-signed account
claim code.

![Custos console home screen for minting an account claim code](/screenshots/admin/home.png)

Before any relay is paired, the console asks you to pair this operator device.

![Custos console home screen before pairing, offering "Pair this device"](/screenshots/admin/home-unpaired.png)

## Pairing

Pair a device with a relay by QR or manual entry.

![Custos console pair screen with QR and manual entry](/screenshots/admin/pair.png)

## Accounts

Every account on one relay, searchable by handle or DID, with a per-row blob-quota
readout.

![Custos console accounts list with search and per-row quota bars](/screenshots/admin/accounts.png)

## Claim codes

The claim-code inventory splits live credentials from terminal history.

![Custos console claim-code inventory](/screenshots/admin/codes.png)

## Devices

Every admin device registered on one relay — active and revoked — with a remote revoke
for a lost device.

![Custos console devices list with remote revoke](/screenshots/admin/devices.png)

## Moderation

Account takedown and restore, then credential revocation — each an armed, biometric-gated
destructive action.

![Custos console moderation screen for account takedown and restore](/screenshots/admin/moderation.png)

## Transfers

In-flight device transfers an operator can watch and cancel.

![Custos console transfers list](/screenshots/admin/transfers.png)

## Server status

One relay's health as it reports it — version and uptime, account counts, blob and block
totals, firehose state, and background-sweep last-runs. Facts only; nothing here is a
verdict.

![Custos console server status readout](/screenshots/admin/status.png)

On a degraded relay, stale background sweeps are flagged with a trailing glyph — status is
never signalled by colour alone.

![Custos console server status for a degraded relay with stale-sweep glyphs](/screenshots/admin/status-degraded.png)

## Settings

Per-relay pairings, the global admin key, and the biometric toggle.

![Custos console settings with per-relay pairings](/screenshots/admin/settings.png)
