---
title: Console screens
description: A visual tour of the Custos operator console — claim codes, accounts, devices, moderation, the audit log, transfers, and server status.
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

<figure>
  <img src="/screenshots/admin/home.png" alt="Custos console home screen for minting an account claim code" width="280" />
  <figcaption>Mint a single-use, device-signed account claim code for the active relay.</figcaption>
</figure>

Before any relay is paired, the console asks you to pair this operator device.

<figure>
  <img src="/screenshots/admin/home-unpaired.png" alt="Custos console home screen before pairing, offering 'Pair this device'" width="280" />
  <figcaption>Before pairing: no relay is bound to this operator device yet.</figcaption>
</figure>

## Pairing

Pair a device with a relay by QR or manual entry.

<figure>
  <img src="/screenshots/admin/pair.png" alt="Custos console pair screen with QR and manual entry" width="280" />
  <figcaption>Pair with a relay by QR or manual entry.</figcaption>
</figure>

## Accounts

Every account on one relay, searchable by handle or DID, with a per-row blob-quota
readout.

<figure>
  <img src="/screenshots/admin/accounts.png" alt="Custos console accounts list with search and per-row quota bars" width="280" />
  <figcaption>Every account on one relay, searchable, with per-row blob quota.</figcaption>
</figure>

## Claim codes

The claim-code inventory splits live credentials from terminal history.

<figure>
  <img src="/screenshots/admin/codes.png" alt="Custos console claim-code inventory" width="280" />
  <figcaption>Outstanding claim codes and their terminal history.</figcaption>
</figure>

## Devices

Every admin device registered on one relay — active and revoked — with a remote revoke
for a lost device.

<figure>
  <img src="/screenshots/admin/devices.png" alt="Custos console devices list with remote revoke" width="280" />
  <figcaption>Admin devices on one relay, with remote revoke for a lost device.</figcaption>
</figure>

## Moderation

Account takedown and restore, then credential revocation — each an armed, biometric-gated
destructive action.

<figure>
  <img src="/screenshots/admin/moderation.png" alt="Custos console moderation screen for account takedown and restore" width="280" />
  <figcaption>Account takedown/restore and credential revocation, each armed and gated.</figcaption>
</figure>

## Audit log

The server-wide admin audit log: every privileged action — takedowns, credential sweeps,
code mints and revokes, device pairings and revocations — newest first, each attributed to
the credential that signed it, with action-word filters and per-event drill-in.

<figure>
  <img src="/screenshots/admin/audit.png" alt="Custos console audit log listing admin actions with action filters and outcome chips" width="280" />
  <figcaption>Every privileged admin action, newest first, attributed to the credential that signed it.</figcaption>
</figure>

## Transfers

In-flight device transfers an operator can watch and cancel.

<figure>
  <img src="/screenshots/admin/transfers.png" alt="Custos console transfers list" width="280" />
  <figcaption>In-flight device transfers an operator can watch and cancel.</figcaption>
</figure>

## Server status

One relay's health as it reports it — version and uptime, account counts, blob and block
totals, firehose state, and background-sweep last-runs. Facts only; nothing here is a
verdict.

<figure>
  <img src="/screenshots/admin/status.png" alt="Custos console server status readout" width="280" />
  <figcaption>One relay's health as it reports it — facts only.</figcaption>
</figure>

On a degraded relay, stale background sweeps are flagged with a trailing glyph — status is
never signalled by colour alone.

<figure>
  <img src="/screenshots/admin/status-degraded.png" alt="Custos console server status for a degraded relay with stale-sweep glyphs" width="280" />
  <figcaption>A degraded relay: stale sweeps flagged by glyph, never colour alone.</figcaption>
</figure>

## Settings

Per-relay pairings, the global admin key, and the biometric toggle.

<figure>
  <img src="/screenshots/admin/settings.png" alt="Custos console settings with per-relay pairings" width="280" />
  <figcaption>Per-relay pairings, the global admin key, and the biometric toggle.</figcaption>
</figure>
