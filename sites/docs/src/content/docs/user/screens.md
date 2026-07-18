---
title: Screens
description: A visual tour of Obsign — the home surface, identity detail, recovering from backup shares, app passwords, agents, settings, and what a tamper alert looks like.
---

A tour of the Obsign app. Every image here is generated automatically from the app's
own browser test harness across named scenarios, so the pictures track the real UI and
cannot quietly go stale.

:::note[These are browser renders, not device captures]
These screenshots come from running the app frontend in a browser (the test harness),
not from an iPhone. They faithfully show layout, copy, and states, but a few things only
exist on a real device and are **not** pictured: Face ID / Touch ID prompts, the
Keychain / Secure Enclave, the system share sheet, and the exact safe-area insets and
font rendering of iOS. Treat these as accurate diagrams of each screen, not pixel-exact
device photos.
:::

## Getting started

The first launch offers to create a new identity, move an existing one in, or
recover one from its backup shares.

<figure>
  <img src="/screenshots/wallet/welcome.png" alt="Obsign welcome screen with 'Add an identity', 'Move an identity', and 'Recover from backup shares' options" width="280" />
  <figcaption>First launch: create a new identity, move one you already have, or recover from backup shares.</figcaption>
</figure>

## Recovering from backup shares

If your phone is lost, any two of your three backup shares can bring your identity to a
new device. Recovery starts from your handle or DID; Share 1 is loaded automatically when
your iCloud Keychain carried it to the new phone.

<figure>
  <img src="/screenshots/wallet/recover-start.png" alt="Obsign recovery start screen with a looked-up identity and Share 1 found on the device" width="280" />
  <figcaption>Recovery starts from a handle or DID; Share 1 auto-loads from the iCloud Keychain when present.</figcaption>
</figure>

With one share in hand, the second can come from your server's escrow (released with an
emailed code) or from the word-phrase backup you saved.

<figure>
  <img src="/screenshots/wallet/recover-shares.png" alt="Obsign share-collection screen showing one of two shares collected, with escrow and manual-entry options" width="280" />
  <figcaption>Collecting two of three shares: ask the server for its escrow share, or enter a saved one.</figcaption>
</figure>

A server can hold the escrow share for a waiting period before handing it over. The delay
is a protection — anyone still signed in to your account can stop a release they didn't
ask for, and the wait continues on the server even if you close the app.

<figure>
  <img src="/screenshots/wallet/recover-escrow-pending.png" alt="Obsign escrow release wait screen showing when the share becomes available and a 'Check again' button" width="280" />
  <figcaption>The escrow waiting period — a release you didn't ask for can be cancelled from any signed-in device.</figcaption>
</figure>

## Your identities

The home surface lists your seals with tamper monitoring shown live at the top.

<figure>
  <img src="/screenshots/wallet/home.png" alt="Obsign home screen showing one identity and an 'All identities secure' banner" width="280" />
  <figcaption>The home surface, with monitoring shown live at the top.</figcaption>
</figure>

A single wallet can hold several identities; the root-key badge is tracked per identity.

<figure>
  <img src="/screenshots/wallet/home-multi.png" alt="Obsign home screen with two identities, one marked 'Root key' and one 'Not root'" width="280" />
  <figcaption>Several identities in one wallet; the root-key badge is per identity.</figcaption>
</figure>

Tapping an identity opens its DID document, decoded. A current-model identity carries
three rotation keys — your device key, your recovery key, and the server's key.

<figure>
  <img src="/screenshots/wallet/identity-detail.png" alt="Obsign identity detail showing the decoded DID document with three rotation keys" width="280" />
  <figcaption>An identity's DID document — identifier, handle, all three rotation keys (device, recovery, PDS), services.</figcaption>
</figure>

An identity created before the recovery-key model was introduced is offered a calm,
one-tap upgrade on the home surface — an improvement, not an alarm.

<figure>
  <img src="/screenshots/wallet/home-rekey.png" alt="Obsign home screen showing an 'Add a recovery key' prompt beneath an identity card" width="280" />
  <figcaption>An older identity without a recovery key is offered the upgrade in place.</figcaption>
</figure>

## Signing in to other apps

App passwords are separate, revocable credentials for signing the official Bluesky app —
or any app that asks for a password — into your account without ever exposing your keys.
Direct-message access is off unless you allow it per credential.

<figure>
  <img src="/screenshots/wallet/app-passwords.png" alt="Obsign app-passwords screen with a create form and two active credentials, one marked 'DMs allowed'" width="280" />
  <figcaption>App passwords: what they can and cannot do, and each active credential with its own revoke.</figcaption>
</figure>

## Agents

Agents you have authorised to act on your behalf are listed under **My agents**, each
with its permissions and full activity record.

<figure>
  <img src="/screenshots/wallet/agents.png" alt="Obsign 'My agents' screen showing a connected agent" width="280" />
  <figcaption>The agents you've approved, with their permissions and activity record.</figcaption>
</figure>

## Settings

<figure>
  <img src="/screenshots/wallet/settings.png" alt="Obsign settings screen with the appearance control" width="280" />
  <figcaption>Appearance and app settings.</figcaption>
</figure>

## When something is wrong

If Obsign detects an unauthorised change to your identity's public record, the home
surface raises an alert — status is always shown with text and an icon, never colour
alone.

<figure>
  <img src="/screenshots/wallet/home-alert.png" alt="Obsign home screen showing a tamper alert banner" width="280" />
  <figcaption>A tamper alert on the home surface — text and icon, not colour alone.</figcaption>
</figure>

Opening the alert shows the change and a live countdown of the 72-hour recovery window.

<figure>
  <img src="/screenshots/wallet/alert-detail.png" alt="Obsign alert detail with a recovery-window countdown" width="280" />
  <figcaption>The alert detail, with a live recovery-window countdown.</figcaption>
</figure>

Local failures are surfaced inline with a way to retry, never a dead end.

<figure>
  <img src="/screenshots/wallet/home-load-error.png" alt="Obsign home screen showing an inline 'Failed to load identities' error with a Try again button" width="280" />
  <figcaption>An injected local failure surfaces inline with a retry, never a dead end.</figcaption>
</figure>
