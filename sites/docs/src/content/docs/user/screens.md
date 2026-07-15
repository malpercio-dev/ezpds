---
title: Screens
description: A visual tour of Obsign — the home surface, identity detail, agents, settings, and what a tamper alert looks like.
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

The first launch offers to create a new identity or move an existing one in.

<figure>
  <img src="/screenshots/wallet/welcome.png" alt="Obsign welcome screen with 'Add an identity' and 'Move an identity' options" width="280" />
  <figcaption>First launch: create a new identity, or move one you already have.</figcaption>
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

Tapping an identity opens its DID document, decoded.

<figure>
  <img src="/screenshots/wallet/identity-detail.png" alt="Obsign identity detail showing the decoded DID document" width="280" />
  <figcaption>An identity's DID document — identifier, handle, verification keys, services.</figcaption>
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
