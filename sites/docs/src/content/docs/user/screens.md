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

![Obsign welcome screen with "Add an identity" and "Move an identity" options](/screenshots/wallet/welcome.png)

## Your identities

The home surface lists your seals with tamper monitoring shown live at the top.

![Obsign home screen showing one identity and an "All identities secure" banner](/screenshots/wallet/home.png)

A single wallet can hold several identities; the root-key badge is tracked per identity.

![Obsign home screen with two identities, one marked "Root key" and one "Not root"](/screenshots/wallet/home-multi.png)

Tapping an identity opens its DID document, decoded.

![Obsign identity detail showing the decoded DID document](/screenshots/wallet/identity-detail.png)

## Agents

Agents you have authorised to act on your behalf are listed under **My agents**, each
with its permissions and full activity record.

![Obsign "My agents" screen showing a connected agent](/screenshots/wallet/agents.png)

## Settings

![Obsign settings screen with the appearance control](/screenshots/wallet/settings.png)

## When something is wrong

If Obsign detects an unauthorised change to your identity's public record, the home
surface raises an alert — status is always shown with text and an icon, never colour
alone.

![Obsign home screen showing a tamper alert banner](/screenshots/wallet/home-alert.png)

Opening the alert shows the change and a live countdown of the 72-hour recovery window.

![Obsign alert detail with a recovery-window countdown](/screenshots/wallet/alert-detail.png)

Local failures are surfaced inline with a way to retry, never a dead end.

![Obsign home screen showing an inline "Failed to load identities" error with a Try again button](/screenshots/wallet/home-load-error.png)
