---
title: Moderation
description: Takedown, restore, credential revocation, and account repair from the operator console.
---

The operator console (the "Brass Console" companion app) exposes the moderation
actions an operator needs. Every action reports exactly what it did — the console
does not soften or hide the effect.

## Actions

<figure>
  <img src="/screenshots/admin/moderation.png" alt="Custos operator console moderation screen with a DID lookup, account status panel, and armed takedown/restore and credential-revocation actions" width="280" />
  <figcaption>The Moderation screen: look up an account, then arm a takedown/restore or credential sweep behind a two-tap confirmation and a biometric gate.</figcaption>
</figure>

On the **Moderation** screen (look up an account by DID first):

- **Takedown** — stop serving an account: logins, writes, and sync are refused
  until it is restored.
- **Restore** — reverse a takedown (the account resumes serving unless it is also
  suspended or deactivated).
- **Credential revocation** — the incident-response follow-up for a compromised
  account: in one sweep it revokes the account's **sessions, app passwords, OAuth
  grants and pending authorization codes, and transfer-device tokens**, and reports
  the literal per-family counts. The account's **main password is untouched**, and
  any already-issued access tokens lapse on their own within minutes. Every holder
  — including the owner — is signed out and must log in again.

You reach an account by tapping it in the account list, which is searchable by
handle or DID and shows each account's blob quota.

<figure>
  <img src="/screenshots/admin/accounts.png" alt="Custos operator console accounts list, searchable by handle or DID, with lifecycle filter chips and per-row blob quota bars" width="280" />
  <figcaption>The account list — search, lifecycle filters, and a per-row blob-quota readout. Tapping a row opens Account detail.</figcaption>
</figure>

On the **Account detail** screen (reached by tapping an account in the list):

- **Correct an email** — fix an account's email address; this resets it to
  unconfirmed.
- **Issue a password-reset token** — mint a single-use, one-hour reset token for
  out-of-band delivery. This is **refused for a passwordless / key-sovereign
  account** — those recover through their escrowed key share, not a reset.

Both takedown and credential revocation are destructive, so the console arms them
behind a two-tap confirmation that restates the target, then a biometric gate,
before anything is signed.

:::caution[Takedown is server-scoped, not identity-scoped]
A takedown affects what _your_ server serves. Because the user holds
`rotationKeys[0]`, they can migrate their identity elsewhere. Moderation is your
control over your infrastructure, not custody over their identity — keep that
distinction clear when you communicate an action.
:::

## Labeler watching — flagged accounts

Custos can watch ATProto **labelers** (moderation services) and flag any hosted
account they label. Flagged accounts float to the top of the console's account
list with an explicit `⚑` indicator per label — the label value, the labeler,
and when it was applied — and the Home screen shows a flagged-accounts notice
for the active server. This turns the account list from a neutral roster into a
spam/abuse triage view: if a labeler your network trusts flags one of your
accounts, you see it on your next glance at the console.

Watching is **off by default** — you choose which labelers' judgment reorders
your console. The recommended starting point is Bluesky's moderation service:

```bash
# Environment form: comma-separated labeler DIDs, each watching every label value.
EZPDS_LABELER_WATCHED=did:plc:ar7c4by46qjdydhdevvrndac
```

or, in `pds.toml`, with an optional per-labeler watchlist (empty or omitted
`labels` means every label from that labeler counts):

```toml
[labeler]
poll_interval_secs = 900 # default: 15 minutes

[[labeler.watched]]
did = "did:plc:ar7c4by46qjdydhdevvrndac" # Bluesky Moderation
labels = ["spam", "!hide", "!warn"]      # omit to watch every label

[[labeler.watched]]
did = "did:web:some-other-labeler.example" # any labeler works, not just Bluesky's
```

How it works: a background pass polls each watched labeler's
`com.atproto.label.queryLabels` for your hosted accounts (the labeler's query
endpoint is resolved from its DID document), honoring label negations and
expiry, and reconciles the flagged state the console reads. The first pass runs
at startup, then every `poll_interval_secs`. The health readout reports the
watcher's last completed pass, so a stale pass is visible on the Status screen.

Two things worth knowing before you enable it:

- **Each poll discloses your hosted-account DIDs to the watched labeler** (they
  arrive as the query's `uriPatterns`). Hosted DIDs are already publicly
  enumerable via `com.atproto.sync.listRepos`, but watching a labeler does
  establish a recurring outbound relationship with it — which is why this is an
  explicit opt-in rather than a default.
- **A flag is the labeler's opinion, not a verdict.** Flagging changes only the
  sort order and the indicator; it takes no action against the account. Takedown
  and credential revocation remain your deliberate, gated decisions above.

Removing a labeler from the config (or disabling watching entirely) clears its
flags on the next pass or restart — flagged state never outlives the
configuration that produced it.

## Accountability

Moderation actions are shown with their subject, the operator device that signed
them, and the result — status carried in text, not by color alone. Pair any
externally visible action with a clear, honest explanation to the affected user;
the tooling reports the literal truth, and so should you.

:::note[Per-device operator keys]
Operator actions are signed by a per-device key (Secure-Enclave-backed on real
devices). Revoking a device revokes its ability to act, per relay, without
disturbing the others.
:::
