---
title: Master-key disaster runbook
description: What to do if the KEK is lost or compromised — the incident procedure for operators.
---

`EZPDS_SIGNING_KEY_MASTER_KEY` is the key-encryption key (KEK): a 32-byte
AES-256-GCM key, supplied env-only, that wraps every at-rest secret in the PDS
database — most importantly each account's repo signing key, the one that
signs every commit. See [Configuration](/operator/configuration/) for how it's
provisioned and rotated day to day. This page is the incident checklist for
when something goes wrong with it.

## What the key protects

| Secret | Self-heals? | Recovery if the KEK is gone |
| --- | --- | --- |
| Per-account repo signing keys | No | **Hard** — wallet-driven rotation |
| Operator-level (legacy) commit-signing keys | No | **Hard** — same path |
| OAuth signing key, JWT secret, Iroh node key | Yes | Drop the row; re-mints on boot |
| PDS-held Shamir recovery share (Share 2 of 3) | No | **Hard** — needs the original KEK |

The three self-healing secrets cost little to lose: delete the row and the
server mints a fresh one under the current KEK on next boot (sessions
re-auth; the Iroh node id changes and devices re-resolve it). **The
commit-signing keys are the entire difficulty** in both scenarios below,
because each one is published in an account's DID document and can only be
replaced by a PLC operation signed by a *current* rotation key — the PDS
cannot silently swap one out from under a user.

## Golden rule (prevention)

**Back up the KEK as carefully as the database, and store it separately from
the DB backup.** A KEK backed up next to your [Litestream replica](/operator/backups/)
gives an attacker who reaches that one location both halves — the ciphertext
and the key that decrypts it — which defeats at-rest encryption entirely.
Store the KEK in a secrets manager or offline vault distinct from where the
database backup lives. This single practice turns Scenario 1 below from
catastrophic into a non-event.

---

## Scenario 1 — KEK lost (never exposed)

**Symptom:** after a redeploy or environment change, the server won't boot —
it hard-errors that encrypted material exists in the database but the key to
decrypt it is gone.

### 1.1 First: is it actually lost?

Check the secrets manager or vault backup (per the golden rule). If the KEK
is recoverable, restore the environment variable and boot normally — **stop
here**, this is a misplaced env var, not a disaster. Only proceed if the KEK
is genuinely unrecoverable.

### 1.2 If genuinely lost

1. **Set a fresh KEK.**
2. **Self-healing secrets** — with the database and the new KEK in place,
   delete the OAuth signing key, JWT secret, and Iroh identity rows and boot.
   Each regenerates under the new KEK automatically.
3. **Commit-signing keys — permanently undecryptable.** The old ciphertext
   can no longer be read, so the server can no longer sign commits under the
   published verification method. There is no server-side fix. Each affected
   account must go through **wallet-driven repo-key rotation**
   (`POST /v1/repo-keys/rotation` + `/complete`): the server generates a fresh
   repo key, the account's wallet signs a PLC operation repointing the
   signing verification method and the server's rotation key, and the server
   cuts over. Prioritize active accounts.
4. **Escrowed Shamir shares — also permanently undecryptable.** There is no
   server-side re-mint, because a replacement wouldn't be one of the shares
   already issued to the user. Recovery must fall back to the user's other
   two shares.

:::note[Takeaway]
A lost KEK is nearly as bad as a compromised one, purely because of the repo
keys — loss and compromise share the same hard recovery path (per-account
wallet-driven rotation).
:::

---

## Scenario 2 — KEK compromised (assume the DB was exposed too)

**Threat assumption:** if the KEK leaked, assume the attacker also has, or
can get, a copy of the database. Treat every KEK-wrapped secret as
plaintext-known to the attacker. Re-wrapping under a new KEK is necessary
hygiene but does **not** by itself contain the compromise — the underlying
keys must be rotated too, not just re-encrypted.

### 2.1 Contain the environment-variable blast radius first

Whatever exposed the KEK (leaked deployment variables, dashboard access, a
leaked deploy log) almost certainly exposed the other env secrets. Rotate
all of them, most-urgent first:

1. **`EZPDS_ADMIN_TOKEN`** — the break-glass bearer credential; rotate
   immediately, it gates admin, moderation, and device routes.
2. SMTP / mail-provider tokens.
3. Any other deployment secrets in the same store.
4. Investigate the exposure vector and revoke the access path (rotate
   deployment-platform credentials, audit who or what could read the
   environment).

### 2.2 New KEK, then re-wrap

Generate a fresh KEK. Use the offline `pds rewrap-master-key` subcommand
(see [Configuration](/operator/configuration/)) to re-encrypt the surviving
blobs under it, then drop and re-mint the self-healing secrets (next step).
This protects the database at rest under a key the attacker doesn't have,
going forward.

### 2.3 Rotate the self-healing secrets

Delete the OAuth signing key, JWT secret, and Iroh identity rows and let the
server re-mint them under the new KEK on boot. This invalidates any
access/refresh tokens the attacker could have forged with the leaked keys —
users re-auth, devices re-resolve the node id.

### 2.4 Rotate the commit-signing keys — the hard part

The server **cannot** do this unilaterally: doing so would require signing
the rotation with the very key that's compromised. Recovery is
wallet-driven and per-account — the user's wallet holds the
higher-precedence rotation key and signs a PLC operation rotating the
signing verification method and the server's rotation key to a fresh
server-generated one, via `POST /v1/repo-keys/rotation`. Prioritize active
accounts; for a mass event, each wallet must still sign individually.

A malicious party holding the compromised server-side rotation key can sign
bad commits and lower-priority PLC operations, but **cannot** move the
identity away from the user — the wallet's higher-precedence key outranks it
and can override within the identity directory's recovery window. The repo
is self-certifying, so the identity itself is never lost; the commit-signing
key is what must be rotated.

---

## Quick reference — ordering

**Loss:** verify backup → (if recoverable) restore & boot, done → else: new KEK →
drop + re-mint easy secrets → per-account wallet-driven repo-key rotation.

**Compromise:** rotate `EZPDS_ADMIN_TOKEN` + mail tokens + env access → new KEK +
`pds rewrap-master-key` → drop + re-mint easy secrets → per-account wallet-driven
repo-key rotation.

---

:::note[Looking for source-level detail?]
This page is the operator-facing procedure. The engineering version — table
and migration names, source file references, and the escrow-share model in
full — lives in the repository at
[`docs/operations/master-key-disaster-runbook.md`](https://github.com/malpercio-dev/ezpds/blob/main/docs/operations/master-key-disaster-runbook.md).
The golden rule and the quick-reference ordering above are kept identical
between the two copies; `just runbook-parity-check` fails CI if they drift.
:::
