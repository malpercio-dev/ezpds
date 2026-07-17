# Master-Key (KEK) Disaster Runbook — Loss & Compromise

Last verified: 2026-07-17

Operator runbook for the two disaster scenarios involving
`EZPDS_SIGNING_KEY_MASTER_KEY` — the key-encryption key (KEK) that wraps every
at-rest secret in the PDS SQLite database. Prevention guidance and a short
summary live in
[deploy.md → Master-Key (KEK) Backup and Disaster Recovery](../deploy.md#master-key-kek-backup-and-disaster-recovery);
this is the full incident checklist with concrete step ordering.

`EZPDS_SIGNING_KEY_MASTER_KEY` is a 32-byte AES-256-GCM key, supplied **env-only**
(64 hex chars). Setting it in a TOML config file is deliberately rejected — a
sentinel field in [`crates/common/src/config.rs`](../../crates/common/src/config.rs)
(`signing_key_master_key_toml_sentinel`) fails startup if the key appears in
TOML, so it can only arrive via the `EZPDS_SIGNING_KEY_MASTER_KEY` environment
variable.

## What the KEK wraps

The authoritative inventory is `SecretFamily::ALL` in
[`crates/pds/src/db/kek.rs`](../../crates/pds/src/db/kek.rs) — the single list the
re-wrap tool iterates. There are **seven** KEK-wrapped families:

| Secret | Table(s) / column | Migration | Recovery class |
| -- | -- | -- | -- |
| **Per-account repo signing key** (`verificationMethods.atproto` / `rotationKeys[1]`, signs every commit) | `signing_keys` | V002 (+ `status`, V048) | **Hard** — wallet-signed PLC op |
| Pre-reserved repo signing keys | `reserved_signing_keys` | V032 | **Hard** — same path once in use |
| Repo signing keys for not-yet-activated accounts | `pending_accounts.repo_signing_private_key_encrypted` | V019 | **Hard** — same path once activated |
| Operator-level commit-signing keys (legacy, not tied to a DID; predates per-account keys) | `relay_signing_keys` | V003 | **Hard** — same path |
| OAuth ES256 signing key | `oauth_signing_key` | V012 | Easy — drop row, re-mint |
| JWT HS256 secret | `jwt_signing_secret` | V015 | Easy — drop row, re-mint |
| Iroh Ed25519 node key | `iroh_identity` | V022 | Easy — drop row, re-mint |

**Not KEK-wrapped** (survives KEK loss): Shamir Share 2 in
`accounts.recovery_share` (base32, V010). See
[A note on escrow Shamir shares](#a-note-on-escrow-shamir-shares) below.

The three "easy" secrets are **self-healing**: delete the single row, and
`load_or_create_*` in
[`crates/pds/src/auth/signing_key.rs`](../../crates/pds/src/auth/signing_key.rs)
mints a fresh one under the current KEK on next boot. The cost is bounded and
acceptable — sessions invalidated (users re-auth), Iroh node id changes (devices
re-resolve via `GET /v1/devices/:id/pds`). **The commit-signing keys are the
entire difficulty** in both scenarios below, because each is published in an
account's DID document and can only be replaced by a PLC operation signed by a
*current* rotation key.

## Golden rule (prevention)

**Back up the KEK as carefully as the database, and store it separately from the
DB backup.** A KEK backed up next to the Litestream snapshot gives an attacker
who reaches that one location both halves — the ciphertext and the key that
decrypts it — which defeats at-rest encryption. Store the KEK in a secrets
manager / offline vault distinct from where the DB backup lives. This single
practice turns Scenario 1 (loss) from catastrophic into a non-event.

---

## Scenario 1 — KEK **lost** (never exposed)

Symptom: after a redeploy / env change, the server **won't boot**. The OAuth,
JWT, and Iroh loaders hard-error (`... exists in the DB; cannot decrypt it — set
signing_key_master_key in config`) when encrypted material exists but the key is
gone.

### 1.1 First: is it actually lost?

- Check the secrets manager / vault backup (per the golden rule). If the KEK is
  recoverable, restore the env var and boot normally. **Stop here** — this is not
  a disaster, just a misplaced env var.
- Only proceed if the KEK is genuinely unrecoverable.

### 1.2 If genuinely lost

Set a **fresh** KEK, then recover each secret family:

1. **Easy secrets** — with the DB and the new KEK, delete the rows and let boot
   re-mint:
   ```sql
   DELETE FROM oauth_signing_key;
   DELETE FROM jwt_signing_secret;
   DELETE FROM iroh_identity;
   ```
   Boot with the new KEK → each is regenerated and persisted under it.
2. **Commit-signing keys** — **permanently undecryptable.** The old ciphertext in
   `signing_keys` (and the other repo-key families) cannot be read, so the PDS can
   no longer sign commits under the published `verificationMethods.atproto`. There
   is **no server-side fix.** Each affected account must go through **wallet-driven
   repo-key rotation** (`POST /v1/repo-keys/rotation` + `/complete`,
   [ADR-0025](../architecture/decisions/0025-wallet-driven-repo-key-rotation.md)):
   the PDS generates a fresh repo key, the account's wallet signs a PLC op
   repointing `verificationMethods.atproto` + `rotationKeys[1]`, and the PDS cuts
   over to the new key. Prioritize active accounts.

> **Takeaway:** a lost KEK is *nearly as bad as a compromised one*, purely because
> of the repo keys. Loss and compromise share the same hard recovery path
> (per-account wallet-driven rotation).

---

## Scenario 2 — KEK **compromised** (assume the DB was also exposed)

Threat assumption: if the KEK leaked, assume the attacker also has (or can get) a
DB copy. Therefore treat **every KEK-wrapped secret as plaintext-known to the
attacker.** Re-wrapping under a new KEK (the `pds rewrap-master-key` tool) is
necessary hygiene but does **not** by itself contain a compromise where the
plaintext keys are already known — you must rotate the underlying keys too.

### 2.1 Contain the env-var blast radius FIRST

Whatever exposed the KEK (leaked deployment variables, dashboard access, a leaked
deploy log) almost certainly exposed the other env secrets. Rotate **all** of
them, most-urgent first:

1. `EZPDS_ADMIN_TOKEN` — break-glass bearer credential; rotate **immediately** (it
   gates admin / moderation / device routes).
2. SMTP / Mailtrap tokens (`EZPDS_EMAIL_*`).
3. Any other deployment secrets in the same store.
4. Investigate the exposure vector and revoke the access path (rotate
   deployment-platform credentials, audit who/what could read env).

### 2.2 New KEK + re-wrap

Generate a fresh KEK. Use the offline `pds rewrap-master-key` subcommand
([deploy.md → Rotating the Master Key](../deploy.md#rotating-the-master-key)) to
re-encrypt the surviving blobs under it, and drop-and-re-mint the three easy
secrets (2.3). This ensures the DB at rest is protected under a key the attacker
doesn't have, going forward.

### 2.3 Rotate the easy secrets (invalidates forged tokens)

```sql
DELETE FROM oauth_signing_key;
DELETE FROM jwt_signing_secret;
DELETE FROM iroh_identity;
```

Re-mint under the new KEK on boot. This invalidates any access/refresh tokens the
attacker could forge with the leaked keys. Users re-auth; devices re-resolve the
node id.

### 2.4 Rotate the commit-signing keys (the hard part)

- The PDS **cannot** do this unilaterally: it would sign the rotation op with
  `rotationKeys[1]`, which is exactly the compromised key. Recovery is
  **wallet-driven and per-account** — the user's wallet holds `rotationKeys[0]`
  (outranks the PDS key;
  [ADR-0001](../architecture/decisions/0001-client-held-rotation-key-custody.md))
  and signs a PLC op rotating `verificationMethods.atproto` + `rotationKeys[1]` to
  a fresh PDS-generated key, via `POST /v1/repo-keys/rotation`
  ([ADR-0025](../architecture/decisions/0025-wallet-driven-repo-key-rotation.md)).
- Prioritize active accounts. For a mass event, each wallet must still sign —
  surfaced as a queued prompt in the Obsign wallet (mass-rotation UX is follow-on
  work per ADR-0025).
- Note: a malicious party with the compromised `rotationKeys[1]` can sign bad
  *commits* and *lower-priority* PLC ops, but **cannot** rotate the identity away
  from the user — `rotationKeys[0]` (the wallet) outranks it and can override
  within plc.directory's 72-hour recovery window (`plc_monitor.rs` flags
  unauthorized ops). The repo is self-certifying. So the identity itself is not
  lost; the commit-signing key is what must be rotated.

---

## Quick reference — ordering

**Loss:** verify backup → (if recoverable) restore & boot, done → else: new KEK →
drop + re-mint easy secrets → per-account wallet-driven repo-key rotation.

**Compromise:** rotate `EZPDS_ADMIN_TOKEN` + mail tokens + env access → new KEK +
`pds rewrap-master-key` → drop + re-mint easy secrets → per-account wallet-driven
repo-key rotation.

---

## A note on escrow Shamir shares

`accounts.recovery_share` (Share 2 of each user's 2-of-3 recovery split, added in
V010) is stored **base32 plaintext, not KEK-wrapped**, so a DB dump exposes it
directly. Two consequences:

- **On KEK loss**, the shares **survive** — they don't depend on the KEK.
- **On DB exposure**, Share 2 leaks — but Shamir 2-of-3 is *information-theoretically*
  secure at a single share, so this stays **sub-threshold**: the recovery secret is
  not reconstructable from Share 2 alone (an attacker still needs Share 1 from
  iCloud Keychain or Share 3 from the user's manual backup). It erodes the margin
  but does not, by itself, reconstruct anything.

Whether to KEK-wrap this share at rest is a tracked defense-in-depth follow-up:
wrapping upgrades a *DB-only* leak (no env-var exposure) from one-share-exposed to
zero, at the cost of coupling escrow recovery to KEK availability (a wrapped share
becomes undecryptable on KEK loss). That tradeoff becomes acceptable once the
golden rule above is in force, since irrecoverable KEK loss stops being a live
risk.

---

## References

- Custody model: [identity-and-key-custody.md](../architecture/identity-and-key-custody.md)
- [ADR-0001](../architecture/decisions/0001-client-held-rotation-key-custody.md) — client-held rotation-key custody
- [ADR-0004](../architecture/decisions/0004-pds-signed-repo-commits.md) — PDS-signed repo commits
- [ADR-0025](../architecture/decisions/0025-wallet-driven-repo-key-rotation.md) — wallet-driven per-account repo-key rotation
- KEK rotation / re-wrap tool: [deploy.md → Rotating the Master Key](../deploy.md#rotating-the-master-key)
- KEK-wrapped inventory: [`crates/pds/src/db/kek.rs`](../../crates/pds/src/db/kek.rs) (`SecretFamily`)
- Loaders: [`crates/pds/src/auth/signing_key.rs`](../../crates/pds/src/auth/signing_key.rs) (`load_or_create_*`, `load_repo_signer`)
- Crypto: [`crates/crypto/src/keys.rs`](../../crates/crypto/src/keys.rs) (`encrypt_private_key` / `decrypt_private_key`)
