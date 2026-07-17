# MM-400 — Parent-driven permanent deletion of a sovereign child agent

[MM-400](https://linear.app/malpercio/issue/MM-400) · Wave 8 (auth.md) · design leg.

## Problem

Minting a sovereign child ([MM-368](https://linear.app/malpercio/issue/MM-368))
creates a full local account — own DID, repo, handle, blobs, an
`agent_identities` capability row, and a durable `agent_child_provisionings`
record. Revoking (`POST /agent/child/revoke`) deliberately kills only the
*delegated capability* and preserves the identity (the ADR-0023 custody ladder).

That leaves no way to retire the *hosting*. A revoked child:

- cannot delete itself — its only credential is the now-revoked capability;
- cannot use `com.atproto.server.deleteAccount` — that needs a password + emailed
  token, and a child has a disabled random password and an `@agents.invalid`
  email by construction;
- has a parent who provisioned it but has only `revoke`, not `delete`.

So a revoked child's account, repo, and records stay served and AppView-indexed
forever. HV-2's demo child `did:plc:5xbotomihodrqalq54rd7rj2` is the live example.

## Decision

Add a parent-authed **`POST /agent/child/delete`** beside `revoke`, gated by the
same `authenticate_account_owner` + `get_child_of_parent` ownership check
(unknown/foreign child DIDs stay a uniform 404; agent-derived credentials are
refused by the owner guard).

### Deletion model — schedule + reaper (not instant)

`delete` **implies revoke** and then **schedules** the permanent deletion,
reusing the existing deactivate → `delete_after` → reaper pipeline
(`db::accounts::deactivate_account`, `accounts_due_for_deletion`,
`account_reaper::spawn_account_reaper` → `account_delete::purge_account`).

One transaction (under the firehose sequencer lock), in order:

1. `revoke_agent_identity` — flip the capability to `revoked` (idempotent).
2. `deactivate_account(child_did, delete_after = now + grace)` — deactivates the
   account and records the scheduled deletion instant. On a real transition it
   emits `#account status="deactivated"`, so relays **stop serving the repo
   immediately** even though the physical purge is deferred.
3. `upsert_child_deletion` — write the durable audit tombstone (below).

The existing hourly reaper then purges the child once `delete_after` elapses,
emitting `#account status="deleted"` and removing all local data via the shared
`purge_account` transaction — identical to `deleteAccount` semantics, so relays
drop the repo.

Why schedule rather than instant purge:

- **Reuse.** No second deletion path; the reaper already does the purge + frame.
- **Undo window.** A mistaken delete can be reversed by reactivating before the
  window elapses (the account/repo/tombstone still exist).
- **Immediacy where it matters.** Deactivation stops the repo being served at
  once; only the irreversible byte-purge waits for the window.

Grace is a config knob **`accounts.child_deletion_grace_secs`** (default 24 h,
settable to `0` so an operator — or a test — can make the next reaper tick purge).

### Audit — a parent-keyed tombstone that outlives the account

`purge_account` deletes `agent_audit_events WHERE registration_id IN (SELECT id
FROM agent_identities WHERE did = ?)`, so the child's own audit trail dies with
it **regardless of timing**. "Auditable after the fact" therefore needs a record
in a table with **no foreign key to the child**.

Decision: the `agent_identities` registration row does **not** survive (it can't —
its `did` FK to `accounts` and the `registration_type='child' ⇒ did NOT NULL`
CHECK both bind it to the account being purged, and it is part of the account's
data). Instead a dedicated **`agent_child_deletions`** tombstone (V030-style
doctrine) records the parent's deletion order and survives the purge:

```
agent_child_deletions(
    child_did TEXT PK,          -- NO FK to accounts: survives the child purge
    parent_did TEXT NOT NULL REFERENCES accounts(did),  -- the accountable owner
    handle TEXT NOT NULL,       -- denormalized (handles row is purged)
    registration_id TEXT NOT NULL,
    scheduled_at TEXT NOT NULL,
    delete_after TEXT NOT NULL)
```

Keyed on `child_did` (idempotent re-delete is an upsert), anchored to
`parent_did` so the parent's audit view outlives the child, and reclaimed only
when the **parent** is itself deleted.

### purge_account FK fix

FK enforcement is always on and there are no account-keyed cascades, so
`purge_account`'s `DELETE_BY_DID` must reach the two child-agent tables before
the `accounts` row:

- `DELETE FROM agent_child_provisionings WHERE child_did = ?` — the child's
  provisioning row FK-references `accounts(did)`; without this the account-row
  delete FK-fails. No-op for non-child accounts.
- `DELETE FROM agent_child_deletions WHERE parent_did = ?` — reclaims a parent's
  tombstones when the **parent** is purged (the tombstone must *survive* a
  *child* purge, so it is deleted by `parent_did`, never `child_did`). No-op for
  a child (a child never authored deletions).

### Out of scope — the did:plc identity stays wallet-driven

Server-side deletion purges *hosting* only. ezpds is wallet-native: the PDS holds
no rotation key, so it never tombstones the did:plc. A full identity retirement is
`delete-on-PDS` (this issue) **+** a wallet-driven PLC tombstone (PR #273). The
child's wallet-held recovery key and PLC identity are untouched by the server.

## API

`POST /agent/child/delete` — body `{ "did": "<childDid>" }`, owner-authed.
Response `{ "did", "status": "deletion_scheduled", "deleteAfter": "<rfc3339>" }`.
Errors: 404 uniform (unknown/foreign child), 403 (agent-derived / non-full-access
token), 403 (parent not local).

## Acceptance → verification

- Parent permanently deletes its child (account/repo/handle purged, `#account
  deleted` emitted, post no longer served) → `delete` schedules + drives the
  reaper in-test to the purge; assert account gone + deleted frame.
- Non-parent gets uniform 404; agent-derived credentials refused → owner-guard
  tests mirroring `revoke_child`.
- Deletion auditable after the fact → `agent_child_deletions` row present after
  `purge_account` runs.
- Wallet recovery key / PLC identity untouched → server issues no PLC op on
  delete (documented; `purge_account` doctrine already asserts it).

## Touch list

- `crates/pds/src/db/migrations/V049__agent_child_deletions.sql` + register.
- `crates/pds/src/db/agent_child_deletions.rs` (upsert + list-by-parent).
- `crates/common/src/config.rs` — `child_deletion_grace_secs`.
- `crates/pds/src/account_delete.rs` — two `DELETE_BY_DID` entries.
- `crates/pds/src/routes/agent_child.rs` — `delete_child` + types + tests.
- `crates/pds/src/app.rs` — route wiring.
- `bruno/agent_child_delete.bru`; `docs/test-plans/2026-07-15-MM-356.md` lineage;
  `crates/pds/src/db/AGENTS.md`.
