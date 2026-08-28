# ADR-0035: Per-space operator takedown lives on the `spaces` row

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** malpercio
- **Related:** MM-526; V070; `crates/pds/src/auth/space.rs` (`require_space_servable`), `crates/pds/src/routes/admin_spaces.rs`; [ADR-0016 lineage: the Atproto Spaces proposal's deletion semantics]

## Context

Custos stores Atproto Space repos for its local accounts. Two facts about that make
account-level moderation insufficient.

**Granularity.** The only moderation lever that reached a space was account takedown:
`auth::space::require_serviceable_caller` refuses any account in a moderation state, so
taking down an account closes its space surface — along with its other spaces and its
entire public repo. To stop serving one abusive space an operator had to take down
everything else that account had.

**Foreign authority.** A space's *authority* need not be this host. `space_record_write`
records the `spaces` row on a member's first write precisely so a local account can join a
space governed elsewhere without this host having been told in advance. So Custos can be
storing and serving records in a space it does not govern: `simplespace.deleteSpace` is not
its to call, and the space's actual authority has no obligation to act. This is an operator
liability with no available action at all, and it is the reason this is more than an
ergonomics gap.

The `spaces` table already carried `deleted_at`, but that is the *owner's* tombstone: it is
written by `deleteSpace`, it clears the simplespace config so the URI can be created again,
and it makes `getSpaceCredential` answer `SpaceDeleted` — the spec's durable "drop your copy"
signal to syncers. An operator refusal is a different thing: reversible, and never an
instruction to destroy data.

## Decision

We will add a `takendown_at` column to `spaces` (V070) as the operator's independent,
reversible refusal to serve, enforced at the space auth seam and inside the write choke
point's commit transaction, and driven by two admin routes (`GET /v1/admin/spaces`,
`POST /v1/admin/spaces/takedown`).

Specifically:

- **A column on `spaces`, not a separate refuse-to-serve list.** The row already exists for
  every space this host stores anything in, foreign-authority spaces included.
- **A refused space answers `SpaceNotFound`, never `SpaceDeleted`.** The same reply an
  unknown space gets, and the same posture `require_serviceable_authority` already takes for
  a non-active authority.
- **Reads, writes, credential minting, notification fan-out, and the member-facing
  `listSpaces` all refuse.** A takedown means this host does not act as space or repo host
  for that URI at all.
- **Every check runs after authentication**, so takedown state is never an unauthenticated
  probe — with the write path as the deliberate exception, checking inside its transaction.
- **Nothing is destroyed.** Config, members, notify registrations, and stored repos stay, so
  clearing the takedown returns the space to exactly its prior state. `createSpace` refuses
  to claim a taken-down row, so the owner cannot delete-and-recreate around the refusal.

## Consequences

- An operator can stop serving one space without touching the owning account, and can act at
  all on a foreign authority's space — the liability case that previously had no lever.
- Restore is a genuine inverse, which is what lets an operator act quickly on a report and
  reverse it if the report was wrong.
- The gate is a per-request `spaces` row read at each seam. It is a primary-key lookup on a
  `WITHOUT ROWID` table on the same single connection every seam already uses, and the write
  path folds it into a read it was already doing.
- The check sits at five call sites (three seam functions, the write choke point, and the
  credential mint) rather than one. `just space-auth-seam-check` does not currently pin this
  the way it pins credential parsing; a new space seam that forgot the gate would not fail a
  build. Extending that script is the natural follow-on if a sixth seam ever appears.
- A takedown survives a delete-and-recreate of the same URI. This is deliberate — the
  operator's refusal outranks the owner's lifecycle actions — but it means an operator must
  clear a takedown before the URI is usable again, and `createSpace` reports that as
  `SpaceAlreadyExists` rather than naming the refusal.
- The admin routes are not gated on `[spaces] enabled`. Turning the surface off stops serving
  new traffic but leaves whatever is already stored, which is exactly when an operator still
  needs to look.

## Alternatives considered

**A separate refuse-to-serve list table.** Its one extra power is naming a space this host
has no row for — a pre-emptive block. But a host is not liable for records it does not store,
and it cannot serve a space it has never heard of; when a member's first write arrives, the
row appears and the column is reachable. That leaves the table's cost (a second source of
truth every seam must consult, and a join on the operator listing) buying nothing concrete.
Rejected as speculative.

**Reusing `deleted_at`.** Simplest possible diff, and wrong twice over: it would make
`getSpaceCredential` answer `SpaceDeleted`, telling every syncer to durably drop copies of
data the operator may restore within the hour, and it would clear the simplespace config,
making the takedown unreversible in practice.

**Enforcing only reads/serving, not writes.** Tempting, since a space nobody can read is
already contained. Rejected: a taken-down space that still accepts writes keeps growing the
store the operator is refusing to serve, which is the disk-and-liability half of the problem
the ticket names.

**A single check inside `require_space_grant`.** Would have been one call site instead of
three at the seam, but the space-credential arms of `authenticate_space_read` and
`authenticate_space_access` never call it — a syncer holding a credential would have walked
straight past the gate.

**Answering `Forbidden` for a refused space.** Discloses which spaces an operator has acted
on, to anyone who can authenticate. The read seam's existing non-disclosure posture
(`RepoNotFound` for another account's repo) is the house rule, and `SpaceNotFound` follows it.
