# Architecture

This directory is the **current-state** description of the ezpds architecture:
what is true about the system *now*. It answers "how does this work?" for
someone reading the code today.

It is deliberately split from two neighbours:

- **`decisions/`** — Architecture Decision Records (ADRs). These are the
  *historical* record of *why* the architecture is the way it is. An ADR is
  immutable once accepted; when a decision changes, a new ADR supersedes the old
  one. Read ADRs to understand how we got here; read the facts docs here to
  understand where "here" is.
- **`../design-plans/`, `../implementation-plans/`, `../*-spec.md`** — forward-
  looking or point-in-time planning documents tied to specific tickets. These
  can go stale; the docs in this directory are meant to be kept current.

## Relationship to the rest of `docs/`

- [`../pds-architecture.md`](../pds-architecture.md) is the long-form,
  milestone-oriented system narrative (device lifecycle phases, tiers,
  firehose). The facts docs here are narrower, kept-current reference sheets on
  specific subsystems, and link out to it rather than duplicate it.
- [`../unified-milestone-map.md`](../unified-milestone-map.md) is the phase model
  (v0.1–v2.0+). Facts docs describe what exists; the milestone map describes when
  things are planned.

## Facts documents

- [`identity-and-key-custody.md`](identity-and-key-custody.md) — where identity
  keys live, the `did:plc` rotation-key hierarchy, and the client-held-key
  custody model that is ezpds's core differentiator.

## Conventions

- One subsystem per file. Keep each doc a *reference sheet*, not a narrative.
- State what is true today. If something is planned but not built, say so
  explicitly, or leave it to a design plan / ADR.
- When a documented fact changes because of a decision, record the decision as an
  ADR in `decisions/` and update the fact here in the same change.
