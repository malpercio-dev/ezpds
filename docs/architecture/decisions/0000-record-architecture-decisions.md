# ADR-0000: Record architecture decisions as ADRs

- **Status:** Accepted
- **Date:** 2026-07-02
- **Deciders:** ezpds maintainers
- **Related:** [`../README.md`](../README.md)

## Context

ezpds spans a Rust PDS, a repo engine, a crypto core, and two Tauri iOS apps,
with load-bearing decisions (custody model, signing model, DID method) scattered
across long-form specs, design plans, and `AGENTS.md` files. Those documents
answer "how does it work now" and "what are we planning", but not "why did we
choose this over the obvious alternative" — and the reasoning behind the
decisions that most shape the system is the easiest thing to lose. New
contributors (human or agent) re-litigate settled choices because the rationale
was never written down in a durable, greppable place.

## Decision

We will record significant architecture decisions as **Architecture Decision
Records** under `docs/architecture/decisions/`, using the format in
[`adr-template.md`](adr-template.md) (a lightly-extended Michael Nygard
template). ADRs are numbered sequentially, are immutable once `Accepted`, and are
superseded rather than edited when a decision changes. Current-state facts live
in sibling docs under `docs/architecture/`; ADRs hold the *why*.

We will also backfill ADRs for already-implemented decisions that are load-
bearing but never had their rationale recorded.

## Consequences

- There is one durable, greppable home for "why", separate from "how" (facts
  docs) and "when" (milestone map / plans).
- Every significant decision now carries a small documentation cost. We accept
  it for load-bearing decisions and explicitly do **not** require ADRs for
  routine or easily-reversible choices.
- The immutability rule means the log doubles as a timeline: superseded ADRs stay
  in place with a pointer forward.

## Alternatives considered

- **Keep decisions in design plans and `AGENTS.md` only.** Rejected: those
  capture current state and get edited in place, erasing the history of *why*,
  and they mix rationale with mechanics.
- **A single `DECISIONS.md` log.** Rejected: it grows unbounded, invites editing
  past entries, and makes one decision hard to link to or supersede cleanly.
- **A heavier RFC process.** Rejected as premature for a project this size; ADRs
  are the minimum that captures rationale without ceremony.
