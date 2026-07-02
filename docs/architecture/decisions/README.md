# Architecture Decision Records

An **Architecture Decision Record (ADR)** captures a single significant
architectural decision: the context that forced it, the decision itself, and the
consequences we accepted. ADRs are the *historical record* — read them to
understand why the architecture is the way it is.

## Rules

- **ADRs are immutable once `Accepted`.** Don't rewrite history. If a decision
  changes, write a *new* ADR and mark the old one `Superseded by ADR-NNNN`.
- **One decision per record.** If you're tempted to use "and", it's probably two
  ADRs.
- **Numbered sequentially**, zero-padded: `0001-...`, `0002-...`. The number is
  permanent; the slug describes the decision.
- **Status** is one of: `Proposed`, `Accepted`, `Deprecated`,
  `Superseded by ADR-NNNN`.
- Record decisions that are *already embodied in the code* too — a decision
  doesn't have to be new to be worth recording. Backfilling the load-bearing
  ones gives future readers the "why".

## Writing a new ADR

1. Copy [`adr-template.md`](adr-template.md) to
   `NNNN-short-slug.md` (next number).
2. Fill it in. Keep it tight — an ADR is a page, not a spec. Link to
   design plans / specs for detail.
3. Add it to the log below.
4. If it changes a documented fact, update the relevant doc under
   [`../`](../) in the same change.

## Log

| ADR | Status | Decision |
| --- | --- | --- |
| [0000](0000-record-architecture-decisions.md) | Accepted | Record architecture decisions as ADRs |
| [0001](0001-client-held-rotation-key-custody.md) | Accepted | The user's wallet holds `rotationKeys[0]`; the PDS holds `rotationKeys[1]` |
| [0002](0002-wallet-authorized-account-migration.md) | Proposed | Account migration is wallet-authorized by default, with a PDS-signed interop fallback |
