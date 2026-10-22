# Domain Docs

How the engineering skills should consume this repo's domain documentation when
exploring the codebase. Layout: **single-context**.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root (not yet written; created lazily).
- **`docs/architecture/decisions/`**: the ADR log, `NNNN-slug.md`, indexed by
  `0000-record-architecture-decisions.md`. Read the ADRs that touch the area
  you're about to work in. This repo keeps ADRs here rather than at the skills'
  default `docs/adr/`; there is no `docs/adr/`.
- Nearest-to-code context lives in each crate's and app's `AGENTS.md`; the root
  `AGENTS.md` is the map.

If `GLOSSARY.md` doesn't exist, **proceed silently**. Don't flag its absence or
suggest creating it upfront. The `/domain-modeling` skill (reached via
`/grill-with-docs` and `/improve-codebase-architecture`) creates it when terms
actually get resolved.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal,
a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift
to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either
you're inventing language the project doesn't use (reconsider) or there's a real
gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than
silently overriding:

> _Contradicts ADR-0013 (…), but worth reopening because…_

Cite only ADRs that still govern: `just adr-ref-check` fails on a citation that
points at a superseded ADR or a number with no file, so check the ADR's status
line before citing it. A new ADR goes through `/domain-modeling` and takes the
next free number.
