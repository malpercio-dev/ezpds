# Writing style guide

Last verified: 2026-08-03

Rules for every prose surface in this repo: the docs site, marketing copy, in-app
strings, code comments, and AGENTS.md files. The dream routine and doc-editing
agents follow this file; human PRs are reviewed against it.

## Audiences

**Obsign (user tier: `sites/docs` `user/`, in-app copy, marketing).**
Write for the *release* audience: security-minded people in the 1Password /
Proton lane, including people who are not technical but want better security
hygiene. The early test audience (peers, protocol-adjacent Bluesky users) can
read down to this register; the release audience cannot read up to a
protocol-native one. Concretely:

- Lead with what can go wrong and how Obsign protects against it. Data
  ownership and sovereignty are outcomes the reader discovers, not the pitch —
  there is credible skepticism, even among protocol-minded users, that "owning
  your data" sells on its own.
- Protocol machinery (DID methods, rotation keys, PLC) appears only behind
  clearly-marked Advanced sections or on reference pages. A first-run page never
  requires it. The in-app register ("What's your situation?") is the model.

**Custos (operator tier: `sites/docs` `operator/`, deploy/ops docs).**
A technical-minded subset of Obsign users who care how the technology works and
want full control over their data and presence. Keep the depth; these readers
want mechanism. The voice rules below still apply — technical is not the same
as dense.

## Voice

The failure mode to avoid is uniform, machine-flavored prose. The tells, and
their fixes:

- **Em-dash budget.** A handful per page, not one per sentence. Most asides
  read fine as a separate sentence or set off with commas.
- **Retire the contrast scaffold.** "X is not Y — it's Z" and "not X, but Y"
  are fine once; as the default sentence shape they are a fingerprint. Say what
  a thing *is*.
- **No self-defense.** Cut asides that argue the design is right ("which is
  exactly the right time", "the trade is real"). Users need the task done, not
  the decision justified. Rationale belongs in ADRs.
- **Drop defensive adverbs.** "deliberately", "exactly", "precisely",
  "load-bearing" are for design docs. In user prose they signal an author
  anticipating an argument no reader is making.
- **Vary rhythm.** Short sentences exist. Use them.
- **Contractions are fine.** "It's" and "don't" read as human; "it is" and
  "do not" at every occurrence read as generated.
- Standard hygiene: active voice, concrete specifics over vague claims, no
  throat-clearing openers, no marketing adjectives ("robust", "seamless").

The read-aloud test catches most violations: if a paragraph sounds like a
narrator defending a thesis, rewrite it as a person explaining a task.

## Screens and rendered pages

Every string a user can see in an app or on a server-rendered page is prose,
and follows the audience rules above. Map each surface to a register by who is
reading and when:

- **User register:** the wallet's everyday tier and onboarding, and the OAuth
  pages Custos renders (authorize, wallet sign-in, error). The OAuth pages are
  read mid-task inside someone else's app, the most stressed reading context we
  own. A protocol noun on one of these surfaces is a bug unless showing the
  machinery is the screen's whole purpose.
- **Operator register:** the wallet's advanced tier and all of the admin
  companion. Machinery is the content here. The voice rules still apply.

Screens add rules the docs tiers never needed:

- **Error copy answers three questions:** what happened, what it means, what
  to do next. Calm under alarm: the scarier the state, the plainer the words.
  Blame the situation, never the user.
- **Internal detail stays out of the user's sentence.** If an error string can
  reach a screen, write it for the screen; wrapped error chains, cache paths,
  and module names belong in the log.
- **Buttons name the action's outcome.** "Approve", "Remove this identity" —
  never a bare "OK" or "Yes" on anything destructive.
- **Confirmations don't hedge.** A screen asking the user to commit states the
  consequence in one sentence and stops.

## Where prose lives

One fact, one home. The repo's parity-check scripts exist because duplicated
prose drifts; the cheaper fix is not duplicating it.

- **Code comments state constraints the code can't show** — invariants,
  ordering requirements, why an obvious alternative is wrong. They do not
  narrate what the next line does, and they do not argue rationale at length:
  link the ADR instead.
- **Don't restate what a test enforces.** If a test pins the behavior, the
  comment states the invariant in a line or two and names the test.
- **AGENTS.md is a map, not the territory.** An entry is a few lines: what the
  module is, the one or two facts an agent needs before opening it, and a
  pointer to the module doc. The detailed prose lives in exactly one place,
  nearest the code — usually the module doc. When consolidating, move detail
  *toward* the code and leave AGENTS.md pointing at it, never the reverse.
- **ADRs and design plans own rationale.** A comment or doc that finds itself
  explaining *why the design is right* should shrink to a link.

## Enforcement

By review, not by gate. Style is judgment work; the dream routine applies this
file on its nightly pass, and reviewers hold PRs to it. If a rule here proves
wrong in practice, change the rule — this file is the spec, not a monument.
