# Clear Signal: three Split Panel refinements

> Historical design evidence. Follow the [selected Emphasis handoff](../../design-plans/2026-09-07-clear-signal-emphasis.md) for implementation. Earlier recommendations and prototype limits below describe their original review round.

Date: 2026-09-07

Status: historical exploration; replaced by the selected Emphasis handoff


The user selected Split Panel from the [Clear Signal visual study](2026-09-07-clear-signal-visual-study.md) and requested three polished alternatives. This study preserves the conclusion/evidence separation, the Clear Signal palette, and the original ecosystem scope. It does not replace the production design briefs or implement an app migration.

## Shared refinements

- One continuous panel replaces the earlier nested evidence card. The shared edge communicates that the conclusion and its evidence belong together.
- Evidence uses explicit labels and values, aligned for scanning. Check time is an observation; device-key availability is a separate fact, never proof of overall safety.
- Everyday wallet destinations return to full-width rows. Long labels have room, and each row retains a usable touch target.
- The review action follows the deadline within the same panel. A new change-review specimen carries the identity, before/after host values, and deadline into the next screen before the proposed override review.
- Operator command panels distinguish the action from its target and biometric confirmation. Claim-code generation stays ahead of federation observations. Literal operator data uses monospace; the consumer wallet uses plain language and sans serif.
- Documentation gives instructions a readable column. The split panel groups an instruction with its applicability or evidence, rather than splitting the entire article into interleaved columns.
- Consent joins requester/permission review with the handoff channel. At phone width, the requester remains first and the handoff follows it.

## Alternatives

| Alternative | Composition | Best reason to choose it | Tradeoff |
| --- | --- | --- | --- |
| Joined | Bounded conclusion above a contiguous tinted evidence surface; full-width review action beneath | Closest refinement of the selected Split Panel; strong grouping without excessive visual weight | Uses more height than Ledger |
| Ledger | Compact conclusion, two evidence columns separated by rules, restrained surface color | Faster everyday scan and more visible tasks on a phone | Evidence labels must stack gracefully at large text sizes; restrained alarms still need a prominent action |
| Emphasis | Broad color-filled conclusion with quieter evidence below; larger status typography | Stronger marketing expression and a more recognizable status region | Routine state takes more space and visual attention |

Joined is the lead recommendation for the wallet. Ledger offers a useful density reference for Brass Console and documentation. Emphasis is strongest as an expressive web alternative; its taller phone status panel has a real cost. A later synthesis could use Joined's shared panel edge, Ledger's compact evidence where labels fit, and Emphasis's larger web composition. This is a recommendation for the next comparison, not a user decision.

## Coverage and interaction

The companion visual comparison includes all three wallet variants, both apps, change review, Obsign and Custos marketing, the documentation gateway, user and operator documentation, browser consent, the PDS instance page, and privacy. Dark/light controls and a 390-pixel contained preview support comparison. Operator surfaces retain their dark register. Normal, attention and unavailable/expired examples apply where the surface has those states; the change-review specimen depicts the attention path.

The local prototype links wallet alerts into change review and selected navigation into the corresponding web specimens. Other destinations return a clearly labeled concept response. Generating a sample code against the unavailable-server example never reports a new code. No authentication, credential, signing or network operation occurs.

Synthetic sample times, identities, hosts and deadlines remain labeled as examples. Expired consent retains neutral restart guidance, without claiming that no access was ever granted. A failed check remains unavailable. PLC recovery, domain authority, key recovery and content restoration remain separate concepts.

## Validation

Inspected the rendered dark comparison, light attention states, a 390-pixel review screen, both apps with an unavailable server, desktop marketing, and the operator reading layout. Verified alert-to-review navigation and the unavailable claim-code response. The inherited palette's measured text/action pairs remain as recorded in the preceding study. This is a visual prototype review, not a full accessibility audit or a native-app test.
