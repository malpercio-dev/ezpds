# Clear Signal: dark appearance and three layout variants

> Historical design evidence. Follow the [selected Emphasis handoff](../../design-plans/2026-09-07-clear-signal-emphasis.md) for implementation. Earlier recommendations and prototype limits below describe their original review round.

Date: 2026-09-07

Status: historical exploration; replaced by the selected Emphasis handoff


The user preferred Clear Signal from the [four ecosystem proposals](2026-09-06-ecosystem-redesign-proposals.md) and requested a dark-mode study and alternative implementations. This is a visual iteration, not a change to production components or the governing product briefs. The original ecosystem coverage and security constraints still apply.

## Dark appearance

Deep navy grounds, a slightly lighter navy for grouped information, cool near-white text, and pale blue actions. The light version keeps white surfaces and deep cobalt actions. The night version needs its own tonal relationships: reusing the light version's saturated button blue would weaken hierarchy and contrast on navy.

| Role | Light | Dark |
| --- | --- | --- |
| Page | `#FFFFFF` | `#121C2C` |
| Raised surface | `#EEF3FA` | `#1C2C43` |
| Primary text | `#152641` | `#F1F5FC` |
| Secondary text | `#40516A` | `#BDCDE2` |
| Action | `#234BA6` | `#B8D4FF` |
| Text on action | `#FFFFFF` | `#12284A` |
| Observation surface | `#EAF0FA` | `#213551` |
| Observation text | `#203F72` | `#C8DCFF` |
| Alert surface | `#FFEBED` | `#49262F` |
| Alert text | `#8B2531` | `#FFD0D7` |

These are concept swatches, to be expressed as semantic OKLCH tokens if adopted. Calculated sRGB contrast: dark primary/page 15.64:1; dark secondary/raised 8.72:1; dark action text/fill 9.73:1; dark alert text/surface 9.53:1; dark observation text/surface 8.94:1. Light action text/fill is 7.99:1, light secondary/raised 7.24:1, and light alert text/surface 7.63:1. These measurements cover the listed pairs, not a complete accessibility audit.

Brass Console keeps a separate dark operator register: a deeper ground (`#0E1724`), compact literal observations, and monospace headings. It shares the action hue and state semantics with Obsign. The appearance control applies to the consumer surfaces; fixed-dark operator pages remain dark.

## Three implementations

All three show the same identity, verification evidence, actions, and example states. Differences are composition and emphasis rather than missing information.

### Wide band

The observation spans the full width of the identity screen, separating the identity context above from everyday actions below. State, supporting explanation, check time, and the relevant review/retry action form one stable region. On marketing, a broad observation panel anchors the first viewport below the headline and introduction. Operator observations become a compact secondary block after code generation.

This is the closest development of the original Clear Signal and the strongest recognizable visual signature. Its tradeoff is vertical space: always test that the critical action is visible at ordinary phone sizes and that large text can reflow without losing any evidence.

### Split panel

Separate the conclusion from its evidence within one bounded area. Phones stack these parts; wider pages put the explanation beside a structured observation. The action directory uses two columns only when labels and touch targets fit, and collapses at narrow widths. The console gives code generation a defined command panel with the issuing server context above it.

This is the most structured option and suits people who routinely inspect details. Its risk is excessive containers and a longer scan before everyday actions; use it only when the separation actually helps comprehension. Evidence is ordinary text, not an invented score or dashboard.

### Quiet rows

The state reads directly on the page, followed by a compact evidence line and ruled action rows. Color is concentrated in the icon/title when attention is needed, and in the primary action. Marketing scales down the headline and places the observation beside it with a simple divider. Documentation relies on reading measure and horizontal rules.

This is the calmest everyday tool and the least visually heavy dark appearance. Its risk is weak urgency: attention and unavailable states must retain explicit titles, icons, a stable position, the exact deadline where applicable, and a prominent review/retry action. The quiet layout cannot mean hiding a warning behind a details disclosure.

## Recommendation and next comparison

Wide Band is the strongest continuation of Clear Signal's original identity. Quiet Rows is the most promising alternative for daily wallet use. Split Panel is worth choosing when separating the evidence materially improves understanding for the intended users.

The visual study opens with dark and light wallet screens side by side. It also carries the layouts into both apps, Obsign/Custos marketing, the docs gateway and both docs audiences, consent, the PDS instance page, and privacy. Controls switch normal, attention, and unavailable/expired examples; a contained 390-pixel preview shows narrow reflow. Sample identities, observations and deadlines are synthetic.

This round does not add new verification guarantees, shorten the signing review, or change credential behavior. An unavailable check stays unverified. Expired consent uses neutral restart guidance without asserting that access was never granted. Keys, domains, recovery shares, content backup, and operator observations remain separate concepts.
