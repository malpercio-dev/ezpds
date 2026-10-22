# Clear Signal / Emphasis

The user selected and approved the final Emphasis refinement on 2026-09-07. Start with the [authoritative design handoff](../../design-plans/2026-09-07-clear-signal-emphasis.md).

## Package

| File | Use |
| --- | --- |
| [preview.html](preview.html) | Standalone interactive preview; opens outside Codex |
| [preview.fragment.html](preview.fragment.html) | Exact editable source of the accepted final visual |
| [tokens.json](tokens.json) | Exact reference palette, geometry and typography; not production CSS |
| [surface-inventory.md](surface-inventory.md) | Existing routes/components and required coverage beyond the specimens |
| [validation.md](validation.md) | Handoff checks, implementation checks and native/browser distinctions |
| [assets/](assets/) | Light/dark vector mark masters |

Open `preview.html` directly in a browser, or serve this directory from the repository root:

```sh
python3 -m http.server 5189 --bind 127.0.0.1 --directory docs/design/clear-signal-emphasis
```

Then open `http://127.0.0.1:5189/preview.html`. The preview has surface, appearance, example-state and width selectors. “Before / after” compares the earlier Emphasis with the final refinement. Some static reading surfaces disable the example-state selector. Operator surfaces stay dark.

## What the preview contains

Obsign wallet, Brass Console, change review, both marketing sites, docs gateway, user/operator docs, browser consent, instance landing and privacy. It is representative visual guidance, not a complete implementation. The surface inventory and real source determine the remaining screens and behavior.

All data and actions are illustrative and local. The default view shows the final wallet in both appearances. The exported document includes its styles, font data and local interactions, with no Codex account or host API required. Its preview shell loads pinned Lucide and Floating UI scripts from `unpkg.com`; internet access is needed for those helpers/icons. Fonts and layout are embedded. This preview dependency is **not** permission to add CDNs to the products.

The export was made with the visualization renderer during the design session. `preview.fragment.html` is embedded verbatim in `preview.html`; the surrounding shell supplies the preview controls and icons. An implementor does not need that renderer to open the committed export. If editing the design later, update the source and regenerate/rebuild the standalone shell together, then verify their parity. Do not paste this exploratory HTML/JS into Svelte or Rust templates.

## Asset provenance

The embedded fonts are existing repository files: Public Sans Regular/SemiBold and JetBrains Mono Regular, under OFL 1.1; see the [font provenance](../../../apps/identity-wallet/static/fonts/README.md). The `Proposal Sans` and `Proposal Mono` names are preview-only aliases for these families. Preserve the production font families, licenses and existing self-hosted copies.

The paired-bar mark is original geometry from the selected preview; the SVG masters reproduce its shape and action colors. The wordmark uses Public Sans (Obsign) or JetBrains Mono (Brass Console). The masters are not final raster app-icon or social-card exports. Generate those at their required sizes using the existing pipelines and review legibility before shipping.

## Decision history

The archived [initial proposals](../../archive/design-plans/2026-09-06-ecosystem-redesign-proposals.md), [Clear Signal study](../../archive/design-plans/2026-09-07-clear-signal-visual-study.md), [Split Panel study](../../archive/design-plans/2026-09-07-split-panel-refinements.md), and [final refinement notes](../../archive/design-plans/2026-09-07-emphasis-refinement.md) record how the direction was chosen. Their earlier recommendations do not govern implementation. This package carries only the selected final preview.
