# Clear Signal / Emphasis design handoff

Date: 2026-09-07

Status: selected design; production implementation pending

Source baseline: `fce27c34` (recheck current routes and contracts before implementation)

## Summary

The approved direction is Clear Signal → Split Panel → Emphasis, with the final refinement captured in the linked preview and token reference. It pairs a strong conclusion pane with quiet supporting evidence inside one joined panel. Obsign uses Public Sans, blue emphasis, and light/dark appearances; Brass Console uses a dark operator register with JetBrains Mono for commands and literal values. The redesign covers both iOS apps and all existing marketing, documentation, privacy, authentication, and instance web surfaces.

Implementors should evolve existing tokens and components in the current stacks, preserve every route and security contract, and use actual state rather than specimen data. Delivery proceeds through the token foundation, wallet, console, public/authentication web, and documentation, with accessibility and relevant behavior verified at each phase.

## Definition of done

Bring the selected **Clear Signal → Split Panel → Emphasis → final refinement** to both iOS apps and every existing web surface. Preserve product behavior, security boundaries, content coverage and audience separation. Deliver responsive, accessible interfaces in the real application stacks, with updated documentation imagery and matching design briefs.

This PR captures the approved direction and the material needed to implement it later. It does not ship the redesign. The preview demonstrates representative screens; it is not the route inventory, a functional replacement application, or a source of authentication logic.

## Authority and reading order

1. This document defines the selected design, constraints and acceptance criteria.
2. [Handoff package](../design/clear-signal-emphasis/README.md) explains how to open the preview and use the assets.
3. [Surface inventory](../design/clear-signal-emphasis/surface-inventory.md) maps the whole scope to source files, including screens not drawn in the preview.
4. [Token reference](../design/clear-signal-emphasis/tokens.json) records the exact selected color values and reference geometry.
5. Current app behavior, endpoint contracts and security specifications govern any feature the visual specimen abbreviates.

The four preceding exploration notes are retained under `docs/archive/design-plans/`. Their recommendations are historical. In particular, Open Charter, Wide Band, Joined and Ledger are not competing implementation directions. The final preview already incorporates the selected compact evidence treatment; do not introduce an end-user theme selector for these alternatives.

The existing root `DESIGN.md` and `apps/admin-companion/DESIGN.md` describe the shipping gold/seal design. Update those briefs and their token consumers together during implementation. Preserve their behavioral, accessibility and platform constraints. This handoff records the user's authorization to replace the visual world with Emphasis; the old palette and display-face rules do not override that choice.

## Acceptance criteria

These criteria translate the approved design and existing product invariants into implementation checks. They do not add new backend capabilities.

- **clear-signal-emphasis.AC1.1 — Coverage:** every family in the surface inventory remains reachable, including the screens without a dedicated specimen. Existing URLs, deep links and native navigation continue to work.
- **clear-signal-emphasis.AC1.2 — Registers:** Obsign, user docs, privacy and user-facing auth support light and dark appearances. Brass Console, Custos and operator docs retain their deliberate dark register and technical voice.
- **clear-signal-emphasis.AC2.1 — Observation:** an identity shows the actual observation state and check time. Loading, missing key, stale/unavailable, unauthorized change and expired recovery are distinguishable without relying on color.
- **clear-signal-emphasis.AC2.2 — Review:** alerts open review; they never sign an override. Review retains identity, changed values, consequences and authoritative deadline through the existing confirmation path.
- **clear-signal-emphasis.AC2.3 — Identity type:** domain identities never inherit PLC verification claims or a PLC recovery countdown. Recovering identity authority never claims to restore missing content.
- **clear-signal-emphasis.AC3.1 — Operator action:** Generate claim code appears before observations and is reachable without scrolling at the 390 × 844 CSS-pixel phone reference and normal text scale, with actual app safe areas accounted for. Larger text may reflow; the action must remain reachable. The issuing host is visible before confirmation and on the result.
- **clear-signal-emphasis.AC3.2 — Failure and switching:** changing selected server cannot relabel a pending request or output. Failed requests, revoked pairings and biometric cancellation do not show a newly issued code or successful mutation.
- **clear-signal-emphasis.AC4.1 — Consent:** requester identity/origin, target identity/server, mandatory and optional grants, broad Spaces access, and unknown tokens remain inspectable. Browser and wallet agree on selected grants. Denial and all supported handoff/password paths remain available.
- **clear-signal-emphasis.AC4.2 — Expiry:** expired requests cannot be approved, show neutral restart guidance and never invent a claim that no access was previously granted. Invalid redirect targets remain rejected. Functional error and supported form paths remain readable without JavaScript.
- **clear-signal-emphasis.AC5.1 — Web completeness:** marketing preserves the complete story and actual waitlist states; docs retain audience-local navigation, search, generated references and runbook parity; instance metadata remains host-specific and public-only.
- **clear-signal-emphasis.AC5.2 — Assets and privacy:** fonts and product icons are self-hosted. Analytics retain their existing marketing-only scope. No preview helper, specimen data or demo interaction enters production.
- **clear-signal-emphasis.AC6.1 — Accessibility:** validate 7:1 normal text and 4.5:1 large text targets on actual backgrounds, 3:1 necessary non-text boundaries, visible focus, keyboard operation, VoiceOver, reduced motion, and at least 44-point app targets.
- **clear-signal-emphasis.AC6.2 — Reflow:** at 320/390 CSS pixels, desktop widths, 200% web zoom and native accessibility text sizes, required text and actions remain available. Long identifiers wrap without silent truncation. Safe areas and native sheets remain usable.

## Glossary

- **Clear Signal / Split Panel / Emphasis:** successive selected design directions; Emphasis is the approved visual treatment.
- **Register:** the visual and verbal style for an audience: humane identity management or literal technical operation.
- **Semantic token:** a named design value expressing a purpose, such as action text or alarm surface.
- **PDS:** Personal Data Server, the instance hosting an account's data and services.
- **PLC:** the directory mechanism used by `did:plc` identities; its recovery semantics do not apply to domain identities.
- **Spaces / grants:** access-controlled data spaces and the permissions requested during authorization; a broad grant can cover more than one named space.
- **IPC:** the communication boundary between the app frontend and native backend.
- **sRGB / OKLCH:** color representations used by the preview reference and production token architecture respectively.
- **Browser harness:** the existing mechanism for exercising real app screens in a browser with controlled data.
- **Runbook parity:** agreement between the canonical operational procedure and published documentation.

## Selected visual system

### Composition

The signature is **a strong conclusion pane joined to quiet supporting evidence**. The shared perimeter and seam make one object. Avoid nesting a second rounded evidence card inside it.

On the wallet, place the identity and host first, then the observation panel, everyday actions, and protection/maintenance destinations. The normal panel uses a blue conclusion with the state icon beside its heading. Supporting copy remains visible. Two labeled evidence columns show the check time and device-key availability; neither is a security score.

Warnings keep full-width deadline rows and the review action within the same panel. The meaning stays explicit in the title, icon and location. A failed check uses a neutral surface and last-known evidence; it does not turn blue simply because the request finished. Domain identities need truthful domain-specific content in this composition.

Brass Console uses the same compositional grammar for **command → issuing context → action**. The title and literal values use the operator register. Target server and biometric confirmation appear immediately above Generate. Federation/storage observations follow, with exact values and timestamps, not a combined health grade.

### Palette and semantic mapping

Preserve the existing appearance-selection behavior: Obsign follows the system appearance, and operator surfaces remain fixed dark. Retain an existing user preference only where the current product already supports it; this design introduces no new preference or persistence. The preview's manual appearance selector is a comparison tool, not product chrome.

The JSON reference contains exact sRGB values from the accepted preview. Convert them to the existing OKLCH token architecture and measure the resulting rendered pairs. Reference hex values belong in this handoff, not in app components.

| Reference role | Light Obsign | Dark Obsign | Dark operator |
| --- | --- | --- | --- |
| Page | `#FFFFFF` | `#121C2C` | `#0E1724` |
| Evidence surface | `#EEF3FA` | `#1C2C43` | `#1A2A3F` |
| Primary text | `#152641` | `#F1F5FC` | `#EDF3FC` |
| Secondary text | `#40516A` | `#BDCDE2` | `#BDCDE2` |
| Action / text | `#234BA6` / `#FFFFFF` | `#B8D4FF` / `#12284A` | same as dark Obsign |
| Strong conclusion / text | `#234BA6` / `#FFFFFF` | `#203F72` / `#F1F5FC` | same as dark Obsign |
| Alarm surface / text | `#FFEBED` / `#8B2531` | `#49262F` / `#FFD0D7` | same as dark Obsign |

Map page, surface, ink, secondary text, action, on-action, info and alarm roles to the existing `--color-*` families. Add a distinct conclusion/on-conclusion pairing: a primary button and a broad blue status region are different roles, especially in dark mode. Do not map every status to brand blue or collapse the existing safe/warning/critical/expired model into the preview's three example choices. Preserve current threshold logic; refine each semantic pairing within this palette and validate it.

The light control-outline reference `#A4B2C4` is a visual swatch, not an automatic 3:1 guarantee on every surface. Necessary control boundaries and focus indicators must pass measurement; darken or otherwise strengthen that role when needed. Decorative rules use separate low-emphasis tokens and never carry meaning alone.

### Typography, geometry and assets

Public Sans is the Obsign display and working face, including wordmarks and task headings. Brass Console uses JetBrains Mono for its wordmark, command headings and literal output, and Public Sans for supporting prose. Reuse the existing bundled font files. Libre Caslon Display is no longer the selected display voice; do not remove shared font assets until all consumers are audited.

Reference sizes describe the accepted normal-size rendering. Implement them as semantic rem/space/size tokens, with native text scaling and content-driven height. Keep the existing fixed-rem production doctrine; the prototype's `clamp()`/container-query display code is a demonstration, not a requirement to copy it.

| Element | Normal-size reference |
| --- | --- |
| Wallet body / supporting status copy | 16 / 15 px, leading 1.55 |
| Wallet identity / conclusion heading | 25 / 24 px, leading about 1.2; compact conclusion 23 px |
| Operator identity / command heading | 24 / 22 px, JetBrains Mono |
| Labels and evidence | 13 px; tabular numerals for times and aligned data |
| Phone content inset | 20 px; compact 16 px |
| Conclusion inset / icon gap | 20 px / 10 px; compact inset 18 px |
| Evidence columns | equal widths; 16 px inset after the dividing rule; stack if labels or scaled text no longer fit |
| Panel / primary-action radius | 12 / 9 px |
| Primary action / destination row minimum | 48 / 54 px in the prototype, never below the platform's 44-point target requirement |
| Web hero / reading width | bounded hero 1120 px; prose around 65 characters; phone web insets 22 px |
| Motion | short press feedback only; no looping decoration or simulated verification; instant reduced-motion path |

The [mark masters](../design/clear-signal-emphasis/assets/obsign-mark-light.svg) reproduce the preview's paired bars: two 8-unit bars separated by 3 units, heights 19 and 12, aligned at the bottom, corner radius 2. Light and dark variants use the action color. This is a brand mark, never a verification badge. Wordmarks remain typeset, not rasterized. Use the existing icon family or locally bundle the depicted Lucide equivalents consistently. App icons, favicon and social-card exports must be generated from this chosen visual language, checked at actual sizes, and wired through existing asset pipelines; do not copy the preview's browser frame into an app icon.

### Surface application

Marketing pairs a concise product proposition with a labeled example observation. Keep the primary CTA available without manipulating the specimen. The short preview feature strip stands in for the complete current story: custody, monitoring, conditional recovery, backup responsibilities, moving, capabilities, prerequisites, FAQ and waitlist remain in scope.

Docs keep a readable article column and audience-local navigation. A joined conclusion/evidence region is useful for a procedure's applicability or prerequisites, not a reason to turn every paragraph into a panel. Keep real code, generated tables, search and previous/next behavior. Custos pages stay dark; don't show a theme selector that has no effect.

Consent puts requester and permission review beside the handoff on wide screens and above it on phones. Use full labels for broad scopes and retain raw tokens where needed. Expired requests keep their requester context and restart guidance; omit actionable permission-review affordances. Do not render absent requester metadata from invented fallback values.

The PDS landing page presents the actual host's joining policy and observations. A failed health probe is “could not check,” not proof of outage. Preserve configured contact and all existing public metadata. Privacy retains the full actual policy; the specimen is only a layout sample.

## Architecture and existing patterns

Keep the current stacks: SvelteKit/Svelte 5 in both Tauri apps; zero-build marketing; Astro Starlight docs; Rust-rendered OAuth pages and the PDS landing template. The visual redesign does not require a new framework, shared runtime package, API or storage model.

- Wallet primitives live in `apps/identity-wallet/src/lib/components/ui/`. Evolve `StatusPanel`, `UrgencyBadge`, `NavRow`, `DiffRow`, `ScreenHeader`, `Button`, `TextField`, `OnboardingShell`, `SkeletonCard` and `Toggle`. Existing countdown and hold-gesture helpers retain their contracts.
- Wallet state and routing in `src/routes/+page.svelte` and its home/onboarding components remain authoritative. Keep cryptographic operations and IPC out of presentational components.
- Console primitives live in `apps/admin-companion/src/lib/components/ui/`. Evolve `ScreenShell`, `RelayStatusBlock`, `StatusChip`, `CodeOutput`, rows and controls while preserving `PinnedPairingGate` and per-server request boundaries.
- Each app keeps its own `src/lib/styles/{tokens,fonts,base}.css`. Preserve the control font reset, screen-reader utility, safe areas and theme behavior. Never hardcode hex or layout px in app components.
- Marketing `sites/marketing/assets/css/site.css`, docs `sites/docs/src/styles/theme.css`, and PDS assets/templates remain explicit consumers of the app design decisions. Update them together and preserve font parity.

**Navigation contract:** the preview is not a proposal to delete or silently rename routes. Its “Apps & agents,” “Codes & devices,” “Transfers & audit” and similar summaries represent groups of existing destinations. The implementor must map those groups to every concrete route in the inventory. Keep the existing app navigation topology and back behavior unless a separately reviewed IA change is necessary. The preview's decorative bottom navigation does not mandate new tabs or route consolidation.

## Implementation phases

Each phase ends with a working build and validation for its own changed surfaces. Create a just-in-time task plan against the then-current code; these phases describe the component-level delivery order.

<!-- START_PHASE_1 -->
### Phase 1: Token and brief foundation

**Goal:** establish both registers and reusable roles without changing behavior.

**Components:** root `DESIGN.md`, `apps/admin-companion/DESIGN.md`, both app style layers, marketing `assets/css/site.css`, docs `src/styles/theme.css`, PDS font/style declarations; existing app primitives named above.

**Dependencies:** this handoff and refreshed source inventory.

**Done when:** AC1.2, AC5.2 and the token portion of AC6 pass; both app checks/builds pass, font/px gates pass, actual color pairs are measured, and light/dark screenshots prove the two registers. Keep a mapping from old semantic tokens to new roles; avoid a blind gold-to-blue replacement.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Wallet states and tasks

**Goal:** carry Emphasis through wallet daily use, setup, review and recovery.

**Components:** `apps/identity-wallet/src/routes/+page.svelte`, `src/lib/components/home/`, `src/lib/components/onboarding/`, `src/lib/harness/scenarios.ts` and relevant existing tests.

**Dependencies:** Phase 1.

**Done when:** AC1.1, AC2 and AC6 pass for every wallet family. Verify missing key, unavailable data, authorized/unauthorized changes, deadline expiry, domain identities, consent and recovery separately. Existing frontend tests and harness-absence build checks pass; native validation covers text scaling, VoiceOver and signing safeguards. Update affected tests when behavior is intentionally changed; do not manufacture snapshot assertions that merely mirror CSS.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Brass Console

**Goal:** make the frequent action immediate while preserving exact operator context.

**Components:** `apps/admin-companion/src/routes/`, console UI primitives, `src/lib/harness/scenarios.ts` and relevant tests.

**Dependencies:** Phase 1; perform after the wallet pilot has established shared visual roles.

**Done when:** AC1.1, AC3 and AC6 pass for the console. Exercise multiple servers, no selection, revoked pairing, server switching during a request, unavailable host, biometric cancellation, issued-code sharing and entity actions. Existing app tests and harness-absence checks pass; native pairing/biometric/share behavior is verified.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: Public and authentication web

**Goal:** apply the selected identity to marketing, instance pages and the browser half of consent.

**Components:** `sites/marketing/`, `crates/pds/assets/landing.html`, `crates/pds/src/routes/oauth_templates.rs`, `crates/pds/src/routes/oauth.rs`, wallet `OAuthConsentApprovalScreen.svelte`, existing OAuth/template tests and `tools/oauth-conformance/`.

**Dependencies:** Phases 1–3, including wallet consent vocabulary.

**Done when:** AC4, marketing/instance portions of AC5, and web AC6 pass. Test no-JS errors, valid/invalid redirect behavior, all approval channels and optional-grant selection. Preserve escaping and request binding. Run affected Rust tests and OAuth conformance whenever template structure touches the consent flow. Run `just bruno-check`; update Bruno only if a route contract actually changes. Generate and verify social/favicon assets from existing pipelines.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Documentation and ecosystem verification

**Goal:** carry the implemented design through help, reference, screenshots and final cross-surface review.

**Components:** `sites/docs/astro.config.mjs`, `sites/docs/src/components/PageFrame.astro`, docs content/style trees, `tools/screenshots/{shots,capture}.mjs`, `sites/docs/public/screenshots/`, relevant published and canonical runbooks.

**Dependencies:** Phases 1–4; capture actual implemented app screens.

**Done when:** documentation AC5, remaining AC1.1 and AC6 pass; docs checks/build succeed; generated reference, runbook and font parity pass; screenshot filenames/captions match their intended screens. Finish native accessibility/appearance checks and cross-surface state review. Archive this plan and its implementation/test companions only when the production work actually lands.
<!-- END_PHASE_5 -->

## Verification and known prototype limits

Use the [validation guide](../design/clear-signal-emphasis/validation.md) to choose commands and scenarios. Browser review established visual behavior of the representative prototype, including dark/light, normal/attention/unavailable, 320-pixel warnings, expired consent, before/after and operator target placement. It did not certify the real apps, native accessibility, real auth flows or usability with participants.

The specimen's synthetic timestamps, match numbers, hosts, keys, code results and feature snippets must never become defaults in production. Its buttons either navigate to another specimen or describe a local concept. The final build uses the existing real data and action seams. No recommendation here changes keys, credentials, Keychain/iCloud identities, bundle IDs, notifications, signing, HTTP schemas or analytics policy.
