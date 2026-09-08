# Validation guide

This separates checks on the design package from checks required when implementing the production redesign.

## Handoff package

- Open `preview.html` outside Codex; verify surface, theme, state and width controls and the before/after view.
- Confirm alert → review preserves identity/deadline, unavailable requests never manufacture success, and expired consent offers restart guidance.
- Inspect dark/light wallet, both apps, 320-pixel warning/consent, marketing desktop/mobile, docs and the instance page. Check keyboard focus and browser errors.
- Check relative links and assets, JSON/SVG validity, and equality of the fragment embedded in the standalone export with `preview.fragment.html`.
- Verify the committed fragment matches the selected final visual and its font data matches the existing repository fonts.
- Run `bash scripts/plan-status-check.sh`, `bash scripts/adr-ref-check.sh`, `bash scripts/font-parity.sh` and `git diff --check` for this documentation/asset change.

Opening the standalone preview does not require Nix or a build. Its shell uses pinned external icon/positioning helpers as documented in the package README; production must not inherit those dependencies.

## Implementation environment

Use the project's Nix/devenv shell, from the repository root. Do not install tools globally:

```sh
nix develop --impure --accept-flake-config
```

Run the commands below inside that shell, with each app's package dependencies already installed through its documented workflow. Recheck commands against the current `justfile` and package manifests before starting a later implementation.

## Frontend and native apps

```sh
pnpm --dir apps/identity-wallet check
pnpm --dir apps/identity-wallet test
pnpm --dir apps/identity-wallet build
pnpm --dir apps/identity-wallet check:harness-absence
pnpm --dir apps/admin-companion check
pnpm --dir apps/admin-companion test
pnpm --dir apps/admin-companion build
pnpm --dir apps/admin-companion check:harness-absence
just px-check
just font-check
just cap-check
```

Start each fake harness in its own terminal using `pnpm --dir apps/identity-wallet dev:harness` or `pnpm --dir apps/admin-companion dev:harness`. Inspect `window.__harness.scenarios` and each app's `src/lib/harness/scenarios.ts`; use named scenarios and `failNext` from the app's AGENTS runbook. Do not mix real user identities or production admin credentials into design testing.

| Scenario | Evidence required |
| --- | --- |
| Wallet routine, checking and stale | Actual check time; no fresh all-clear from missing data; everyday actions reachable |
| Unauthorized PLC change, approaching/closed deadline | Identity, before/after, authoritative deadline, review before signing; expired action cannot sign |
| Missing key / domain identity / server gone | Distinct explanations and supported next actions; no borrowed PLC guarantee or content-restoration promise |
| Consent and delegated access | Real optional/base/broad/unknown scopes remain legible and match browser choices |
| Operator unpaired/revoked/multi-server | Clear selected host, re-pairing path, request/result target stays pinned during switching |
| Code pending/failure/cancel/success | No premature success; issuing host on output; actual biometric and sharing flow |
| Empty/error/partial collections | Accounts, devices, codes, Spaces, transfers, audit and diagnostics remain operable |
| Long content and accessibility | Handles, DIDs, URLs and translated-length text wrap; 200% zoom, large text, keyboard and reduced motion work |

Native validation is separate: VoiceOver, Dynamic Type including accessibility sizes, safe areas, light/dark system appearance, biometric cancellation, camera permission, deep links, notifications and share sheets. Use the documented iOS PR checks (`just ios-pr-check`, `just admin-pr-check`) and a simulator/device for the interactions that the browser fake cannot certify. Preserve the existing signing and key-store boundaries.

## Web, docs and PDS templates

```sh
pnpm --dir sites/docs check
pnpm --dir sites/docs build
just docs-check
just runbook-parity-check
just capability-docs-check
just bruno-check
just docs-screenshots
```

Marketing is zero-build; serve it locally and verify the full content and waitlist's disabled/validation/error/success branches without submitting real addresses. Inspect network requests to confirm analytics remain marketing-only and no runtime font/icon CDN was added.

For landing/OAuth template changes, run affected PDS tests (`cargo test -p pds`, narrowed while iterating if needed), then the existing OAuth conformance workflow (`just oauth-conformance-setup` once, `just oauth-conformance-test` with its documented PDS prerequisites). Verify HTML escaping, no-JS error/form paths, request expiry, invalid redirects and the actual browser/wallet scope contract. If changing endpoint shape or auth, update Bruno alongside it; cosmetic template changes alone do not justify a new API.

Regenerate documentation screenshots from the implemented apps using the existing `tools/screenshots` runbook, and inspect each filename/caption against the depicted route. Visual drift checks are intentionally separate from the full CI gate because font rendering can vary by runner.

## Contrast and final review

Use the selected token roles, not a global color replacement. Measure every actual text/background pairing, including disabled controls, tinted warning panes, secondary labels and focus indicators. Target 7:1 normal and 4.5:1 large text; necessary non-text boundaries need 3:1. The prototype's decorative rules are not suitable substitutes for essential control outlines.

The selected sample pairs previously measured above 7:1 are documented in the archived Clear Signal study. Those measurements do not certify new pairings, converted OKLCH values, generated icons or native behavior. Compare representative screens at 320/390, 768 and 1024/1440 CSS pixels, plus 200% zoom and actual iOS accessibility sizes. Give color-independent status and complete literal values priority over matching a screenshot's line breaks.

Run the repository gates relevant to each change and the required CI lanes before release. This handoff PR does not run or claim the production app/PDS suites because no production code is modified.
