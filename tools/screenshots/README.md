# Docs screenshots

Playwright-driven documentation screenshots. Boots each mobile app's **browser test
harness** in fake mode (`VITE_HARNESS=fake`) and drives it across named scenarios —
happy paths plus error/rare states — to capture deterministic PNGs into
`sites/docs/public/screenshots/`, so the documentation sites' app imagery tracks the real
UI and cannot go stale silently.

This implements Phase 4 (docs.AC4) of
[docs/design-plans/2026-07-14-documentation-sites.md](../../docs/design-plans/2026-07-14-documentation-sites.md).
It reuses the browser harness from
[docs/design-plans/2026-07-12-browser-harness.md](../../docs/design-plans/2026-07-12-browser-harness.md)
(MM-324) — the same `window.__harness.scenario(...)` / `failNext(...)` control surface.

## Run it

From the repo root:

```bash
just docs-screenshots          # regenerate every screenshot, then commit the PNGs
just docs-screenshots-check    # re-render and fail on any drift from the committed PNGs
```

Both wrap `scripts/docs-screenshots.sh`, which installs deps if missing, starts (or reuses)
each app's harness dev server, runs the capture, and tears the servers down. Flags pass
through:

```bash
just docs-screenshots --app admin            # one app only (wallet | admin)
just docs-screenshots --only status          # shots whose name contains "status"
```

## How it stays deterministic (docs.AC4.3)

- The browser clock is frozen to a fixed instant (`FIXED_CLOCK` in `shots.mjs`), so
  relative-time UI — uptime, background-sweep ages, the recovery-window countdown — renders
  the same every run.
- The harness is an in-memory fake: no network, no `Date.now()` reliance.
- Animations and transitions are disabled before each capture.

Because the harness runs the app frontends without the native Tauri shell, this runs on a
plain **Linux** runner — no macOS/Xcode (docs.AC4.4).

## Fidelity caveat

These are browser renders, not device renders. They do **not** show the real
Keychain/Secure-Enclave, the biometric prompt, WKWebView-specific rendering, or iOS
safe-area insets — the same boundary the browser harness itself carries. Good for feature
documentation; not a substitute for device/simulator imagery. The docs gallery pages state
this where it matters.

## Files

- `shots.mjs` — the manifest: every screenshot's scenario, navigation steps, and output name.
  Add a shot here.
- `capture.mjs` — the driver: launches Chromium, seeds each scenario, walks the steps, and
  writes PNGs (or, with `--check`, pixel-diffs against the committed baselines and writes a
  diff image under `diff/` on drift).
- `../../scripts/docs-screenshots.sh` — the orchestrator (dev-server lifecycle + capture).

## Adding a screenshot

1. Add an entry to `SHOTS` in `shots.mjs` (pick an existing harness scenario; use `steps`
   to click into a screen or arm a `failNext` error).
2. Run `just docs-screenshots` to generate the PNG.
3. Reference it from a docs page under `sites/docs/src/content/docs/` and commit both.

## Browsers

In this managed environment Chromium is pre-installed at `/opt/pw-browsers/chromium`;
`capture.mjs` launches it directly, so nothing is downloaded. On a runner without it, the
orchestrator runs `playwright install chromium` first.
