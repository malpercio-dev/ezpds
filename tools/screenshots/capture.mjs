/**
 * Harness-driven documentation screenshots (docs.AC4).
 *
 * Boots nothing itself — the orchestrator (`scripts/docs-screenshots.sh`) starts each app's
 * browser harness in fake mode (`VITE_HARNESS=fake`) and this driver connects to them. For
 * every shot in `shots.mjs` it opens a clean browser context, seeds the named scenario, walks
 * the interaction steps to reach the screen (or an injected error state), and writes a
 * deterministic PNG under `sites/docs/public/screenshots/<app>/`.
 *
 * Determinism (docs.AC4.3): the browser clock is frozen to `FIXED_CLOCK` and animations are
 * disabled, so relative-time UI and transitions render identically every run. The harness is
 * the fake in-memory backend, so there is no network or `Date.now()` reliance. Because the
 * apps run as plain frontends here (no Tauri shell), this runs on a Linux runner (docs.AC4.4).
 *
 * Usage:
 *   node capture.mjs                 # regenerate every screenshot
 *   node capture.mjs --check         # re-render and diff against the committed PNGs (visual-diff)
 *   node capture.mjs --app wallet    # limit to one app (wallet|admin)
 *   node capture.mjs --only home     # limit to shots whose `out` matches (substring)
 *
 * Fidelity caveat (inherited from the harness): these are browser renders, not device renders —
 * no Keychain/Secure-Enclave, biometric prompt, WKWebView specifics, or safe-area insets.
 */
import { chromium } from '@playwright/test';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APPS,
  SHOTS,
  FIXED_CLOCK,
  VIEWPORT,
  DEVICE_SCALE_FACTOR,
} from './shots.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** The pre-installed Chromium in this environment; falls back to Playwright's own download in CI. */
const PREINSTALLED_CHROMIUM = '/opt/pw-browsers/chromium';

/** Injected once per context: freeze scenario selection and kill motion for stable pixels. */
const DISABLE_MOTION_CSS = `
  *, *::before, *::after {
    transition-duration: 0s !important;
    animation-duration: 0s !important;
    animation-delay: 0s !important;
    scroll-behavior: auto !important;
    caret-color: transparent !important;
  }
`;

function parseArgs(argv) {
  const args = { check: false, app: null, only: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--check') args.check = true;
    else if (a === '--app') args.app = argv[++i];
    else if (a === '--only') args.only = argv[++i];
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (args.app && !APPS[args.app]) {
    throw new Error(`Unknown --app '${args.app}'. Known: ${Object.keys(APPS).join(', ')}`);
  }
  return args;
}

/** Run one shot's interaction step against a live page. */
async function runStep(page, step) {
  if (step.click) {
    await page.locator(step.click).first().click();
  } else if (step.clickText) {
    await page.getByText(step.clickText, { exact: false }).first().click();
  } else if (step.fill) {
    const [selector, value] = step.fill;
    await page.locator(selector).first().fill(value);
  } else if (step.failNext) {
    const [command, error] = step.failNext;
    await page.evaluate(
      ([c, e]) => window.__harness.failNext(c, e),
      [command, error]
    );
  } else if (step.waitFor) {
    await page.locator(step.waitFor).first().waitFor({ state: 'visible' });
  } else if (step.waitForText) {
    await page.getByText(step.waitForText, { exact: false }).first().waitFor({ state: 'visible' });
  } else {
    throw new Error(`Unrecognized step: ${JSON.stringify(step)}`);
  }
}

/** Render one shot to a PNG buffer. */
async function renderShot(browser, app, shot) {
  const context = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: DEVICE_SCALE_FACTOR,
    reducedMotion: 'reduce',
    // A clean context per shot: sessionStorage (the scenario pointer) never leaks between shots.
  });
  // Seed the scenario before any app script runs, so the harness installs it on first load
  // (no reload race). The key mirrors `control.ts` SCENARIO_KEY in both apps.
  await context.addInitScript((name) => {
    try {
      sessionStorage.setItem('ezpds-harness-scenario', name);
    } catch {
      // sessionStorage may be unavailable; the harness falls back to its default scenario.
    }
  }, shot.scenario);

  const page = await context.newPage();
  await page.clock.setFixedTime(new Date(FIXED_CLOCK));

  try {
    const target = `http://localhost:${app.port}${shot.goto ?? '/'}`;
    await page.goto(target, { waitUntil: 'networkidle' });

    for (const step of shot.steps ?? []) {
      await runStep(page, step);
    }
    if (shot.waitForText) {
      await page.getByText(shot.waitForText, { exact: false }).first().waitFor({ state: 'visible' });
    }
    if (shot.waitFor) {
      await page.locator(shot.waitFor).first().waitFor({ state: 'visible' });
    }

    // Settle: let the fake's async loads and any reflow finish, then hard-stop motion.
    await page.waitForLoadState('networkidle');
    await page.addStyleTag({ content: DISABLE_MOTION_CSS });
    await page.waitForTimeout(400);

    return await page.screenshot({ fullPage: true, animations: 'disabled' });
  } finally {
    await context.close();
  }
}

/** Pixel-diff two PNG buffers; returns { changed, diffPixels, total } and an optional diff PNG buffer. */
function diffPng(expectedBuf, actualBuf) {
  const expected = PNG.sync.read(expectedBuf);
  const actual = PNG.sync.read(actualBuf);
  if (expected.width !== actual.width || expected.height !== actual.height) {
    return { changed: true, diffPixels: Infinity, total: 0, reason: 'dimensions differ', diff: null };
  }
  const { width, height } = expected;
  const diff = new PNG({ width, height });
  const diffPixels = pixelmatch(expected.data, actual.data, diff.data, width, height, {
    threshold: 0.1,
  });
  return {
    changed: diffPixels > 0,
    diffPixels,
    total: width * height,
    diff: diffPixels > 0 ? PNG.sync.write(diff) : null,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const appNames = args.app ? [args.app] : Object.keys(APPS);

  const launchOptions = {};
  if (existsSync(PREINSTALLED_CHROMIUM)) {
    // Use the environment's pre-installed Chromium instead of downloading (the revision may
    // differ from @playwright/test's default; the harness renders identically either way).
    launchOptions.executablePath = PREINSTALLED_CHROMIUM;
  }
  const browser = await chromium.launch(launchOptions);

  const failures = [];
  let written = 0;
  let checked = 0;

  try {
    for (const appName of appNames) {
      const app = APPS[appName];
      const outDir = join(REPO_ROOT, app.outDir);
      const diffDir = join(REPO_ROOT, 'tools/screenshots/diff', appName);
      if (!args.check) mkdirSync(outDir, { recursive: true });

      for (const shot of SHOTS[appName]) {
        if (args.only && !shot.out.includes(args.only)) continue;

        const outPath = join(outDir, `${shot.out}.png`);
        const label = `${appName}/${shot.out}`;
        process.stdout.write(`  ${args.check ? 'check' : 'shoot'} ${label} … `);

        let actual;
        try {
          actual = await renderShot(browser, app, shot);
        } catch (e) {
          process.stdout.write('FAILED\n');
          failures.push(`${label}: render error: ${e.message}`);
          continue;
        }

        if (args.check) {
          checked++;
          if (!existsSync(outPath)) {
            process.stdout.write('MISSING baseline\n');
            failures.push(`${label}: no committed baseline at ${app.outDir}/${shot.out}.png`);
            continue;
          }
          const result = diffPng(readFileSync(outPath), actual);
          if (result.changed) {
            mkdirSync(diffDir, { recursive: true });
            writeFileSync(join(diffDir, `${shot.out}.actual.png`), actual);
            if (result.diff) writeFileSync(join(diffDir, `${shot.out}.diff.png`), result.diff);
            const detail = result.reason ?? `${result.diffPixels} px changed`;
            process.stdout.write(`CHANGED (${detail})\n`);
            failures.push(`${label}: image changed (${detail}) — see tools/screenshots/diff/${appName}/`);
          } else {
            process.stdout.write('ok\n');
          }
        } else {
          writeFileSync(outPath, actual);
          written++;
          process.stdout.write('ok\n');
        }
      }
    }
  } finally {
    await browser.close();
  }

  if (args.check) {
    if (failures.length > 0) {
      console.error(`\n✗ ${failures.length} screenshot(s) drifted or are missing:`);
      for (const f of failures) console.error(`  - ${f}`);
      console.error(
        '\nIf the change is intentional, regenerate with `just docs-screenshots` and commit the PNGs.'
      );
      process.exit(1);
    }
    // No drift: the throwaway diff dir (if any) is irrelevant.
    rmSync(join(REPO_ROOT, 'tools/screenshots/diff'), { recursive: true, force: true });
    console.log(`\n✓ ${checked} screenshot(s) match the committed baselines.`);
  } else {
    if (failures.length > 0) {
      console.error(`\n✗ ${failures.length} screenshot(s) failed to render:`);
      for (const f of failures) console.error(`  - ${f}`);
      process.exit(1);
    }
    console.log(`\n✓ wrote ${written} screenshot(s).`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
