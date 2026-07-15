/**
 * The screenshot manifest: every deterministic app image the docs sites embed.
 *
 * Each shot names a browser-harness scenario preset (the same names
 * `window.__harness.scenario(...)` accepts), an optional route to navigate to, and an
 * optional list of interaction steps to reach a screen or an injected error state. The
 * capture driver (`capture.mjs`) boots each app's harness (`VITE_HARNESS=fake`), replays
 * the steps, and writes `<out>.png` under that app's screenshot directory.
 *
 * Determinism is a hard requirement (docs.AC4.3): every shot must reach the same pixels on
 * every run. The driver freezes the browser clock to `FIXED_CLOCK` and disables animations,
 * so relative-time UI (uptime, sweep ages, recovery-window countdowns) and transitions are
 * stable. Keep steps to stable selectors — `aria-label`, visible text, or the semantic
 * classes the components already carry — never nth-child positional chains.
 *
 * Step vocabulary (each step is one key):
 *   { click: '<css selector>' }          – click the first match
 *   { clickText: '<text>' }              – click the first element whose text matches
 *   { fill: ['<selector>', '<value>'] }  – fill an input
 *   { failNext: ['<command>', <error>] } – arm a one-shot IPC failure (window.__harness.failNext)
 *   { waitFor: '<css selector>' }        – wait for a selector to be visible
 *   { waitForText: '<text>' }            – wait for text to appear
 */

/**
 * The instant the browser clock is frozen at for every shot. Matches the reference clock the
 * harness scenarios use (`scenarios.ts` `isoHoursAgo`), so seeded ages line up predictably.
 */
export const FIXED_CLOCK = '2026-07-15T12:00:00.000Z';

/** iPhone-ish portrait frame at 2x, so the renders read as phone screens without a device chrome. */
export const VIEWPORT = { width: 390, height: 844 };
export const DEVICE_SCALE_FACTOR = 2;

/**
 * The two harness surfaces. `port` matches each app's `vite.config.ts` dev port so the
 * orchestrator and driver agree without a handshake.
 */
export const APPS = {
  wallet: {
    label: 'Obsign (identity-wallet)',
    dir: 'apps/identity-wallet',
    port: 5173,
    outDir: 'sites/docs/public/screenshots/wallet',
  },
  admin: {
    label: 'Custos operator console (admin-companion)',
    dir: 'apps/admin-companion',
    port: 5174,
    outDir: 'sites/docs/public/screenshots/admin',
  },
};

/** Wallet (Obsign) shots — the app is a single-page state machine, so screens are reached by clicking. */
const WALLET_SHOTS = [
  {
    out: 'welcome',
    scenario: 'fresh-install',
    waitForText: 'Your self-sovereign identity',
    caption: 'First launch — create or import an identity.',
  },
  {
    out: 'home',
    scenario: 'one-identity',
    waitForText: 'All identities secure',
    caption: 'The home surface: your seals, with tamper monitoring live.',
  },
  {
    out: 'home-multi',
    scenario: 'multi-identity',
    waitForText: 'Your seals',
    caption: 'Several identities held in one wallet; the root-key badge is per identity.',
  },
  {
    out: 'identity-detail',
    scenario: 'one-identity',
    steps: [{ click: 'button.card' }],
    waitForText: 'DID document',
    caption: 'An identity’s DID document, decoded.',
  },
  {
    out: 'settings',
    scenario: 'one-identity',
    steps: [{ click: '[aria-label="Settings"]' }],
    caption: 'Appearance and app settings.',
  },
  {
    out: 'agents',
    scenario: 'agent-connected',
    steps: [{ click: 'button.agents-row' }],
    caption: 'Agents you have authorised to act on your behalf.',
  },
  {
    out: 'home-alert',
    scenario: 'alert-active',
    waitForText: 'need your attention',
    caption: 'A tamper alert: an unauthorised change to the public record was detected.',
    rareState: true,
  },
  {
    out: 'alert-detail',
    scenario: 'alert-active',
    steps: [{ click: 'button.alert-strip' }],
    caption: 'The alert detail with a live recovery-window countdown.',
    rareState: true,
  },
  {
    out: 'home-load-error',
    scenario: 'one-identity',
    steps: [
      { waitForText: 'All identities secure' },
      { failNext: ['list_identities', { code: 'KEYCHAIN_ERROR' }] },
      { click: '[aria-label="Refresh"]' },
    ],
    waitForText: 'Failed to load identities',
    caption: 'An injected local failure surfaces inline with a retry, never a dead end.',
    errorState: true,
  },
];

/** Admin (Custos operator console) shots — file-based routes, so most are a direct navigation. */
const ADMIN_SHOTS = [
  {
    out: 'home',
    scenario: 'single-relay',
    waitForText: 'claim code',
    caption: 'Mint a single-use, device-signed account claim code for the active relay.',
  },
  {
    out: 'home-unpaired',
    scenario: 'unpaired',
    waitForText: 'Pair this device',
    caption: 'Before pairing: no relay is bound to this operator device yet.',
  },
  {
    out: 'pair',
    scenario: 'unpaired',
    goto: '/pair',
    caption: 'Pair a device with a relay by QR or manual entry.',
  },
  {
    out: 'accounts',
    scenario: 'multi-relay',
    goto: '/accounts',
    caption: 'Every account on one relay, searchable, with per-row blob quota.',
  },
  {
    out: 'codes',
    scenario: 'single-relay',
    goto: '/codes',
    caption: 'The claim-code inventory: outstanding credentials and history.',
  },
  {
    out: 'transfers',
    scenario: 'multi-relay',
    goto: '/transfers',
    caption: 'In-flight device transfers an operator can watch and cancel.',
  },
  {
    out: 'devices',
    scenario: 'single-relay',
    goto: '/devices',
    caption: 'Admin devices registered on one relay, with remote revoke for a lost device.',
  },
  {
    out: 'moderation',
    scenario: 'single-relay',
    goto: '/moderation',
    caption: 'Account takedown/restore and credential revocation, each armed and gated.',
  },
  {
    out: 'status',
    scenario: 'single-relay',
    goto: '/status',
    caption: 'One relay’s server health as it reports it — facts only.',
  },
  {
    out: 'status-degraded',
    scenario: 'degraded-health',
    goto: '/status',
    caption: 'A degraded relay: stale background sweeps flagged by glyph, never colour alone.',
    rareState: true,
  },
  {
    out: 'settings',
    scenario: 'multi-relay',
    goto: '/settings',
    caption: 'Per-relay pairings, the global admin key, and the biometric toggle.',
  },
];

/** The full manifest, keyed by app. */
export const SHOTS = {
  wallet: WALLET_SHOTS,
  admin: ADMIN_SHOTS,
};
