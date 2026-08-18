<script lang="ts">
  import { onMount } from 'svelte';
  import ScreenHeader from '$lib/components/ui/ScreenHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Toggle from '$lib/components/ui/Toggle.svelte';
  import {
    readLocalMirror,
    setAppearance,
    type AppearancePreference,
  } from '$lib/appearance';
  import {
    exportDiagnostics,
    shareTextNative,
    getBackgroundBackupSettings,
    setBackgroundBackupSettings,
    getNotificationDiagnostics,
    clearNotificationFailures,
    type BackgroundBackupSettings,
    type NotificationDiagnostics,
  } from '$lib/ipc';
  import {
    summarizeNotificationFailures,
    type NotificationHealth,
  } from '$lib/notification-health';
  import {
    describeRegistration,
    registrationRecords,
  } from '$lib/notification-registration';
  import { loadIdentityCards, type IdentityCard } from '$lib/identity-cards';

  let { onback }: { onback: () => void } = $props();

  // ── Notification health ─────────────────────────────────────────────────────
  // The in-app half of the unverified notice. iOS will not let the Notification Service
  // Extension suppress an alert push, so a payload this device cannot verify still shows a
  // banner saying so — and that banner cannot say WHY. The extension leaves a breadcrumb for
  // each one; this reads them back and states the difference between a key desync (fixable by
  // opening the app) and a relay sending junk (grounds for switching relays).
  let notifications = $state<NotificationDiagnostics | null>(null);
  let notificationsUnavailable = $state(false);
  let clearingFailures = $state(false);

  const notificationHealth = $derived<NotificationHealth | null>(
    notifications ? summarizeNotificationFailures(notifications.recentFailures) : null
  );
  /** Whether this device has ever minted its notification key — i.e. whether push is set up. */
  const notificationsConfigured = $derived(notifications?.notificationKeyId != null);

  // ── Registration by identity ────────────────────────────────────────────────
  // The other half of notification health. The breadcrumb summary above can only describe
  // pushes that ARRIVED broken; an identity whose registration fails on every app open
  // receives nothing at all, and used to read as perfect health here. These rows state, per
  // identity, whether this launch's registration pass succeeded — and when it didn't, why
  // and what fixes it.
  let identityCards = $state<IdentityCard[]>([]);

  async function loadRegistrationIdentities() {
    try {
      identityCards = await loadIdentityCards();
    } catch (e) {
      console.error('Failed to list identities for the registration readout:', e);
      // An empty list hides the rows rather than rendering a wrong one.
      identityCards = [];
    }
  }

  /** The mark glyph + screen-reader prefix for a health level (shared with the summary above). */
  function levelMark(level: 'quiet' | 'info' | 'attention'): { glyph: string; prefix: string } {
    if (level === 'attention') return { glyph: '!', prefix: 'Needs attention: ' };
    if (level === 'info') return { glyph: 'i', prefix: 'For information: ' };
    return { glyph: '✓', prefix: 'All clear: ' };
  }

  async function loadNotifications() {
    try {
      notifications = await getNotificationDiagnostics();
      notificationsUnavailable = false;
    } catch (e) {
      console.error('Failed to read notification diagnostics:', e);
      // Say nothing rather than claim health. This surface exists for the case where something
      // is already wrong; "No notification problems" over a failed read would be the one
      // sentence it must never produce.
      notifications = null;
      notificationsUnavailable = true;
    }
  }

  async function acknowledgeFailures() {
    clearingFailures = true;
    try {
      await clearNotificationFailures();
      await loadNotifications();
    } catch (e) {
      console.error('Failed to clear notification failures:', e);
    } finally {
      clearingFailures = false;
    }
  }

  // ── Background media-backup settings ────────────────────────────────────────
  // App-global (the background sweep is one task covering every opted-in identity).
  // "Only while charging" and "Wi-Fi only" refine the background pass, so they're
  // inert while it's off. Defaults match the backend; the real value loads on mount.
  let bgBackup = $state<BackgroundBackupSettings>({
    backgroundEnabled: true,
    requireExternalPower: false,
    wifiOnly: false,
  });
  let bgSaveError = $state(false);

  onMount(async () => {
    try {
      bgBackup = await getBackgroundBackupSettings();
    } catch (e) {
      console.error('Failed to load media-backup settings:', e);
      // Keep the defaults; a failed read must not present a wrong state as if saved.
    }
    await loadNotifications();
    await loadRegistrationIdentities();
  });

  async function updateBgBackup(patch: Partial<BackgroundBackupSettings>) {
    const prev = bgBackup;
    bgBackup = { ...bgBackup, ...patch }; // optimistic — the switch flips instantly
    bgSaveError = false;
    try {
      bgBackup = await setBackgroundBackupSettings(bgBackup);
    } catch (e) {
      console.error('Failed to save media-backup settings:', e);
      bgBackup = prev; // revert so the UI never claims a change that didn't persist
      bgSaveError = true;
    }
  }

  // initAppearance() reconciled the mirror against the Keychain at launch,
  // so the mirror is authoritative by the time this screen opens.
  let selected = $state<AppearancePreference>(readLocalMirror());
  let saveError = $state(false);

  const OPTIONS: { value: AppearancePreference; label: string }[] = [
    { value: 'system', label: 'System' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
  ];

  let segmentEls: (HTMLButtonElement | undefined)[] = Array.from(
    { length: OPTIONS.length },
    () => undefined
  );

  async function choose(preference: AppearancePreference) {
    selected = preference;
    saveError = false;
    try {
      // Applies instantly (inline color-scheme + localStorage mirror);
      // the awaited part is only the durable Keychain write.
      await setAppearance(preference);
    } catch (e) {
      console.error('Failed to persist appearance preference:', e);
      saveError = true;
    }
  }

  // ── Diagnostics export ──────────────────────────────────────────────────
  // A user-initiated share of the session's redacted network-error log. The report is
  // built on the Rust side (operation names, server hosts, HTTP statuses, short error
  // codes only — no tokens, bodies, handles, or DIDs) and handed to the native share
  // sheet. Nothing is collected passively, so there is no opt-in toggle to manage.
  let exportBusy = $state(false);
  let exportError = $state(false);

  async function shareDiagnostics() {
    exportBusy = true;
    exportError = false;
    try {
      const report = await exportDiagnostics();
      await shareTextNative(report);
    } catch (e) {
      console.error('Failed to export diagnostics:', e);
      exportError = true;
    } finally {
      exportBusy = false;
    }
  }

  /** Radiogroup keyboard pattern: arrows move selection, focus follows. */
  function onSegmentKeydown(event: KeyboardEvent, index: number) {
    let next: number;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      next = (index + 1) % OPTIONS.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      next = (index - 1 + OPTIONS.length) % OPTIONS.length;
    } else {
      return;
    }
    event.preventDefault();
    segmentEls[next]?.focus();
    choose(OPTIONS[next].value);
  }
</script>

<div class="screen">
  <ScreenHeader title="Settings" {onback} />

  <section class="group" aria-labelledby="appearance-title">
    <div class="group-head">
      <h2 class="group-title" id="appearance-title">Appearance</h2>
      <p class="group-sub">System follows your iPhone’s appearance setting.</p>
    </div>

    <div class="segmented" role="radiogroup" aria-labelledby="appearance-title">
      {#each OPTIONS as opt, i (opt.value)}
        <button
          bind:this={segmentEls[i]}
          class="segment"
          class:segment--selected={selected === opt.value}
          role="radio"
          aria-checked={selected === opt.value}
          tabindex={selected === opt.value ? 0 : -1}
          onclick={() => choose(opt.value)}
          onkeydown={(e) => onSegmentKeydown(e, i)}
        >
          {#if selected === opt.value}
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2.6"
              stroke-linecap="round"
              stroke-linejoin="round"
              aria-hidden="true"
            >
              <path d="m5 12 5 5L20 7" />
            </svg>
          {/if}
          {opt.label}
        </button>
      {/each}
    </div>

    {#if saveError}
      <p class="save-error" role="alert">
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </svg>
        Couldn’t save this choice to your device. It applies now, but may not stick after a
        relaunch.
      </p>
    {/if}
  </section>

  <section class="group" aria-labelledby="media-backup-title">
    <div class="group-head">
      <h2 class="group-title" id="media-backup-title">Media backup</h2>
      <p class="group-sub">
        For identities with media backup turned on, keep the iCloud copy up to date in the
        background — so media stays protected without opening the app.
      </p>
    </div>

    <Toggle
      label="Back up in the background"
      description="Let your iPhone refresh your backups on its own. Off backs up only when you open the app."
      checked={bgBackup.backgroundEnabled}
      onchange={(v) => updateBgBackup({ backgroundEnabled: v })}
    />

    <div class="sub-toggles">
      <Toggle
        label="Only while charging"
        description="Wait until your iPhone is plugged in."
        checked={bgBackup.requireExternalPower}
        disabled={!bgBackup.backgroundEnabled}
        onchange={(v) => updateBgBackup({ requireExternalPower: v })}
      />
      <Toggle
        label="Use Wi-Fi only"
        description="Skip background backups on cellular data."
        checked={bgBackup.wifiOnly}
        disabled={!bgBackup.backgroundEnabled}
        onchange={(v) => updateBgBackup({ wifiOnly: v })}
      />
    </div>

    {#if bgSaveError}
      <p class="save-error" role="alert">
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </svg>
        Couldn’t save this setting to your device. Please try again.
      </p>
    {/if}
  </section>

  <section class="group" aria-labelledby="notifications-title">
    <div class="group-head">
      <h2 class="group-title" id="notifications-title">Notifications</h2>
      <p class="group-sub">
        Notifications from your server arrive sealed and are opened on this iPhone. When one
        can’t be opened, your phone still shows it — marked as unverified — and records why
        here.
      </p>
    </div>

    {#if notificationsUnavailable}
      <p class="notice notice--info" role="status">
        <span class="notice-mark" aria-hidden="true">?</span>
        <span class="notice-text">
          <span class="notice-headline">Couldn’t read notification status</span>
          <span class="notice-detail">Try again after reopening Obsign.</span>
        </span>
      </p>
    {:else if !notificationsConfigured}
      <p class="notice notice--info" role="status">
        <span class="notice-mark" aria-hidden="true">·</span>
        <span class="notice-text">
          <span class="notice-headline">Not set up on this iPhone yet</span>
          <span class="notice-detail">
            Sealed notifications start once an identity registers this device with its server.
          </span>
        </span>
      </p>
    {:else if notificationHealth}
      <!-- The level is carried by the mark glyph, the headline wording, and the screen-reader
           prefix — never by the tint alone (DESIGN.md: status is never colour-only). -->
      <p
        class="notice notice--{notificationHealth.level}"
        role={notificationHealth.level === 'attention' ? 'alert' : 'status'}
      >
        <span class="notice-mark" aria-hidden="true">
          {notificationHealth.level === 'attention'
            ? '!'
            : notificationHealth.level === 'info'
              ? 'i'
              : '✓'}
        </span>
        <span class="notice-text">
          <span class="notice-headline">
            <span class="sr-only">
              {notificationHealth.level === 'attention'
                ? 'Needs attention: '
                : notificationHealth.level === 'info'
                  ? 'For information: '
                  : 'All clear: '}
            </span>
            {notificationHealth.headline}
          </span>
          <span class="notice-detail">{notificationHealth.detail}</span>
          {#if notificationHealth.advice}
            <span class="notice-advice">{notificationHealth.advice}</span>
          {/if}
        </span>
      </p>

      {#if notificationHealth.count > 0}
        <Button variant="secondary" disabled={clearingFailures} onclick={acknowledgeFailures}>
          {clearingFailures ? 'Clearing…' : 'Clear this record'}
        </Button>
      {/if}
    {/if}

    {#if identityCards.length > 0}
      <!-- Per-identity registration state: whether this launch's registration pass succeeded
           for each identity. Complements the breadcrumb summary above, which can only describe
           pushes that arrived — an identity that never registered receives nothing, and these
           rows are the one place that says so. Level is carried by mark + wording + the
           screen-reader prefix, never tint alone. -->
      <div class="reg-list" role="list" aria-label="Notification registration by identity">
        <h3 class="reg-title">Delivery by identity</h3>
        {#each identityCards as card (card.did)}
          {@const health = describeRegistration($registrationRecords[card.did])}
          {@const mark = levelMark(health.level)}
          <p
            class="notice notice--{health.level}"
            role={health.level === 'attention' ? 'alert' : 'status'}
          >
            <span class="notice-mark" aria-hidden="true">{mark.glyph}</span>
            <span class="notice-text">
              <span class="notice-headline">
                <span class="sr-only">{mark.prefix}</span>
                <span class="reg-identity">{card.handle ?? card.did}</span>
                — {health.headline}
              </span>
              <span class="notice-detail">{health.detail}</span>
              {#if health.advice}
                <span class="notice-advice">{health.advice}</span>
              {/if}
            </span>
          </p>
        {/each}
      </div>
    {/if}
  </section>

  <section class="group" aria-labelledby="diagnostics-title">
    <div class="group-head">
      <h2 class="group-title" id="diagnostics-title">Diagnostics</h2>
      <p class="group-sub">
        Share a log of this session’s network errors when troubleshooting. It lists operation
        names, server addresses, and error codes only — never your keys, tokens, or account
        details.
      </p>
    </div>

    <Button variant="secondary" disabled={exportBusy} onclick={shareDiagnostics}>
      {exportBusy ? 'Preparing…' : 'Export diagnostics'}
    </Button>

    {#if exportError}
      <p class="save-error" role="alert">
        <svg
          width="13"
          height="13"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M10.3 3.2 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.2a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
        </svg>
        Couldn’t open the share sheet just now. Please try again.
      </p>
    {/if}
  </section>
</div>

<style>
  .screen {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: var(--space-lg) var(--space-md) var(--space-xl);
    gap: var(--space-md);
    overflow-y: auto;
  }

  /* One parchment group, flat at rest — depth is a tonal step and a hairline. */
  .group {
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md) var(--space-md) var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }
  .group-head {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
  }
  .group-title {
    font-family: var(--font-sans);
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
    margin: 0;
  }
  .group-sub {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
  }

  /* The two dependent switches read as sub-options of "Back up in the background":
     a hairline step down and a small inset, no nested card. */
  .sub-toggles {
    display: flex;
    flex-direction: column;
    padding-left: var(--space-md);
    padding-top: var(--space-2xs);
    border-top: 1px solid var(--color-line);
  }

  .segmented {
    display: flex;
    gap: var(--space-2xs);
    background: var(--color-surface-sunk);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-2xs);
  }
  .segment {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: var(--size-tap-target);
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
    cursor: pointer;
    transition:
      background var(--duration-base) var(--ease-standard),
      color var(--duration-base) var(--ease-standard);
  }
  .segment:active {
    background: var(--color-seal-tint);
  }
  /* Selection is check glyph + label weight + position + the pale-seal ground
     (which takes ink text at AAA in both appearances) — never color alone. */
  .segment--selected {
    background: var(--color-seal-pale);
    color: var(--color-ink);
    font-weight: var(--weight-semibold);
  }

  /* The notification-health readout. Three states share one shape so the surface reads the
     same whether or not anything is wrong; what changes is the mark glyph, the wording, and
     a tonal ground — never the tint on its own. */
  .notice {
    display: flex;
    align-items: flex-start;
    gap: var(--space-xs);
    margin: 0;
    padding: var(--space-sm);
    border-radius: var(--radius-md);
    border: 1px solid var(--color-line);
    background: var(--color-surface-sunk);
  }
  .notice-mark {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 20px;
    height: 20px;
    margin-top: 1px;
    border-radius: 50%;
    border: 1.5px solid currentColor;
    font-family: var(--font-sans);
    font-size: 12px;
    font-weight: var(--weight-semibold);
    line-height: 1;
  }
  .notice-text {
    display: flex;
    flex-direction: column;
    gap: var(--space-2xs);
    min-width: 0;
  }
  .notice-headline {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  .notice-detail,
  .notice-advice {
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  /* The action reads as an instruction, not as more description. */
  .notice-advice {
    color: var(--color-ink);
  }
  .notice--quiet {
    background: var(--color-safe-surface);
    border-color: var(--color-safe);
    color: var(--color-safe);
  }
  .notice--quiet .notice-detail {
    color: var(--color-safe-soft);
  }
  .notice--attention {
    background: var(--color-warning-surface);
    border-color: var(--color-warning);
    color: var(--color-warning);
  }
  .notice--attention .notice-detail {
    color: var(--color-warning-soft);
  }
  .notice--info {
    color: var(--color-muted);
  }

  /* Per-identity registration rows: same notice vocabulary, grouped under a small label so
     they read as detail beneath the device-level summary rather than as more alarms. */
  .reg-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    padding-top: var(--space-2xs);
    border-top: 1px solid var(--color-line);
  }
  .reg-title {
    font-family: var(--font-sans);
    font-size: var(--text-label);
    font-weight: var(--weight-semibold);
    color: var(--color-muted);
    margin: 0;
  }
  .reg-identity {
    font-weight: var(--weight-semibold);
    overflow-wrap: anywhere;
  }

  .save-error {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    font-size: var(--text-label);
    line-height: var(--leading-label);
    color: var(--color-critical);
    margin: 0;
  }
  .save-error svg {
    flex-shrink: 0;
    margin-top: 1px;
  }
</style>
