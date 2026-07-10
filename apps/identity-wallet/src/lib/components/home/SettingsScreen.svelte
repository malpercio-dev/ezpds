<script lang="ts">
  import ChevronLeftIcon from '$lib/components/ui/ChevronLeftIcon.svelte';
  import {
    readLocalMirror,
    setAppearance,
    type AppearancePreference,
  } from '$lib/appearance';

  let { onback }: { onback: () => void } = $props();

  // initAppearance() reconciled the mirror against the Keychain at launch,
  // so the mirror is authoritative by the time this screen opens.
  let selected = $state<AppearancePreference>(readLocalMirror());
  let saveError = $state(false);

  const OPTIONS: { value: AppearancePreference; label: string }[] = [
    { value: 'system', label: 'System' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
  ];

  let segmentEls: (HTMLButtonElement | undefined)[] = [undefined, undefined, undefined];

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
  <div class="topbar">
    <button class="back" onclick={onback} aria-label="Back">
      <ChevronLeftIcon />
    </button>
    <h1 class="title">Settings</h1>
  </div>

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

  .topbar {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
  }
  .back {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 38px;
    height: 38px;
    border-radius: var(--radius-full);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    color: var(--color-ink);
    cursor: pointer;
    flex-shrink: 0;
  }
  .title {
    font-family: var(--font-sans);
    font-size: 1.375rem;
    font-weight: var(--weight-bold);
    letter-spacing: -0.01em;
    color: var(--color-ink);
    margin: 0;
    min-width: 0;
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
    gap: 3px;
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

  .segmented {
    display: flex;
    gap: 3px;
    background: var(--color-surface-sunk);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: 3px;
  }
  .segment {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 44px;
    border: none;
    border-radius: calc(var(--radius-md) - 2px);
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
