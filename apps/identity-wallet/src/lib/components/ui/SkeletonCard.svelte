<script lang="ts">
  // A single shimmering placeholder card, matching the shape of the list cards it stands in
  // for while data loads. Replaces the per-screen `.skel`/`.skel-line`/shimmer copies in
  // MyAgentsScreen and IdentityListHome. `seal` adds the leading avatar circle (identity list);
  // omit it for the plain two-line card (agent list).
  let { seal = false }: { seal?: boolean } = $props();
</script>

<div class="skel" aria-hidden="true">
  {#if seal}<div class="skel-seal"></div>{/if}
  <div class="skel-lines">
    <span class="skel-line w55"></span>
    <span class="skel-line w80"></span>
  </div>
</div>

<style>
  /* This placeholder must occupy the same box as the MyAgentsScreen / IdentityListHome cards it
     stands in for, so the list doesn't jump on load. The padding is var(--space-md), the same
     token those cards now use — moved in lockstep. The remaining metrics (gap, seal size, line
     height) still track the cards' off-scale values verbatim; retuning them means moving
     placeholder and card together. */
  .skel {
    display: flex;
    align-items: center;
    gap: 14px;
    background: var(--color-bg);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-xl);
    padding: var(--space-md);
  }
  .skel-seal {
    width: 52px;
    height: 52px;
    border-radius: var(--radius-full);
    background: var(--color-surface-sunk);
    flex-shrink: 0;
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skel-lines {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    flex: 1;
  }
  .skel-line {
    height: 12px;
    border-radius: var(--radius-sm);
    background: var(--color-surface-sunk);
    animation: shimmer 1.4s ease-in-out infinite;
  }
  .skel-line.w55 {
    width: 55%;
  }
  .skel-line.w80 {
    width: 80%;
  }
  @keyframes shimmer {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
</style>
