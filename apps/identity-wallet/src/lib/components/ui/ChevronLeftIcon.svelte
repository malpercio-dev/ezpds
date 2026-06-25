<script lang="ts">
  // The back-arrow chevron used in screen app bars and onboarding back affordances.
  // Color is inherited via currentColor so callers set it through CSS. The default
  // 11x18 size matches the original inlined markup; scaling keeps the aspect ratio.
  let { size = 18 }: { size?: number } = $props();

  let width = $derived((size * 11) / 18);
</script>

<svg
  width={width}
  height={size}
  viewBox="0 0 11 18"
  fill="none"
  stroke="currentColor"
  stroke-width="2.2"
  stroke-linecap="round"
  stroke-linejoin="round"
>
  <path d="M9 1 2 9l7 8" />
</svg>
