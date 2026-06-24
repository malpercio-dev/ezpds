<script lang="ts">
  let {
    did,
    handle,
  }: {
    did: string;
    handle: string;
  } = $props();

  // Derive a stable hue (0-359) from the DID string using a simple polynomial hash.
  // The same DID always produces the same hue across re-renders and app sessions.
  let hue = $derived.by(() => {
    let h = 0;
    for (let i = 0; i < did.length; i++) {
      h = (h * 31 + did.charCodeAt(i)) & 0xffffff;
    }
    return h % 360;
  });

  // Show '?' for the ATProto sentinel value that means "no handle registered".
  let initial = $derived(
    handle === 'handle.invalid' ? '?' : handle.charAt(0).toUpperCase()
  );
</script>

<div
  class="avatar"
  style="background: oklch(0.55 0.09 {hue})"
  aria-label="Seal for {handle}"
>
  {initial}
</div>

<style>
  /* The personal seal: a deterministic monogram in the display serif, embossed
     like pressed wax. Chroma and lightness are constrained (0.55 L, 0.09 C) so a
     wall of identities reads as a coherent set of seals, not rainbow avatars. */
  .avatar {
    width: 64px;
    height: 64px;
    border-radius: var(--radius-full);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-on-color);
    font-family: var(--font-display);
    font-size: 1.75rem;
    line-height: 1;
    flex-shrink: 0;
    user-select: none;
    box-shadow:
      inset 0 0 0 1.5px oklch(1 0 0 / 0.22),
      inset 0 -2px 5px oklch(0.2 0.05 60 / 0.18);
  }
</style>
