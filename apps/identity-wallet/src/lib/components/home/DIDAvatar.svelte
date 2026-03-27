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
  style="background: hsl({hue}, 65%, 45%)"
  aria-label="Avatar for {handle}"
>
  {initial}
</div>

<style>
  .avatar {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-size: 1.75rem;
    font-weight: 700;
    flex-shrink: 0;
    user-select: none;
  }
</style>
