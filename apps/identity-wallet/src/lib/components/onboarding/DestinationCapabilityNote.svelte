<script lang="ts">
  // What the chosen destination server offers, stated plainly at the moment the user is
  // choosing it. Every destination in these flows works — the move, the repo and blob
  // import, the identity op, and the cutover are all standard AT Protocol. What differs
  // is how the wallet signs back in afterwards, so that is what this reports, rather than
  // ranking servers or naming a vendor.
  //
  // Silent until the server has actually answered: a host that could not be asked gets no
  // claim made about it, and the picker's own error surface already covers unreachable.
  import { getPdsCapabilities, hasPdsCapability, type PdsCapabilities } from '$lib/ipc';

  let { pdsUrl }: { pdsUrl: string } = $props();

  let capabilities = $state<PdsCapabilities | null>(null);

  $effect(() => {
    const url = pdsUrl.trim();
    capabilities = null;
    if (!url) return;

    let cancelled = false;
    (async () => {
      try {
        const probed = await getPdsCapabilities(url);
        if (!cancelled) capabilities = probed;
      } catch {
        // Best-effort: an unreadable answer says nothing about the server.
      }
    })();
    return () => {
      cancelled = true;
    };
  });
</script>

{#if capabilities?.reached}
  <div class="note">
    {#if hasPdsCapability(capabilities, 'sovereignSessions')}
      <p class="note-text">
        This server supports passwordless sign-in. After the move you'll unlock this identity
        with Face ID — no password to remember or lose.
      </p>
    {:else}
      <p class="note-text">
        This server uses standard sign-in. After the move you'll unlock this identity with its
        account password. Everything else — your keys, monitoring, and backups — works the same.
      </p>
    {/if}
    {#if hasPdsCapability(capabilities, 'escrow')}
      <p class="note-text">
        It can also hold one of your encrypted recovery shares, so a lost device is recoverable
        with the server's help as well as on your own.
      </p>
    {/if}
  </div>
{/if}

<style>
  .note {
    width: 100%;
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    background: var(--color-surface-sunk);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .note-text {
    font-size: var(--text-label);
    color: var(--color-muted);
    margin: 0;
    line-height: 1.4;
  }
</style>
