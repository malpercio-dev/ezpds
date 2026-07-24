<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    pdsUrl,
    onimport,
    onchangeserver,
    onback,
  }: {
    pdsUrl: string;
    onimport: () => void;
    onchangeserver: () => void;
    onback: () => void;
  } = $props();

  // Show the bare host: the user typed a URL, but the scheme and any trailing slash are
  // noise when the point is "which server is this".
  let host = $derived(pdsUrl.replace(/^https?:\/\//, '').replace(/\/+$/, ''));
</script>

<OnboardingShell
  title="This server can't create identities"
  subtitle="Everything else in Obsign works here — creating a brand-new identity is the one thing it can't do."
  {onback}
>
  {#snippet icon()}
    <!-- A plain informational mark, deliberately not a warning triangle: nothing has gone
         wrong and nothing is at risk. The user chose a server that does a different job. -->
    <svg
      width="32"
      height="32"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-5" />
      <path d="M12 8h.01" />
    </svg>
  {/snippet}

  <p class="host">{host}</p>

  <p class="body">
    Creating an identity means this device writes its first record and holds the master key
    from that moment on. A server has to be built to accept that, and this one isn't.
  </p>
  <p class="body">
    Importing one works here. You still get the key on this device, tamper monitoring, the
    72-hour window to reverse a change you didn't make, and your own backups.
  </p>

  <div class="actions">
    <Button onclick={onimport}>Import an identity</Button>
    <Button variant="secondary" onclick={onchangeserver}>Use a different server</Button>
  </div>
</OnboardingShell>

<style>
  /* The steer is a redirect, not a wall: "Import an identity" is the single primary
     action and lands on the same flow the welcome screen offers, with the server the user
     already chose still configured. Changing servers stays available but is not the
     suggestion — most people arriving here meant to bring an identity in, not to shop for
     a host. Nothing here sells Custos; the honest reason is the whole message. */
  .host {
    margin: 0;
    align-self: stretch;
    padding: var(--space-xs) var(--space-sm);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-ink);
    font-family: var(--font-mono);
    font-size: var(--text-label);
    word-break: break-all;
    text-align: left;
  }
  .body {
    margin: 0;
    align-self: stretch;
    /* Body copy on the page ground takes ink, not muted: this is the explanation itself,
       and hierarchy against the subtitle comes from position, not from dimming it. */
    color: var(--color-ink);
    font-size: var(--text-body);
    line-height: var(--leading-body);
    text-align: left;
  }
  .actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    width: 100%;
    padding-top: var(--space-xs);
  }
</style>
