<script lang="ts">
  // Brass Console component gallery — every primitive in every state, on the console
  // ground. A design-review + screenshot surface, not a shipped screen. Lives at
  // /preview; excluded from the operator flows.
  import ScreenShell from '$lib/components/ui/ScreenShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import StatusChip from '$lib/components/ui/StatusChip.svelte';
  import CodeOutput from '$lib/components/ui/CodeOutput.svelte';
  import DeviceRow from '$lib/components/ui/DeviceRow.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';

  let relayUrl = $state('https://relay.ezpds.com');
  let label = $state('');
  let loadingDemo = $state(false);

  function demoLoad() {
    loadingDemo = true;
    setTimeout(() => (loadingDemo = false), 1400);
  }
</script>

<ScreenShell prompt="preview" title="Components">
  <section>
    <h2>Buttons</h2>
    <div class="stack">
      <Button variant="primary">Generate claim code</Button>
      <Button variant="secondary">Share</Button>
      <Button variant="destructive">Revoke device</Button>
      <Button variant="secondary" disabled>Disabled</Button>
      <Button variant="primary" loading={loadingDemo} onclick={demoLoad}>
        {loadingDemo ? 'Working…' : 'Tap to load'}
      </Button>
    </div>
  </section>

  <section>
    <h2>Status chips</h2>
    <div class="row-wrap">
      <StatusChip status="active" />
      <StatusChip status="ready" />
      <StatusChip status="pending" />
      <StatusChip status="revoked" />
      <StatusChip status="error" />
      <StatusChip status="info" />
    </div>
  </section>

  <section>
    <h2>Code output</h2>
    <div class="stack">
      <CodeOutput label="Account claim code" value="PDS-7Q4M-2XK9" />
      <CodeOutput
        label="This device's admin key"
        value="did:key:zDnaerByL1n8mP2qVxK4hyTpR9wQ7cF6sJvU3bN5aH2gWmEx"
        prompt={false}
      />
    </div>
  </section>

  <section>
    <h2>Device rows</h2>
    <div class="panel">
      <DeviceRow
        label="iPhone 17 Pro"
        deviceId="did:key:zDnaerByL1n8mP2qVxK4hyTpR9wQ7cF6sJvU3bN5aH2g"
        lastSeen="seen 2m ago"
        status="active"
        current
        onclick={() => {}}
      />
      <div class="divider"></div>
      <DeviceRow
        label="Demo iPad"
        deviceId="did:key:zQ3shoK9pLmN2vB7xW4rT6yU8iO0pA1sD2fG3hJ4kL5mN6bV"
        lastSeen="seen 3d ago"
        status="active"
        onclick={() => {}}
      />
      <div class="divider"></div>
      <DeviceRow
        label="Old phone"
        deviceId="did:key:zQx4tY7uI9oP2aS5dF8gH1jK3lZ6xC9vB2nM4qW7eR0tY5u"
        lastSeen="revoked 1d ago"
        status="revoked"
        onclick={() => {}}
      />
    </div>
  </section>

  <section>
    <h2>Text fields</h2>
    <div class="stack">
      <TextField label="Device label" bind:value={label} placeholder="e.g. Operator iPhone" />
      <TextField label="Relay URL" bind:value={relayUrl} mono type="url" inputmode="url" />
      <TextField
        label="Pairing code"
        value="bad-code"
        mono
        error="That pairing code has expired. Mint a new one from the laptop."
      />
    </div>
  </section>
</ScreenShell>

<style>
  h2 {
    margin: 0 0 var(--space-sm);
    font-family: var(--font-sans);
    font-size: var(--text-title);
    font-weight: var(--weight-semibold);
    color: var(--color-ink);
  }
  section {
    padding-bottom: var(--space-sm);
    border-bottom: var(--border-hairline) solid var(--color-line);
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }
  .row-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-sm);
  }
  .panel {
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: 0 var(--space-md);
  }
  .divider {
    height: var(--border-hairline);
    background: var(--color-line);
  }
</style>
