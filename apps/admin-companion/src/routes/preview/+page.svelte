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
  import Toggle from '$lib/components/ui/Toggle.svelte';
  import ErrorState from '$lib/components/ui/ErrorState.svelte';
  import { classifyRelayError } from '$lib/errors';

  let relayUrl = $state('https://relay.ezpds.com');
  let label = $state('');
  let loadingDemo = $state(false);
  let biometricOn = $state(true);
  let switcherOpen = $state(false);

  function demoLoad() {
    loadingDemo = true;
    setTimeout(() => (loadingDemo = false), 1400);
  }

  // The error matrix, built through the real classifier so the gallery shows exactly
  // what the screens render.
  const notPairedView = classifyRelayError({ code: 'NOT_PAIRED' });
  const unreachableView = classifyRelayError({ code: 'UNREACHABLE', message: 'connection refused' });
  const revokedView = classifyRelayError({ code: 'RELAY_REJECTED', status: 403, message: 'forbidden' });
  const clockSkewView = classifyRelayError({ code: 'RELAY_REJECTED', status: 401, message: 'unauthorized' });
  const noSuchPairingView = classifyRelayError({ code: 'NO_SUCH_PAIRING' });

  const stagingServer = { nickname: 'staging', host: 'staging.ezpds.example' };
  const noop = () => {};
</script>

<ScreenShell
  prompt="preview"
  title="Components"
  server={stagingServer}
  onservertap={() => (switcherOpen = !switcherOpen)}
>
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
      <CodeOutput label="Account claim code" value="PDS-7Q4M-2XK9" onshare={noop} />
      <CodeOutput
        label="This device's admin key"
        value="did:key:zDnaerByL1n8mP2qVxK4hyTpR9wQ7cF6sJvU3bN5aH2gWmEx"
        prompt={false}
      />
    </div>
  </section>

  <section>
    <h2>Toggle</h2>
    <div class="panel-pad">
      <Toggle
        bind:checked={biometricOn}
        label="Require Face ID to sign"
        description="Confirm with Face ID, Touch ID, or your passcode before generating a claim code or unpairing."
      />
    </div>
  </section>

  <section>
    <h2>Error states</h2>
    <div class="stack">
      <div class="panel-pad"><ErrorState view={notPairedView} onpair={noop} /></div>
      <div class="panel-pad">
        <ErrorState view={unreachableView} server={stagingServer} onretry={noop} onforgetlocally={noop} />
      </div>
      <div class="panel-pad">
        <ErrorState view={revokedView} server={stagingServer} onforget={noop} onswitch={noop} />
      </div>
      <div class="panel-pad"><ErrorState view={clockSkewView} onretry={noop} /></div>
      <div class="panel-pad">
        <ErrorState view={noSuchPairingView} server={stagingServer} />
      </div>
    </div>
  </section>

  <section>
    <h2>Server context</h2>
    <div class="panel-pad">
      <p class="static-label">Static server identity (Settings pattern):</p>
      <div class="server-context-example">
        <span class="server-nickname">production</span>
        <span class="server-host">relay.example.com</span>
      </div>
    </div>
    <div class="panel-pad">
      <p class="static-label">Tappable server identity (Home pattern):</p>
      <button type="button" class="server-context-button" onclick={() => console.log('Switcher toggled')}>
        <span class="server-nickname">staging</span>
        <span class="server-host">staging.ezpds.example</span>
        <span class="server-affordance" aria-hidden="true">▾</span>
        <span class="visually-hidden">Switch server</span>
      </button>
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
    <h2>Server list (Settings)</h2>
    <div class="panel">
      <DeviceRow
        label="staging"
        deviceId="relay.staging.example"
        lastSeen="staging.ezpds.example"
        status="active"
        current
        onclick={() => {}}
      />
      <div class="divider"></div>
      <DeviceRow
        label="production"
        deviceId="relay.prod.example"
        lastSeen="relay.example.com"
        status="ready"
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
  .panel-pad {
    background: var(--color-surface);
    border: var(--border-hairline) solid var(--color-line);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
  }
  .divider {
    height: var(--border-hairline);
    background: var(--color-line);
  }
  .static-label {
    margin: 0 0 var(--space-sm) 0;
    font-family: var(--font-sans);
    font-size: var(--text-label);
    color: var(--color-muted);
  }
  .server-context-example {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }
  .server-context-button {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
    align-self: flex-start;
    padding: var(--space-xs) 0;
    background: transparent;
    border: none;
    font-family: inherit;
    text-align: inherit;
    cursor: pointer;
  }
  .server-nickname {
    display: block;
    font-family: var(--font-sans);
    font-size: var(--text-body);
    font-weight: var(--weight-medium);
    color: var(--color-ink);
  }
  .server-host {
    display: block;
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink-soft);
  }
  .server-affordance {
    display: inline;
    margin-left: var(--space-xs);
    color: var(--color-muted);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }
</style>
