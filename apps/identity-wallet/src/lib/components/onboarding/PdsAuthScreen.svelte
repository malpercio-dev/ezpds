<script lang="ts">
  import { authenticateSourcePds } from '$lib/ipc';
  import SourcePasswordAuthScreen from './SourcePasswordAuthScreen.svelte';

  // Claim-flow source login: sign in to the identity's existing PDS with the account password so
  // the wallet can request + sign the PLC operation that adds this device as a rotation key. Shares
  // the whole form/2FA/error scaffolding with the outbound-migration source login via
  // `SourcePasswordAuthScreen`; only the copy, the IPC fn, and the two claim-specific error codes
  // (`INSUFFICIENT_SCOPE`, `UNAUTHORIZED`) differ.
  let {
    did,
    handle,
    pdsUrl,
    onnext,
    onback,
  }: {
    did: string;
    handle: string;
    pdsUrl: string;
    onnext: () => void;
    onback: () => void;
  } = $props();

  // Claim-only error codes the shared switch doesn't model; everything else falls to the default.
  function mapClaimError(code: string): string | null {
    switch (code) {
      case 'INSUFFICIENT_SCOPE':
        return `${pdsUrl} refused to authorize the identity change for this session. This shouldn't happen with a full sign-in — please try again.`;
      case 'UNAUTHORIZED':
        return 'This claim is no longer active. Go back and start again.';
      default:
        return null;
    }
  }
</script>

<SourcePasswordAuthScreen
  {did}
  {handle}
  {pdsUrl}
  {onnext}
  {onback}
  authenticate={authenticateSourcePds}
  errorLogLabel="Source PDS sign-in failed:"
  openingStatus="Opening a session with your server…"
  title="Sign in to your server"
  subtitle="Adding this device as a recovery key is an identity change, and only a full sign-in can authorize one."
  appPasswordClause="authorize identity changes"
  mapExtraError={mapClaimError}
>
  {#snippet why()}
    <p>
      Your server only permits identity changes with your <strong>account password</strong> —
      there is no way to delegate this one action, which is why migration tools ask for it too.
    </p>
    <p class="reassure">
      Your password is sent only to {pdsUrl}, used once to open a session, and never stored on this
      device or seen by Obsign. An app password won't work here.
    </p>
  {/snippet}
</SourcePasswordAuthScreen>
