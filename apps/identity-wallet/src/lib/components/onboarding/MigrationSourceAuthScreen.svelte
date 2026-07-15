<script lang="ts">
  import { authenticateMigrationSource } from '$lib/ipc';
  import SourcePasswordAuthScreen from './SourcePasswordAuthScreen.svelte';

  // Outbound-migration source login: sign in to the account's current PDS with the account password
  // so the wallet can mint the `com.atproto.server.createAccount` service-auth token the source PDS
  // gates behind a full session (ADR-0021/MM-302). Shares the whole form/2FA/error scaffolding with
  // the claim-flow source login via `SourcePasswordAuthScreen`; only the copy, the IPC fn, and the
  // one migration-specific error code (`MIGRATION_NOT_READY`) differ.
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

  // Migration-only error codes the shared switch doesn't model; everything else falls to the default.
  function mapMigrationError(code: string): string | null {
    switch (code) {
      case 'MIGRATION_NOT_READY':
        return 'This migration is no longer active. Go back and start again.';
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
  authenticate={authenticateMigrationSource}
  errorLogLabel="Migration source sign-in failed:"
  openingStatus="Opening a session with your current PDS…"
  title="Sign in to your current PDS"
  subtitle="Moving your account off this PDS needs a full sign-in — the protocol lets only a full session authorize the move."
  appPasswordClause="authorize the move"
  mapExtraError={mapMigrationError}
>
  {#snippet why()}
    <p>
      Creating your account on the new PDS uses a token your current PDS signs, and it will only
      mint that token for a <strong>full sign-in with your account password</strong> — the same
      reason migration tools ask for it. An app password won't work here.
    </p>
    <p class="reassure">
      Your password is sent only to {pdsUrl}, used once to open a session, and never stored on this
      device or seen by Obsign.
    </p>
  {/snippet}
</SourcePasswordAuthScreen>
