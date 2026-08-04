<script lang="ts">
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import { didWebFromDomain } from '$lib/did-web';
  import { isCodedError } from '$lib/ipc';
  let { value = $bindable(''), onnext, onback }: {
    value?: string;
    /** May be async (the existing-identity branch resolves + imports the domain's document). */
    onnext: () => void | Promise<void>;
    onback: () => void;
  } = $props();
  let error = $state('');
  let busy = $state(false);
  async function next() {
    try {
      didWebFromDomain(value);
      error = '';
      busy = true;
      await onnext();
    } catch (e) {
      error = describe(e);
    } finally {
      busy = false;
    }
  }
  function describe(e: unknown): string {
    if (e instanceof Error) return e.message;
    if (isCodedError(e)) {
      switch (e.code) {
        case 'INVALID_DOMAIN':
          return 'Enter a public domain name without a path or port.';
        case 'DOCUMENT_NOT_FOUND':
          return "Couldn't find a did.json at /.well-known/did.json on this domain. Publish it there, then try again.";
        case 'INVALID_DOCUMENT':
          return "This domain's did.json isn't a usable identity document.";
        case 'PDS_UNREACHABLE':
          return "Couldn't reach the server named in this domain's did.json.";
        case 'KEYCHAIN_ERROR':
          return "Couldn't save the identity on this device. Try again.";
        default:
          return 'Network error. Check your connection and try again.';
      }
    }
    return 'Something went wrong. Try again.';
  }
</script>
<OnboardingShell title="Which domain is your identity?" subtitle="You must control this domain and be able to publish its did.json." {onback}>
  <TextField aria-label="Identity domain" placeholder="identity.example.com" bind:value {error} mono />
  <Button onclick={next} disabled={busy}>{busy ? 'Checking domain…' : 'Continue'}</Button>
</OnboardingShell>
