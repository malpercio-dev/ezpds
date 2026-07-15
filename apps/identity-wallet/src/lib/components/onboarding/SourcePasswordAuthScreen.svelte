<script lang="ts">
  import type { Snippet } from 'svelte';
  import { isCodedError } from '$lib/ipc';
  import { formatRateLimitMessage, formatServerErrorMessage } from '$lib/claim-errors';
  import OnboardingShell from '$lib/components/ui/OnboardingShell.svelte';
  import TextField from '$lib/components/ui/TextField.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Spinner from '$lib/components/ui/Spinner.svelte';

  // Shared base for the two wallet source-PDS password logins — the claim flow (`PdsAuthScreen`)
  // and the outbound migration (`MigrationSourceAuthScreen`). Both open a full session against the
  // account's current PDS with a password `createSession` and are ~identical bar copy, the IPC fn,
  // and a handful of error codes. This component owns the form, the 2FA branch, and the
  // shared error switch; each wrapper supplies its copy, its `authenticate` IPC fn, and a mapper
  // for the codes only it produces.

  // The shape every source-login error enum serializes to (`ClaimError` / `MigrationError`): a
  // SCREAMING_SNAKE `code`, plus an optional `message`/`retryAfter` on some variants.
  type CodedAuthError = { code: string; message?: string; retryAfter?: string | null };

  let {
    did,
    handle,
    pdsUrl,
    onnext,
    onback,
    authenticate,
    errorLogLabel,
    openingStatus,
    title,
    subtitle,
    why,
    appPasswordClause,
    mapExtraError,
  }: {
    did: string;
    handle: string;
    pdsUrl: string;
    onnext: () => void;
    onback: () => void;
    /** IPC source-login command: one-shot password `createSession` against the source PDS. */
    authenticate: (
      did: string,
      identifier: string,
      password: string,
      twoFactorToken?: string,
    ) => Promise<void>;
    /** `console.error` label for a failed sign-in (per-flow, aids log triage). */
    errorLogLabel: string;
    /** Status line under the spinner while the session opens. */
    openingStatus: string;
    /** Main (non-2FA) form title. */
    title: string;
    /** Main (non-2FA) form subtitle. */
    subtitle: string;
    /** The rich "why a full password sign-in" explainer for the main form. */
    why: Snippet;
    /**
     * Trailing clause of the `SOURCE_AUTH_FAILED` message: the shared sentence structure lives here
     * to stop the two copies drifting (the exact hazard duplication created here); only this clause varies
     * — e.g. "authorize the move" vs "authorize identity changes".
     */
    appPasswordClause: string;
    /**
     * Map a flow-specific error code (one the shared switch below doesn't handle) to a message.
     * Return `null` to fall through to the generic "Sign-in failed (CODE)" default.
     */
    mapExtraError: (code: string) => string | null;
  } = $props();

  // Prefill the login identifier with the handle, then let the user edit it to a DID or email if
  // that is how they sign in to their PDS. Capturing the initial value is intentional — this
  // screen's `handle` prop is fixed for its lifetime, so it never needs to re-sync.
  // svelte-ignore state_referenced_locally
  let identifier = $state(handle);
  let password = $state('');
  // For accounts with email 2FA: once the PDS asks for a code, we keep the password in memory and
  // re-submit it alongside the code the user enters here.
  let needsTwoFactor = $state(false);
  let twoFactorToken = $state('');
  let authenticating = $state(false);
  let error = $state<string | null>(null);

  async function runAuth() {
    if (!identifier.trim() || !password) return;
    if (needsTwoFactor && !twoFactorToken.trim()) return;
    authenticating = true;
    error = null;

    try {
      await authenticate(
        did,
        identifier.trim(),
        password,
        needsTwoFactor ? twoFactorToken.trim() : undefined,
      );
      // Credentials are not retained after this call resolves.
      password = '';
      twoFactorToken = '';
      onnext();
    } catch (raw: unknown) {
      authenticating = false;
      console.error(errorLogLabel, raw);

      if (isCodedError(raw)) {
        const err = raw as CodedAuthError;
        switch (err.code) {
          case 'TWO_FACTOR_REQUIRED':
            if (needsTwoFactor) {
              // We already submitted a code and it wasn't accepted.
              error = "That code wasn't accepted. Check the latest code emailed to you.";
            } else {
              // First time: the account has 2FA. Advance to the code step — not an error.
              needsTwoFactor = true;
            }
            break;
          case 'SOURCE_AUTH_FAILED':
            error = needsTwoFactor
              ? "That code wasn't accepted. Check the latest code emailed to you."
              : `${pdsUrl} did not accept that password. Use your account password — an app password can't ${appPasswordClause}.`;
            break;
          case 'ACCOUNT_MISMATCH':
            error = `Those credentials signed in to a different account than ${handle}. Sign in as ${handle}.`;
            break;
          case 'INSECURE_SOURCE_URL':
            error = `Can't sign in securely: ${pdsUrl} isn't served over HTTPS. Your password won't be sent over an unencrypted connection.`;
            break;
          case 'RATE_LIMITED':
            error = formatRateLimitMessage(err.retryAfter ?? null);
            break;
          case 'SERVER_ERROR':
            error = formatServerErrorMessage(err.message ?? '');
            break;
          case 'NETWORK_ERROR':
            error = 'Network error. Check your connection and try again.';
            break;
          default:
            error = mapExtraError(err.code) ?? `Sign-in failed (${err.code}). Please try again.`;
        }
      } else {
        error = 'Sign-in failed. Please try again.';
      }
    }
  }

  // Return from the 2FA step to the password form (e.g. wrong account, or to restart).
  function backToPassword() {
    needsTwoFactor = false;
    twoFactorToken = '';
    error = null;
  }
</script>

{#if authenticating}
  <div class="centered">
    <Spinner size={44} label="Signing in" />
    <p class="status">{openingStatus}</p>
  </div>
{:else if needsTwoFactor}
  <OnboardingShell
    title="Enter your two-factor code"
    subtitle="Your account has email two-factor authentication turned on."
  >
    <span class="pds-chip">{pdsUrl}</span>

    <div class="why" role="note">
      <p>{pdsUrl} emailed a one-time code to the address on <strong>{identifier}</strong>. Enter it to finish signing in.</p>
    </div>

    <TextField
      bind:value={twoFactorToken}
      type="text"
      inputmode="text"
      autocomplete="one-time-code"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Two-factor code"
      placeholder="Two-factor code"
      error={error ?? undefined}
    />

    <Button disabled={!twoFactorToken.trim()} onclick={runAuth}>Verify code</Button>
    <Button variant="secondary" onclick={backToPassword}>Back</Button>
  </OnboardingShell>
{:else}
  <OnboardingShell {title} {subtitle}>
    <span class="pds-chip">{pdsUrl}</span>

    <div class="why" role="note">
      {@render why()}
    </div>

    <TextField
      bind:value={identifier}
      type="text"
      autocomplete="username"
      autocapitalize="none"
      autocorrect="off"
      spellcheck={false}
      aria-label="Handle, DID, or email"
      placeholder="Handle, DID, or email"
    />
    <TextField
      bind:value={password}
      type="password"
      autocomplete="current-password"
      aria-label="Account password"
      placeholder="Account password"
      error={error ?? undefined}
    />

    <Button disabled={!identifier.trim() || !password} onclick={runAuth}>
      {error ? 'Try again' : 'Sign in'}
    </Button>
    <Button variant="secondary" onclick={onback}>Back</Button>
  </OnboardingShell>
{/if}

<style>
  .centered {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: var(--space-lg);
    padding: var(--space-xl);
  }
  .status {
    font-size: var(--text-body);
    color: var(--color-muted);
    margin: 0;
    text-align: center;
  }
  .pds-chip {
    font-family: var(--font-mono);
    font-size: var(--text-data);
    color: var(--color-ink);
    background: var(--color-surface);
    border: 1px solid var(--color-line);
    border-radius: var(--radius-md);
    padding: var(--space-sm) var(--space-md);
    word-break: break-all;
    max-width: 100%;
  }
  .why {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
    font-size: var(--text-label);
    line-height: 1.5;
    color: var(--color-ink);
  }
  /* The `why` explainer is caller-supplied (a snippet), so target its paragraphs via :global —
     scoped selectors don't reach into rendered snippet content. */
  .why :global(p) {
    margin: 0;
  }
  .why :global(.reassure) {
    color: var(--color-muted);
  }
</style>
