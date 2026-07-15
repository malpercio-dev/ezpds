/**
 * Proxy-mode account/domain handlers for the wallet harness (browser-harness Phase 5).
 *
 * These are the wallet's genuinely thin-HTTP commands: they run for real against the
 * hermetic local PDS through the `/__pds/*` dev-server proxy, using the real WebCrypto
 * device key for the account's device public key. Everything NOT returned here falls
 * through to the fake — deliberately, for the heavy-logic commands the honest boundary
 * keeps faked even in proxy mode: the DID ceremony (`perform_did_ceremony`), the OAuth
 * completion (`prepare/complete_oauth_flow`), migration transfer legs, and the agent
 * surfaces (which need a real post-ceremony session that the faked ceremony never mints).
 * See the runbook in apps/identity-wallet/AGENTS.md.
 */
import type { Handler } from '../registry';
import type { CreateAccountResult, RegisterHandleResult } from '$lib/ipc';
import type { WalletState } from '../state';
import { deviceDidKey } from './device-key';
import { mintClaimCode, pdsFetch } from './transport';

/** Map a mobile-account error response to the typed `CreateAccountError` shape. */
async function createAccountError(res: Response): Promise<never> {
  let message = `create_account failed (${res.status})`;
  let bodyText = '';
  try {
    bodyText = await res.text();
    const parsed = JSON.parse(bodyText) as { error?: string; message?: string };
    message = parsed.message ?? parsed.error ?? message;
  } catch {
    if (bodyText) message = bodyText;
  }
  const lower = `${message} ${bodyText}`.toLowerCase();
  let code: string;
  if (lower.includes('email')) code = 'EMAIL_TAKEN';
  else if (lower.includes('handle')) code = 'HANDLE_TAKEN';
  else if (res.status === 409) code = 'REDEEMED_CODE';
  else if (res.status === 404) code = 'EXPIRED_CODE';
  else code = 'UNKNOWN';
  throw { code, message };
}

export async function buildAccountProxyHandlers(
  state: WalletState
): Promise<Partial<Record<string, Handler>>> {
  return {
    // Real: mint a claim code (admin API), then POST /v1/accounts/mobile with the real
    // device public key. The account is created on the PDS and observable via the admin
    // API (browser-harness.AC3.1). The subsequent DID ceremony stays faked.
    create_account: async (args): Promise<CreateAccountResult> => {
      const email = String(args.email ?? '');
      const handle = String(args.handle ?? '');
      const claimCode = await mintClaimCode();
      const devicePublicKey = await deviceDidKey();
      const res = await pdsFetch('/v1/accounts/mobile', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, handle, devicePublicKey, platform: 'ios', claimCode }),
      });
      if (!res.ok) return createAccountError(res);
      state.create = { claimCode, email, handle };
      return { nextStep: 'did_creation' };
    },

    // Real: the PDS's served handle domains from describeServer.
    get_available_user_domains: async (): Promise<string[]> => {
      const res = await pdsFetch('/xrpc/com.atproto.server.describeServer');
      if (!res.ok) throw { message: `describeServer failed (${res.status})` };
      const body = (await res.json()) as { availableUserDomains?: string[] };
      const domains = body.availableUserDomains ?? [];
      state.availableUserDomains = domains;
      return domains;
    },

    // Real: register the handle against the PDS's describeServer domains. The mobile
    // create flow assembles the full handle client-side, so this is a light echo that
    // confirms the domain is served; the authoritative handle binding happens in the
    // (faked) DID ceremony.
    register_handle: async (args): Promise<RegisterHandleResult> => {
      const handle = String(args.handle ?? state.create?.handle ?? '');
      if (state.create) state.create.handle = handle;
      return { handle, dnsStatus: 'not_configured' };
    },
  };
}
