import { invoke } from '@tauri-apps/api/core';

// ── OAuth ───────────────────────────────────────────────────────────────────
//
// These variants must exactly match the Rust `OAuthError` enum in oauth.rs.
// Rust serializes them as `{ "code": "SCREAMING_SNAKE_CASE" }` via:
//   #[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]

export type OAuthError =
  | { code: 'DPOP_KEY_GEN_FAILED' }
  | { code: 'DPOP_KEY_INVALID' }
  | { code: 'DPOP_PROOF_FAILED' }
  | { code: 'KEYCHAIN_ERROR' }
  | { code: 'STATE_MISMATCH' }
  | { code: 'CALLBACK_ABANDONED' }
  | { code: 'PAR_FAILED' }
  | { code: 'TOKEN_EXCHANGE_FAILED' }
  | { code: 'TOKEN_REFRESH_FAILED' }
  | { code: 'INVALID_GRANT' }
  | { code: 'NOT_AUTHENTICATED' };

/**
 * Drive the create-flow PDS login via the native in-app auth session (ASWebAuthenticationSession
 * on iOS, via the auth-session plugin). Three steps: `prepare_oauth_flow` (Rust) does PKCE + PAR
 * and returns the authorize URL; the plugin opens the in-app session and returns the
 * custom-scheme callback URL; `complete_oauth_flow` (Rust) validates the CSRF state and exchanges
 * the code for tokens. The PKCE verifier and CSRF state never leave the Rust backend — only the
 * authorize URL and (briefly) the callback URL transit the webview.
 *
 * An in-app session is required because iOS Safari will not auto-launch the app from a
 * server-side redirect to a custom URL scheme.
 */
export const startOAuthFlow = async (): Promise<void> => {
  const prepared = await invoke<{ authUrl: string; callbackScheme: string }>('prepare_oauth_flow');
  let callbackUrl: string;
  try {
    callbackUrl = await invoke<string>('plugin:auth-session|start', {
      authUrl: prepared.authUrl,
      callbackUrlScheme: prepared.callbackScheme,
    });
  } catch {
    // The auth-session plugin rejects with a plain string ("user_cancelled", "Invalid auth
    // URL: ..."), not the OAuthError shape. Normalize so the UI's error handling stays uniform;
    // a dismissed sheet reads as an abandoned callback.
    throw { code: 'CALLBACK_ABANDONED' } as OAuthError;
  }
  await invoke('complete_oauth_flow', { callbackUrl });
};
