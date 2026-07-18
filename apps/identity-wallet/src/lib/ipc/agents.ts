import { invoke } from '@tauri-apps/api/core';
import type { UnlockReason } from './identity';

// ── Agent consent + audit (auth.md claim ceremony, "My agents") ──────────────
//
// Per-identity: every command takes a `did` and runs through the refreshable per-DID
// session (SessionProvider) in `agents.rs`, so an expired session self-heals — or returns
// SESSION_LOCKED, the cue to run the biometric `sovereignLogin(did)` and retry.

/** One agent identity bound to this account. */
export type AgentSummary = {
  registrationId: string;
  registrationType: 'service_auth' | 'identity_assertion' | 'anonymous';
  issuer?: string;
  subject?: string;
  scopes: string[];
  /** `active` = registered, awaiting the claim ceremony; then `claimed` or `revoked`. */
  status: 'active' | 'claimed' | 'revoked';
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
};

/** One entry of an agent's append-only audit trail. */
export type AgentAuditEvent = {
  id: string;
  eventType:
    | 'registered'
    | 'claim_initiated'
    | 'claim_confirmed'
    | 'claim_expired'
    | 'token_exchanged'
    | 'repo_write'
    | 'blob_upload'
    | 'revoked';
  did?: string;
  detail?: Record<string, unknown>;
  createdAt: string;
};

/** One page of audit events, newest first; `cursor` present means more pages exist. */
export type AgentAuditPage = {
  events: AgentAuditEvent[];
  cursor?: string;
};

/** What confirming a claim-ceremony code would grant. */
export type AgentClaimPreview = {
  registrationId: string;
  registrationType: 'service_auth' | 'identity_assertion' | 'anonymous';
  issuer?: string;
  subject?: string;
  scopes: string[];
  userCodeExpiresAt: string;
};

/** Result of a confirmed claim ceremony. */
export type AgentClaimConfirmation = {
  registrationId: string;
  status: string;
  did: string;
};

/**
 * Errors from the agent consent/management commands. Matches `AgentsError` in `agents.rs`
 * (`#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]`) — codes must match exactly.
 *
 * `SESSION_LOCKED` is the cue to run the passwordless {@link sovereignLogin} (biometric) and
 * retry, exactly as in the app-password and change-handle flows.
 */
export type AgentsError =
  | { code: 'NOT_AUTHENTICATED' }
  | { code: 'CODE_NOT_FOUND' }
  | { code: 'CODE_EXPIRED' }
  | { code: 'ALREADY_CLAIMED' }
  | { code: 'ACCESS_DENIED' }
  | { code: 'AGENT_NOT_FOUND' }
  | { code: 'RATE_LIMITED' }
  // The identity is locked — run sovereignLogin(did) and retry.
  | { code: 'SESSION_LOCKED'; reason: UnlockReason }
  | { code: 'NETWORK_ERROR'; message: string }
  | { code: 'UNKNOWN'; message: string };

/** List the agent identities bound to this identity's account. */
export const listAgents = (did: string): Promise<AgentSummary[]> =>
  invoke('list_agents', { did });

/** Revoke an agent identity (idempotent; the next token exchange is refused immediately). */
export const revokeAgent = (did: string, registrationId: string): Promise<void> =>
  invoke('revoke_agent', { did, registrationId });

/** Page an agent's audit trail, newest first. Pass the previous page's cursor to continue. */
export const getAgentAudit = (
  did: string,
  registrationId: string,
  cursor?: string
): Promise<AgentAuditPage> => invoke('get_agent_audit', { did, registrationId, cursor });

/**
 * Preview what confirming a claim-ceremony code would grant. Call this BEFORE the biometric
 * gate — the approval screen must show the agent's type and scope list first (informed consent).
 */
export const previewAgentClaim = (did: string, userCode: string): Promise<AgentClaimPreview> =>
  invoke('preview_agent_claim', { did, userCode });

/**
 * Confirm a claim ceremony — the human gate that binds the agent to this account. Callers gate
 * this behind `authenticateBiometric()`; it is the authorization boundary for granting an agent
 * standing access to the identity.
 */
export const confirmAgentClaim = (
  did: string,
  userCode: string
): Promise<AgentClaimConfirmation> => invoke('confirm_agent_claim', { did, userCode });
