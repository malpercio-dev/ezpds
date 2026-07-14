import { invoke } from '@tauri-apps/api/core';

// ── Agent consent + audit (auth.md claim ceremony, "My agents") ──────────────

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

/** Errors from the agent consent/management commands. */
export type AgentsError = {
  code:
    | 'NOT_AUTHENTICATED'
    | 'CODE_NOT_FOUND'
    | 'CODE_EXPIRED'
    | 'ALREADY_CLAIMED'
    | 'ACCESS_DENIED'
    | 'AGENT_NOT_FOUND'
    | 'RATE_LIMITED'
    | 'NETWORK_ERROR'
    | 'UNKNOWN';
};

/** List the agent identities bound to this account. */
export const listAgents = (): Promise<AgentSummary[]> => invoke('list_agents');

/** Revoke an agent identity (idempotent; the next token exchange is refused immediately). */
export const revokeAgent = (registrationId: string): Promise<void> =>
  invoke('revoke_agent', { registrationId });

/** Page an agent's audit trail, newest first. Pass the previous page's cursor to continue. */
export const getAgentAudit = (
  registrationId: string,
  cursor?: string
): Promise<AgentAuditPage> => invoke('get_agent_audit', { registrationId, cursor });

/**
 * Preview what confirming a claim-ceremony code would grant. Call this BEFORE the biometric
 * gate — the approval screen must show the agent's type and scope list first (informed consent).
 */
export const previewAgentClaim = (userCode: string): Promise<AgentClaimPreview> =>
  invoke('preview_agent_claim', { userCode });

/**
 * Confirm a claim ceremony — the human gate that binds the agent to this account. Callers gate
 * this behind `authenticateBiometric()`; it is the authorization boundary for granting an agent
 * standing access to the identity.
 */
export const confirmAgentClaim = (userCode: string): Promise<AgentClaimConfirmation> =>
  invoke('confirm_agent_claim', { userCode });
