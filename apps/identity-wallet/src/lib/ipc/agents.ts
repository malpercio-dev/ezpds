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
    | 'revoked'
    | 'assertion_reminted';
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
  /**
   * The handle an `anonymous` agent proposed for an account of its own. Present only when it
   * asked; offer it as an editable default, never a commitment.
   */
  handleHint?: string;
};

/** A child account just minted for an agent — its own identity, under this account's authority. */
export type MintedChild = {
  registrationId: string;
  /** The child's own `did:plc`, which is the hash of the genesis op this wallet signed. */
  did: string;
  handle: string;
};

/**
 * One sovereign child account under this identity (`GET /agent/child` entry).
 *
 * Addressed by `did` — its own — rather than a registration id, because a child is an account
 * first and a capability second. Its audit trail still reads through {@link getAgentAudit} with
 * `registrationId`: the `/v1/agents` routes accept the parent as owner of a child's registration.
 */
export type ChildSummary = {
  registrationId: string;
  /** The child's own `did:plc`. Every lifecycle command takes this as `childDid`. */
  did: string;
  handle: string;
  /** `claimed` = live, `active` = mid-provisioning, `revoked` = capability turned off. */
  status: 'active' | 'claimed' | 'revoked';
  createdAt: string;
  scopes: string[];
  /**
   * Set only once deletion is scheduled: when the server purges the child permanently. Deleting
   * revokes as a side effect, so `status` alone cannot tell a retired child from a merely revoked
   * one — this field is what distinguishes them, and it must lead the UI when present.
   */
  deleteAfter?: string;
};

/** Result of scheduling a child's deletion. */
export type ChildDeletion = {
  did: string;
  status: string;
  /** When the child is purged for good — until then it is deactivated, not gone. */
  deleteAfter: string;
};

/**
 * A renewed child credential. `identityAssertion` is live and secret: show it once for the user
 * to hand back to the agent, offer a copy, and keep no copy of it in wallet state.
 */
export type ChildAssertion = {
  did: string;
  registrationId: string;
  identityAssertion: string;
  assertionExpires: string;
  scopes: string[];
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
  // No delegation seed — route to "Enable agent accounts" instead of retrying.
  | { code: 'NOT_PROVISIONED' }
  // The proposed child handle (or the op built around it) was refused. Recoverable: the claim
  // attempt is not spent, so the user can correct the handle and submit again.
  | { code: 'HANDLE_REJECTED'; message: string }
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

/**
 * Confirm a claim ceremony the cooperative way: mint the agent an account of its own — its own
 * DID, repo, and handle — under this account's rotation authority, instead of handing it a
 * credential for this account.
 *
 * Only offered for an `anonymous` registration on a provisioned identity; gate it behind
 * `authenticateBiometric()` exactly like {@link confirmAgentClaim}, since it is the same
 * authorization boundary. A `HANDLE_REJECTED` failure is recoverable — the claim attempt is not
 * spent, so re-submit with a corrected handle rather than restarting the ceremony.
 */
export const mintChildFromClaim = (
  did: string,
  userCode: string,
  handle: string
): Promise<MintedChild> => invoke('mint_child_from_claim', { did, userCode, handle });

/**
 * Whether this identity can give an agent an account of its own.
 *
 * True once the delegation seed — the root every child account's rotation key derives from —
 * is in the Keychain: written by the create ceremony for identities made since, and by
 * "Enable agent accounts" (share verification) for any made before. Gate the child-mint path
 * on this and route an unprovisioned identity to provisioning; never start a mint without it,
 * since there would be no key to sign the child's genesis op with.
 */
export const agentAccountsProvisioned = (did: string): Promise<boolean> =>
  invoke('agent_accounts_provisioned', { did });

// ── Child lifecycle (the parent console under My Agents) ─────────────────────
//
// `did` is always the authenticating parent; `childDid` names the child being acted on.

/** List the sovereign child accounts this identity has minted for agents. */
export const listChildren = (did: string): Promise<ChildSummary[]> =>
  invoke('list_children', { did });

/**
 * Turn a child's delegated capability off, keeping its account, repo, and DID.
 *
 * The lower rung of the custody ladder — the identity the user gave the agent survives, and its
 * history stays readable. Gate it behind `authenticateBiometric()` like {@link revokeAgent}.
 */
export const revokeChild = (did: string, childDid: string): Promise<void> =>
  invoke('revoke_child', { did, childDid });

/**
 * Retire a child's hosting: revoke it, deactivate it now, schedule the permanent purge.
 *
 * Show the returned `deleteAfter` — until it passes the data is deactivated rather than gone.
 * The child's did:plc is untouched; this server holds no rotation key for it.
 */
export const deleteChild = (did: string, childDid: string): Promise<ChildDeletion> =>
  invoke('delete_child', { did, childDid });

/**
 * Renew a live child's identity assertion — its credential for the token endpoint.
 *
 * An active child renews itself at every token exchange, so this is for one that lay dormant past
 * a full assertion lifetime and can no longer bootstrap. A revoked child is `ACCESS_DENIED`:
 * renewal is never a way back up the ladder revocation walked down.
 */
export const remintChildAssertion = (did: string, childDid: string): Promise<ChildAssertion> =>
  invoke('remint_child_assertion', { did, childDid });

// ── Recovery epilogue for children ──────────────────────────────────────────

/**
 * What the recovery check concluded about one child's rotation key.
 *
 * `unmatched` and `unchecked` are deliberately different answers and must read differently to
 * the user: the first is a custody finding — the public directory was read and names no key this
 * wallet derives — while the second means the question could not be asked at all. Rendering a
 * network blip as a lost key would be a false alarm about the one thing this screen exists to
 * report honestly.
 */
export type ChildKeyStatus =
  | { status: 'matched'; index: number }
  | { status: 'unmatched' }
  | { status: 'unchecked'; message: string };

/** One child's entry in a recovery reconciliation. */
export type ChildKeyCheck = { did: string; handle: string } & ChildKeyStatus;

/** The result of re-deriving this identity's children against the public directory. */
export type ChildReconciliation = {
  /**
   * False when this device's counter already covered the server's list, so nothing was
   * re-derived and nothing was checked. `children` is then empty — an absence of findings, never
   * a clean bill of health, so never render it as one.
   */
  rebuilt: boolean;
  children: ChildKeyCheck[];
  /** The child index this device will mint at next. */
  nextIndex: number;
};

/**
 * Re-derive this identity's agent accounts after a recovery and rebuild the local child counter.
 *
 * The recovery epilogue for children: once a restore has put the delegation seed back, this asks
 * the server which children exist and checks each one's live rotation keys against the keys that
 * seed derives — so a restored wallet can say which of its agents' accounts it still holds
 * recovery authority for. Cheap and idempotent otherwise: on a device that is not recovering it
 * short-circuits before touching the public directory and returns `rebuilt: false`.
 */
export const reconcileChildren = (did: string): Promise<ChildReconciliation> =>
  invoke('reconcile_children', { did });
