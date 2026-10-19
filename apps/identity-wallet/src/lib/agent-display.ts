import type { AgentSummary, AgentAuditEvent, ChildSummary } from '$lib/ipc';

/** Status is always text + icon + position — never color alone. */
export const AGENT_STATUS: Record<AgentSummary['status'], { label: string; hint: string }> = {
  active: { label: 'Pending approval', hint: 'Registered, waiting for your confirmation' },
  claimed: { label: 'Connected', hint: 'Can act within its granted permissions' },
  revoked: { label: 'Revoked', hint: 'Access turned off — new sign-ins are refused' },
};

export const AGENT_EVENT_LABELS: Record<AgentAuditEvent['eventType'], string> = {
  registered: 'Registered with your server',
  claim_initiated: 'Asked for your approval',
  claim_confirmed: 'You approved access',
  claim_expired: 'Approval request expired',
  token_exchanged: 'Signed in',
  repo_write: 'Wrote to your repository',
  blob_upload: 'Uploaded a file',
  revoked: 'Access revoked',
  assertion_reminted: 'You renewed its credential',
};

export const AGENT_TYPE_LABELS: Record<AgentSummary['registrationType'], string> = {
  service_auth: 'Server-requested',
  identity_assertion: 'Identity-provider vouched',
  anonymous: 'Self-registered',
};

export function agentName(agent: AgentSummary): string {
  return agent.subject ?? agent.registrationId;
}

/** Mechanical detail facts → one short human line; unknown shapes stay hidden behind the label. */
export function agentDetailLine(event: AgentAuditEvent): string | null {
  const d = event.detail;
  if (!d) return null;
  if (event.eventType === 'repo_write') {
    const parts: string[] = [];
    const counts: string[] = [];
    if (typeof d.creates === 'number' && d.creates > 0) counts.push(`${d.creates} created`);
    if (typeof d.updates === 'number' && d.updates > 0) counts.push(`${d.updates} edited`);
    if (typeof d.deletes === 'number' && d.deletes > 0) counts.push(`${d.deletes} deleted`);
    if (counts.length) parts.push(counts.join(', '));
    if (Array.isArray(d.collections) && d.collections.length) {
      parts.push(`in ${d.collections.join(', ')}`);
    }
    return parts.length ? parts.join(' ') : null;
  }
  if (event.eventType === 'blob_upload') {
    const mime = typeof d.mime_type === 'string' ? d.mime_type : null;
    const size = typeof d.size === 'number' ? `${Math.max(1, Math.round(d.size / 1024))} KB` : null;
    return [mime, size].filter(Boolean).join(', ') || null;
  }
  if (event.eventType === 'token_exchanged' && typeof d.grant === 'string') {
    return d.grant === 'claim' ? 'collected its first credential' : 'renewed its credential';
  }
  return null;
}

// ── Sovereign child accounts ─────────────────────────────────────────────────

/**
 * A child's displayed state. Not the same axis as its registration `status`: deleting a child
 * revokes it as a side effect, so a retired child and a merely revoked one share `status:
 * 'revoked'` on the wire and are told apart only by the purge date. Scheduled deletion is the
 * graver fact, so it wins over the status it implies.
 */
export type ChildState = 'live' | 'provisioning' | 'revoked' | 'deleting';

export const CHILD_STATUS: Record<ChildState, { label: string; hint: string }> = {
  live: {
    label: 'Active',
    hint: 'Acts as itself, under your recovery authority',
  },
  provisioning: {
    label: 'Being set up',
    hint: 'The account exists but has not collected its credential yet',
  },
  revoked: {
    label: 'Revoked',
    hint: 'Credential turned off — the account and its history remain',
  },
  deleting: {
    label: 'Scheduled for deletion',
    hint: 'Deactivated now; permanently removed after the date below',
  },
};

export function childState(child: ChildSummary): ChildState {
  if (child.deleteAfter) return 'deleting';
  if (child.status === 'claimed') return 'live';
  if (child.status === 'active') return 'provisioning';
  return 'revoked';
}
