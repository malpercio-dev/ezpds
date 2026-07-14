import type { AgentSummary, AgentAuditEvent } from '$lib/ipc';

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
