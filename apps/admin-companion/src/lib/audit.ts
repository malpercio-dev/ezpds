/**
 * Pure presentation logic for the server-wide admin audit log screen (Functional Core —
 * no IPC, no DOM; unit-tested in `audit.test.ts`).
 *
 * The relay reports literal facts (action words, actor strings, a JSON detail object);
 * everything judgment-shaped — which chip tone an action gets, how a row's summary line
 * reads — lives here, not in the endpoint and not inline in the screen.
 */
import type { AuditEventEntry } from '$lib/ipc';

/** Chip variants the UI primitive understands (mirrors `StatusChip`'s `status` prop). */
export type AuditChip = 'active' | 'ready' | 'revoked' | 'error' | 'pending' | 'info';

/**
 * Every action word the relay can record, in the relay's own vocabulary — the filter
 * chip row renders these verbatim (the console reports the literal truth; no renaming).
 * Must stay in lockstep with `AdminAuditAction` in `crates/pds/src/db/admin_audit.rs`.
 */
export const AUDIT_ACTIONS = [
  'account_takedown',
  'account_restore',
  'credentials_revoked',
  'claim_codes_minted',
  'claim_code_revoked',
  'pairing_code_minted',
  'device_registered',
  'device_revoked',
  'transfer_cancelled',
  'request_crawl',
  'email_updated',
  'reset_token_issued',
  'signing_key_created',
] as const;

/**
 * Map an action to its chip tone. Destructive interventions get the critical tone,
 * the one restorative action the safe tone, and everything additive/neutral stays
 * informational — tone always rides with a text label, never color alone.
 */
export function chipFor(event: AuditEventEntry): { chip: AuditChip; label: string } {
  switch (event.action) {
    case 'account_takedown':
    case 'credentials_revoked':
    case 'claim_code_revoked':
    case 'device_revoked':
    case 'transfer_cancelled':
      return { chip: 'revoked', label: event.outcome };
    case 'account_restore':
      return { chip: 'ready', label: event.outcome };
    default:
      return { chip: 'info', label: event.outcome };
  }
}

/**
 * The row's second mono line: when and by whom, plus the subject when there is one.
 * `2026-07-15 11:45:00 · device:dev-1 → did:plc:abc`
 */
export function summaryLine(event: AuditEventEntry): string {
  const base = `${event.createdAt} · ${event.actor}`;
  return event.subject ? `${base} → ${event.subject}` : base;
}

/**
 * Flatten the detail object into fact-sheet rows. Values render as compact literals —
 * strings verbatim, everything else JSON — so the sheet stays the relay's truth.
 */
export function detailEntries(detail: Record<string, unknown> | null): [string, string][] {
  if (!detail) return [];
  return Object.entries(detail).map(([key, value]) => [
    key,
    typeof value === 'string' ? value : JSON.stringify(value),
  ]);
}
