import { describe, expect, it } from 'vitest';
import type { AuditEventEntry } from '$lib/ipc';
import { AUDIT_ACTIONS, chipFor, detailEntries, summaryLine } from './audit';

function event(overrides: Partial<AuditEventEntry> = {}): AuditEventEntry {
  return {
    id: 'evt-1',
    actor: 'master-token',
    action: 'request_crawl',
    subject: null,
    outcome: 'ok',
    detail: null,
    createdAt: '2026-07-15 12:00:00',
    ...overrides,
  };
}

describe('chipFor', () => {
  it('gives destructive interventions the critical tone with the outcome as label', () => {
    for (const action of [
      'account_takedown',
      'credentials_revoked',
      'claim_code_revoked',
      'device_revoked',
      'transfer_cancelled',
    ]) {
      const chip = chipFor(event({ action, outcome: 'revoked' }));
      expect(chip.chip).toBe('revoked');
      expect(chip.label).toBe('revoked');
    }
  });

  it('gives the restore action the safe tone', () => {
    expect(chipFor(event({ action: 'account_restore' })).chip).toBe('ready');
  });

  it('keeps additive and neutral actions informational', () => {
    for (const action of [
      'claim_codes_minted',
      'pairing_code_minted',
      'device_registered',
      'request_crawl',
      'email_updated',
      'reset_token_issued',
      'signing_key_created',
    ]) {
      expect(chipFor(event({ action })).chip).toBe('info');
    }
  });

  it('covers every action word the relay can record', () => {
    // A new relay action must land in an explicit tone bucket (default = info), and the
    // filter-chip vocabulary must include it.
    expect(AUDIT_ACTIONS).toHaveLength(13);
    for (const action of AUDIT_ACTIONS) {
      expect(['revoked', 'ready', 'info']).toContain(chipFor(event({ action })).chip);
    }
  });
});

describe('summaryLine', () => {
  it('reads time · actor for a subject-less event', () => {
    expect(summaryLine(event())).toBe('2026-07-15 12:00:00 · master-token');
  });

  it('appends the subject with an arrow when present', () => {
    const line = summaryLine(
      event({ actor: 'device:dev-1', action: 'account_takedown', subject: 'did:plc:abc' }),
    );
    expect(line).toBe('2026-07-15 12:00:00 · device:dev-1 → did:plc:abc');
  });
});

describe('detailEntries', () => {
  it('is empty for a detail-less event', () => {
    expect(detailEntries(null)).toEqual([]);
  });

  it('renders strings verbatim and non-strings as compact JSON', () => {
    expect(
      detailEntries({ resultingStatus: 'takendown', sessionsRevoked: 2, flag: true }),
    ).toEqual([
      ['resultingStatus', 'takendown'],
      ['sessionsRevoked', '2'],
      ['flag', 'true'],
    ]);
  });
});
