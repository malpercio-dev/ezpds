import { describe, expect, it } from 'vitest';
import { agentName } from './agent-display';
import type { AgentSummary } from '$lib/ipc';

const base: AgentSummary = {
  registrationId: 'reg_1',
  registrationType: 'oauth_app',
  scopes: [],
  status: 'claimed',
  createdAt: '2026-11-08T00:00:00.000Z',
  updatedAt: '2026-11-08T00:00:00.000Z',
};

describe('agentName', () => {
  it('names an OAuth grant by its client host', () => {
    expect(agentName({ ...base, clientId: 'https://bsky.app/oauth-client-metadata.json' })).toBe(
      'bsky.app',
    );
  });

  it('falls back to the raw client id, then the registration id', () => {
    expect(agentName({ ...base, clientId: 'not a url' })).toBe('not a url');
    expect(agentName(base)).toBe('reg_1');
  });

  it('prefers the subject an agent registered with', () => {
    expect(agentName({ ...base, subject: 'helper-bot', clientId: 'https://x.example/m.json' })).toBe(
      'helper-bot',
    );
  });
});
