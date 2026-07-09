import { describe, expect, it } from 'vitest';
import { describeScope, describeScopes } from './agent-scopes';

describe('describeScope', () => {
  it('describes the default agent grant profile in plain language', () => {
    // The operator default: atproto + repo create/update + any blob.
    expect(describeScope('atproto').summary).toBe('Act as an ATProto client for your account');
    expect(describeScope('repo:*?action=create&action=update').summary).toBe(
      'Create and edit any record in your repository'
    );
    expect(describeScope('blob:*/*').summary).toBe('Upload files (any type)');
  });

  it('names well-known collections', () => {
    expect(describeScope('repo:app.bsky.feed.post?action=create').summary).toBe('Create posts');
    expect(describeScope('repo:app.bsky.graph.follow?action=create&action=delete').summary).toBe(
      'Create and delete follows'
    );
  });

  it('falls back to the raw collection NSID for unknown collections', () => {
    expect(describeScope('repo:com.example.custom?action=update').summary).toBe(
      'Edit com.example.custom records'
    );
  });

  it('describes blob mime families', () => {
    expect(describeScope('blob:image/*').summary).toBe('Upload images');
    expect(describeScope('blob:video/*').summary).toBe('Upload videos');
    expect(describeScope('blob:application/pdf').summary).toBe('Upload application/pdf files');
  });

  it('marks account/identity/full-access grants as elevated', () => {
    expect(describeScope('account:email?action=manage').elevated).toBe(true);
    expect(describeScope('identity:handle').elevated).toBe(true);
    expect(describeScope('com.atproto.access').elevated).toBe(true);
    expect(describeScope('transition:generic').elevated).toBe(true);
    expect(describeScope('repo:*').elevated).toBe(false);
  });

  it('never hides an unknown token behind a vague label', () => {
    const desc = describeScope('mystery:thing?x=1');
    expect(desc.summary).toBe('mystery:thing?x=1');
    expect(desc.token).toBe('mystery:thing?x=1');
  });

  it('always carries the raw token alongside the summary', () => {
    for (const desc of describeScopes(['atproto', 'repo:*', 'blob:*/*', 'weird'])) {
      expect(desc.token.length).toBeGreaterThan(0);
    }
  });
});
