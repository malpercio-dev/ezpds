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

  it('describes space grants, mirroring the server defaults', () => {
    // No params: your own spaces, full record access (the grammar's default action set).
    expect(describeScope('space:org.example.bucket').summary).toBe(
      'Read, create, edit, and delete records in your org.example.bucket private spaces'
    );
    // Explicit actions; read_self folds into read.
    expect(describeScope('space:*?action=read&action=read_self').summary).toBe(
      'Read records in your private spaces'
    );
    // Foreign authority and the anyone wildcard are said out loud.
    expect(
      describeScope('space:org.example.bucket?authority=did:plc:abc234567abc234567abc234').summary
    ).toBe(
      'Read, create, edit, and delete records in org.example.bucket private spaces run by did:plc:abc234567abc234567abc234'
    );
    expect(describeScope('space:*?authority=*&collection=*').summary).toBe(
      'Read, create, edit, and delete records in private spaces run by anyone'
    );
    // manage verbs act on the spaces themselves and are called out separately.
    expect(describeScope('space:org.example.bucket?manage=delete').summary).toBe(
      'Read, create, edit, and delete records in your org.example.bucket private spaces — and delete those spaces themselves'
    );
    expect(describeScope('space:*').elevated).toBe(false);
  });

  it('names the service an rpc grant is bound to', () => {
    // The default agent profile's AppView-read grant.
    expect(describeScope('rpc:*?aud=did:web:api.bsky.app').summary).toBe(
      'Call the Bluesky app service on your behalf'
    );
    // A `#serviceId` fragment does not change what the grant reaches, so it does not change
    // the name either — the server matches audiences on the bare DID.
    expect(describeScope('rpc:*?aud=did:web:api.bsky.chat#bsky_chat').summary).toBe(
      'Call the Bluesky chat service on your behalf'
    );
    // A named method leads with the method.
    expect(describeScope('rpc:app.bsky.feed.getPosts?aud=did:web:api.bsky.app').summary).toBe(
      'Call app.bsky.feed.getPosts on the Bluesky app service'
    );
    // An audience with no friendly name is shown verbatim, never softened.
    expect(describeScope('rpc:*?aud=did:plc:abc234567abc234567abc234').summary).toBe(
      'Call did:plc:abc234567abc234567abc234 on your behalf'
    );
    // The one unbounded case says so.
    expect(describeScope('rpc:app.bsky.feed.getPosts?aud=*').summary).toBe(
      'Call app.bsky.feed.getPosts on ANY service'
    );
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
