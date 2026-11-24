import { describe, it, expect } from 'vitest';
import { buildRegistry } from './registry';
import { scenarios } from './scenarios';
import type { KemKeyPlan } from '$lib/ipc';

/**
 * "Update identity for Spaces" through the fake: an account created before KEM keys existed
 * publishes `atproto_kem`, once per publish path.
 */
describe('wallet harness: update identity for Spaces', () => {
  const methodsOf = (registry: ReturnType<typeof buildRegistry>, did: string) =>
    (registry.get_stored_did_doc({ did }) as { verificationMethods: Record<string, string> })
      .verificationMethods;

  it('publishes the KEM key for a did:plc through a reviewed op', () => {
    const registry = buildRegistry(scenarios['spaces-kem-unpublished']());
    const did = (registry.list_identities({}) as string[]).find((d) => d.startsWith('did:plc:'))!;
    expect(methodsOf(registry, did).atproto_kem).toBeUndefined();

    const plan = registry.prepare_kem_key_publish_cmd({ did }) as KemKeyPlan;
    expect(plan.kind).toBe('plcOperation');
    if (plan.kind !== 'plcOperation') return;
    expect(methodsOf(registry, did).atproto_kem, 'prepare changes nothing').toBeUndefined();

    registry.complete_kem_key_publish_cmd({ did });
    expect(methodsOf(registry, did).atproto_kem).toBe(plan.diff.kemKey);
    expect(() => registry.complete_kem_key_publish_cmd({ did })).toThrow();
  });

  it('hands a self-hosted did:web the updated did.json to publish', () => {
    const registry = buildRegistry(scenarios['spaces-kem-unpublished']());
    const did = 'did:web:alice.example';

    const plan = registry.prepare_kem_key_publish_cmd({ did }) as KemKeyPlan;
    expect(plan.kind).toBe('didWebDocument');
    if (plan.kind !== 'didWebDocument') return;
    expect(plan.documentUrl).toBe('https://alice.example/.well-known/did.json');
    const document = JSON.parse(plan.documentText) as {
      verificationMethod: Array<{ id: string; publicKeyMultibase: string }>;
    };
    const kem = document.verificationMethod.find((m) => m.id === '#atproto_kem');
    expect(`did:key:${kem?.publicKeyMultibase}`).toBe(plan.diff.kemKey);

    registry.complete_kem_key_publish_cmd({ did });
    expect(methodsOf(registry, did).atproto_kem).toBe(plan.diff.kemKey);
  });

  it('stages a fresh key on a rotation and names the one it replaces', () => {
    const registry = buildRegistry(scenarios['spaces-kem-unpublished']());
    const did = (registry.list_identities({}) as string[])[0];
    const first = registry.prepare_kem_key_publish_cmd({ did }) as KemKeyPlan;
    registry.complete_kem_key_publish_cmd({ did });
    const second = registry.prepare_kem_key_publish_cmd({ did }) as KemKeyPlan;
    if (first.kind === 'published' || second.kind === 'published') throw new Error('unexpected');
    expect(second.diff.kemKey).not.toBe(first.diff.kemKey);
    expect(second.diff.replacedKemKey).toBe(first.diff.kemKey);
  });
});
