import { describe, expect, it } from 'vitest';
import { composeDidWebDocument, didWebDocumentUrl, didWebFromDomain, serializeDidWebDocument } from './did-web';

describe('did:web ceremony document', () => {
  it('publishes the device key, reserved repo key, and Custos service', () => {
    const doc = composeDidWebDocument('Alice.Example.com', 'alice.example.com', 'zdevice', 'zrepo', 'https://pds.example.com/');
    expect(doc.id).toBe('did:web:alice.example.com');
    expect(doc.verificationMethod.map((vm) => [vm.id, vm.publicKeyMultibase])).toEqual([
      ['did:web:alice.example.com#device', 'zdevice'],
      ['did:web:alice.example.com#atproto', 'zrepo'],
    ]);
    expect(doc.service[0]).toMatchObject({ id: 'did:web:alice.example.com#atproto_pds', serviceEndpoint: 'https://pds.example.com' });
  });

  it('uses well-known resolution and deterministic serialization', () => {
    expect(didWebDocumentUrl(didWebFromDomain('https://me.example/'))).toBe('https://me.example/.well-known/did.json');
    const rendered = serializeDidWebDocument(composeDidWebDocument('me.example', 'me.example', 'zd', 'zr', 'https://pds.example'));
    expect(rendered.endsWith('\n')).toBe(true);
  });

  it('rejects paths, ports, and non-public-looking names', () => {
    for (const value of ['localhost', 'example.com/path', 'example.com:8443']) {
      expect(() => didWebFromDomain(value)).toThrow();
    }
  });
});
