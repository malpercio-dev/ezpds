export type DidWebHosting = 'self' | 'custos';
export type DidWebOrigin = 'new' | 'existing';

export type DidWebDocument = {
  '@context': string[];
  id: string;
  alsoKnownAs: string[];
  verificationMethod: Array<{
    id: string;
    type: 'Multikey';
    controller: string;
    publicKeyMultibase: string;
  }>;
  service: Array<{
    id: string;
    type: 'AtprotoPersonalDataServer';
    serviceEndpoint: string;
  }>;
};

/** Convert a user-owned HTTPS hostname to the hostname-form ATProto did:web DID. */
export function didWebFromDomain(input: string): string {
  const raw = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (raw.includes('/') || raw.includes(':') || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(raw) || !raw.includes('.')) {
    throw new Error('Enter a public domain name without a path or port.');
  }
  return `did:web:${raw}`;
}

/** Compose the exact document the user must publish before Custos promotes the account. */
export function composeDidWebDocument(
  domain: string,
  handle: string,
  deviceKeyMultibase: string,
  repoKeyMultibase: string,
  pdsUrl: string,
): DidWebDocument {
  const did = didWebFromDomain(domain);
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    alsoKnownAs: [`at://${handle}`],
    verificationMethod: [
      {
        id: `${did}#device`,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: deviceKeyMultibase,
      },
      {
        id: `${did}#atproto`,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: repoKeyMultibase,
      },
    ],
    service: [
      {
        id: `${did}#atproto_pds`,
        type: 'AtprotoPersonalDataServer',
        serviceEndpoint: pdsUrl.replace(/\/$/, ''),
      },
    ],
  };
}

/** Serialize a DID document deterministically, including its required final newline. */
export function serializeDidWebDocument(document: DidWebDocument): string {
  return `${JSON.stringify(document, null, 2)}\n`;
}

/** Resolve a validated did:web identifier to its authoritative HTTPS document URL. */
export function didWebDocumentUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error('Not a did:web identifier.');
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  const host = parts.shift();
  if (!host || forbiddenDidWebAuthority(host) || parts.some((part) => part === '' || /[/\\?#]/.test(part))) {
    throw new Error('Invalid did:web identifier.');
  }
  return parts.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${parts.join('/')}/did.json`;
}

function forbiddenDidWebAuthority(authority: string): boolean {
  if (authority.includes('@') || authority.includes('[') || authority.includes(']')) return true;
  const separator = authority.lastIndexOf(':');
  const host = separator === -1 ? authority : authority.slice(0, separator);
  const port = separator === -1 ? null : authority.slice(separator + 1);
  if (!host || (port !== null && (!/^\d+$/.test(port) || Number(port) > 65535))) return true;
  const normalized = host.replace(/\.$/, '').toLowerCase();
  return normalized === 'localhost' || normalized.endsWith('.localhost') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized);
}
