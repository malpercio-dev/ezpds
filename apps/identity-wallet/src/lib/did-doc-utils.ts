/**
 * Utility functions for working with DID documents, especially PLC directory format.
 *
 * PLC directory format differs from W3C DID format:
 * - PLC uses "did" (W3C uses "id")
 * - PLC uses "services" as a map (W3C uses "service" as an array)
 * - PLC uses "rotationKeys" as a flat string array (W3C uses "verificationMethod" as an object array)
 * - PLC uses "verificationMethods" as a map (W3C uses "verificationMethod" as an object array)
 */

/**
 * Extracts the PDS (Personal Data Server) endpoint from a PLC directory format DID document.
 *
 * PLC documents store services as a map with keys like "atproto_pds", where the value
 * has an "endpoint" field containing the PDS URL.
 *
 * @param doc - The DID document (loosely typed Record)
 * @returns The PDS endpoint URL, or null if not found or invalid
 */
export function extractPdsFromPlcDoc(doc: Record<string, unknown>): string | null {
  const services = doc.services;
  if (typeof services !== 'object' || services === null) return null;

  const pds = (services as Record<string, unknown>).atproto_pds;
  if (typeof pds !== 'object' || pds === null) return null;

  const endpoint = (pds as Record<string, unknown>).endpoint;
  return typeof endpoint === 'string' ? endpoint : null;
}

/**
 * Whether a cached DID document needs a re-fetch from plc.directory: missing
 * entirely, or lacking a non-empty `rotationKeys` array (the PLC data shape).
 * Earlier builds cached the W3C document — which has no `rotationKeys` — after
 * claim/migration/recovery, starving the custody badge and hiding the migrate
 * entry; `IdentityListHome` uses this predicate to self-heal those caches.
 *
 * @param doc - The cached DID document, or null when none is stored
 * @returns true when the doc should be re-fetched and re-cached
 */
export function docNeedsRotationKeysRefresh(doc: Record<string, unknown> | null): boolean {
  if (!doc) return true;
  const keys = doc.rotationKeys;
  return !Array.isArray(keys) || keys.length === 0;
}

/**
 * Extracts the handle from a PLC directory format DID document's alsoKnownAs array.
 * Strips the "at://" prefix from AT Protocol identifiers.
 *
 * @param doc - The DID document (loosely typed Record)
 * @returns The handle string (without at:// prefix), or null if not found
 */
export function extractHandle(doc: Record<string, unknown>): string | null {
  const alsoKnownAs = doc.alsoKnownAs;
  if (!Array.isArray(alsoKnownAs)) return null;
  for (const aka of alsoKnownAs) {
    if (typeof aka === 'string' && aka.startsWith('at://')) {
      return aka.slice(5);
    }
  }
  return null;
}

/**
 * Truncates a did:plc identifier for display on narrow mobile screens.
 * "did:plc:abcdefghijklmnopqrstuvwx" → "did:plc:abcdefgh…stuvwx"
 *
 * @param did - The full DID string
 * @returns The truncated DID string, or the original if too short to truncate
 */
export function truncateDid(did: string): string {
  const prefix = 'did:plc:';
  if (!did.startsWith(prefix)) return did;
  const specific = did.slice(prefix.length);
  if (specific.length < 14) return did;
  return `${prefix}${specific.slice(0, 8)}…${specific.slice(-6)}`;
}

/**
 * Returns the method segment of a DID (`did:<method>:<method-specific-id>` → `<method>`),
 * or null when `did` is not a well-formed DID.
 */
export function didMethod(did: string): string | null {
  const parts = did.split(':');
  if (parts.length < 3 || parts[0] !== 'did' || parts[1] === '') return null;
  return parts[1];
}

/**
 * Whether `did` is a `did:web` identity.
 *
 * `did:web` has no rotation-key hierarchy, no plc.directory audit log, and no recovery window
 * (ADR-0003): the DID document lives at the user's own domain and is defended by domain control,
 * not by the PLC machinery. The wallet uses this to gate the `did:plc`-only surfaces (PLC
 * monitoring, the recovery-window override, the claim/Shamir ceremonies) so it never presents
 * those assurances for an identity they do not apply to — it says so in-app instead of silently
 * showing an inapplicable "all secure" state.
 */
export function isDidWeb(did: string): boolean {
  return didMethod(did) === 'web';
}

/**
 * Whether an identity is on the OLD recovery model and eligible for a re-key (MM-411).
 *
 * Every account created before the ceremony inversion carries a server-generated split of a
 * secret bound to nothing — its `rotationKeys` are the 2-key `[device, PDS]` array with no
 * recovery key. The new (client-generated) model inserts a recovery key at `rotationKeys[1]`,
 * giving 3 keys. The re-key prompt appears only for old-model identities:
 *
 * - `did:web` is skipped entirely — it has no PLC `rotationKeys`, so the recovery-key concept
 *   does not apply (a separate design question).
 * - A doc without a usable `rotationKeys` array (a stale W3C cache) returns `false` — the caller
 *   self-heals the cache first (`docNeedsRotationKeysRefresh`) so detection reads the PLC shape.
 * - `rotationKeys.length >= 3` is already new-model and never prompts.
 *
 * @param did - The identity's DID
 * @param doc - The cached PLC-shape DID document, or null when none is stored
 * @returns true only for a did:plc identity whose authoritative doc has exactly 2 rotation keys
 */
export function isOldModelRecovery(did: string, doc: Record<string, unknown> | null): boolean {
  if (didMethod(did) !== 'plc') return false;
  if (!doc) return false;
  const keys = doc.rotationKeys;
  if (!Array.isArray(keys)) return false;
  return keys.length === 2;
}

/**
 * Normalizes a PLC directory format DID document to W3C format for DIDDocumentScreen.
 *
 * Converts:
 * - "did" → "id"
 * - "services" map → "service" array (each entry: {id, type, serviceEndpoint})
 * - "rotationKeys" string array → "verificationMethod" array (each entry: {id, type, publicKeyMultibase})
 * - "verificationMethods" map → appended to "verificationMethod" array (each entry: {id, type, publicKeyMultibase})
 * - "alsoKnownAs" passed through
 */
export function normalizePlcDocToW3c(plcDoc: Record<string, unknown>): Record<string, unknown> {
  const normalized: Record<string, unknown> = {
    id: plcDoc.did ?? plcDoc.id,
    alsoKnownAs: plcDoc.alsoKnownAs,
  };

  // Convert services map to service array
  if (typeof plcDoc.services === 'object' && plcDoc.services !== null) {
    const servicesMap = plcDoc.services as Record<string, unknown>;
    const serviceArray: Array<Record<string, unknown>> = [];

    for (const [key, value] of Object.entries(servicesMap)) {
      if (typeof value === 'object' && value !== null) {
        const serviceObj = value as Record<string, unknown>;
        serviceArray.push({
          id: `#${key}`,
          type: serviceObj.type,
          serviceEndpoint: serviceObj.endpoint,
        });
      }
    }

    if (serviceArray.length > 0) {
      normalized.service = serviceArray;
    }
  }

  // Convert rotationKeys array and verificationMethods map to verificationMethod array
  const verificationMethods: Array<Record<string, unknown>> = [];

  if (Array.isArray(plcDoc.rotationKeys)) {
    for (let i = 0; i < plcDoc.rotationKeys.length; i++) {
      const key = plcDoc.rotationKeys[i];
      if (typeof key === 'string') {
        verificationMethods.push({
          id: `#rotation-${i}`,
          type: 'Multikey',
          publicKeyMultibase: key,
        });
      }
    }
  }

  if (typeof plcDoc.verificationMethods === 'object' && plcDoc.verificationMethods !== null) {
    const vmMap = plcDoc.verificationMethods as Record<string, unknown>;
    for (const [key, value] of Object.entries(vmMap)) {
      if (typeof value === 'string') {
        verificationMethods.push({
          id: `#${key}`,
          type: 'Multikey',
          publicKeyMultibase: value,
        });
      }
    }
  }

  if (verificationMethods.length > 0) {
    normalized.verificationMethod = verificationMethods;
  }

  return normalized;
}
