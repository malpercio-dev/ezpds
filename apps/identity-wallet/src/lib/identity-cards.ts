import { listIdentities, getStoredDidDoc, refreshDidDoc, getDeviceKeyId, isCodedError } from '$lib/ipc';
import {
  extractHandle,
  extractPdsFromPlcDoc,
  docNeedsRotationKeysRefresh,
} from '$lib/did-doc-utils';

/**
 * Reading the local facts about a managed identity — what the home list and the Protection
 * surface both need before either can say anything about it.
 *
 * This is a composition over `$lib/ipc` rather than an `invoke()` wrapper, so it lives out
 * here alongside `unlock.ts` rather than inside the IPC registry. It is shared because the
 * two surfaces must agree: home and Protection listing the same identity with different
 * custody answers would be a security surface contradicting itself.
 */
export interface IdentityCard {
  did: string;
  handle: string | null;
  pdsUrl: string | null;
  /** The cached PLC-shaped DID document; null when the cache had nothing for this DID. */
  didDoc: Record<string, unknown> | null;
  deviceKeyIsRoot: boolean | null;
  /**
   * The Secure Enclave no longer holds this identity's device key (`DEVICE_KEY_UNUSABLE`).
   * Distinct from `deviceKeyIsRoot === null`, which only means the custody question could
   * not be answered; this is a definite answer — the key is gone.
   */
  deviceKeyUnusable: boolean;
}

function isDeviceKeyRoot(
  didDoc: Record<string, unknown>,
  deviceKeyId: string
): boolean | null {
  const rotationKeys = didDoc.rotationKeys;
  if (!Array.isArray(rotationKeys) || rotationKeys.length === 0) return null;
  return rotationKeys[0] === deviceKeyId;
}

/** Read one identity's local facts. Throws only if the identity cannot be read at all. */
export async function loadIdentityCard(did: string): Promise<IdentityCard> {
  // The device key is asked for separately from the doc so a DEVICE_KEY_UNUSABLE verdict is
  // caught as the specific, actionable state it is rather than collapsing the whole card
  // into the generic degraded branch its caller falls back to.
  let deviceKeyUnusable = false;
  let keyId = '';
  let didDoc = await getStoredDidDoc(did);
  try {
    keyId = await getDeviceKeyId(did);
  } catch (e) {
    if (isCodedError(e) && e.code === 'DEVICE_KEY_UNUSABLE') {
      deviceKeyUnusable = true;
    } else {
      throw e;
    }
  }

  // Cache self-heal: earlier builds cached DID docs without rotationKeys (the W3C shape),
  // which starves the custody badge and hides the migrate entry. Re-fetch the PLC data
  // document once and re-store it; on failure keep whatever the cache had.
  if (docNeedsRotationKeysRefresh(didDoc)) {
    try {
      didDoc = await refreshDidDoc(did);
    } catch (e) {
      console.warn(`DID doc refresh failed for ${did}:`, e);
    }
  }

  return {
    did,
    handle: didDoc ? extractHandle(didDoc) : null,
    pdsUrl: didDoc ? extractPdsFromPlcDoc(didDoc) : null,
    didDoc,
    // With no usable key there is no custody claim to make in either direction: the badge
    // must not say "root key" (nothing can sign) and must not say "not root" (the DID
    // document still lists this device's key at the top).
    deviceKeyIsRoot: didDoc && !deviceKeyUnusable ? isDeviceKeyRoot(didDoc, keyId) : null,
    deviceKeyUnusable,
  };
}

/**
 * Every managed identity's local facts, in `IdentityStore` order.
 *
 * An identity whose read fails becomes a degraded card rather than disappearing: a
 * security surface that silently drops an identity it could not read is the one failure
 * mode worse than showing it with unknowns.
 */
export async function loadIdentityCards(): Promise<IdentityCard[]> {
  const dids = await listIdentities();
  const cards: IdentityCard[] = [];
  for (const did of dids) {
    try {
      cards.push(await loadIdentityCard(did));
    } catch (e) {
      console.error(`Failed to load identity ${did}:`, e);
      cards.push({
        did,
        handle: null,
        pdsUrl: null,
        didDoc: null,
        deviceKeyIsRoot: null,
        deviceKeyUnusable: false,
      });
    }
  }
  return cards;
}
