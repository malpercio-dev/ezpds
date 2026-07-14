/**
 * A pairing payload decoded from a scanned QR (or pasted text). The operator's
 * code-minting tool encodes `{ relayUrl, pairingCode }` as JSON in the QR.
 */
export interface PairingPayload {
  relayUrl: string;
  pairingCode: string;
}

/**
 * Parse a scanned/pasted pairing payload. Accepts the canonical JSON
 * `{"relayUrl":"…","pairingCode":"…"}`; returns `null` if the text is not a
 * well-formed payload (the caller then keeps the manual-entry fields).
 *
 * A pure parser — no IPC — so it lives outside `$lib/ipc.ts` (which stays the
 * sole `invoke()` caller). The QR scan itself is the mobile-plugin wrapper in `ipc.ts`.
 */
export function parsePairingPayload(text: string): PairingPayload | null {
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object') return null;
    const record = parsed as Record<string, unknown>;
    const { relayUrl, pairingCode } = record;
    // The contract is exactly two fields — an object carrying extras (e.g. a stray
    // "debug" key) is not a valid pairing payload and must be rejected. Requiring both
    // fields to be present strings under a 2-key cap means the two keys can only be
    // relayUrl and pairingCode.
    if (
      Object.keys(record).length === 2 &&
      typeof relayUrl === 'string' &&
      typeof pairingCode === 'string'
    ) {
      const url = relayUrl.trim();
      const code = pairingCode.trim();
      if (url && code) {
        return { relayUrl: url, pairingCode: code };
      }
    }
  } catch {
    // Not JSON — not a structured payload.
  }
  return null;
}
