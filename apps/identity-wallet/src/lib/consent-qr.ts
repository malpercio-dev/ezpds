/**
 * Parse the `request_id` out of a scanned consent QR (Phase B).
 *
 * The Custos consent page encodes the pending request under the wallet's private-use scheme:
 * `org.obsign.identitywallet:/consent?request_id=…&origin=…`. The QR (and the same-device handoff
 * link) carries the requesting `origin` too, but the wallet deliberately ignores it here: the
 * approval screen re-fetches the client, origin, and scope from the server's record **by
 * request_id** and never trusts the QR contents for what it displays. So this parser extracts only
 * the `request_id`.
 *
 * A pure parser — no IPC — so it lives outside `$lib/ipc` (which stays the `invoke()` boundary). The
 * camera scan itself is the mobile-plugin wrapper in `$lib/ipc/qr-scan`.
 *
 * Returns the `request_id` string, or `null` if the text is not a well-formed consent payload (the
 * caller then keeps the typed-code entry — the guaranteed fallback).
 */
export function parseConsentQr(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  // Accept the full private-use URI. A bare `?query` or a `//host/path?query` shape both parse once
  // a base is supplied, so normalize to a parseable URL and read the `request_id` param.
  let requestId: string | null = null;
  try {
    // The custom scheme (`org.obsign.identitywallet:/consent?…`) is a valid absolute URL; `URL`
    // parses its query even though the scheme is non-special.
    const url = new URL(trimmed);
    requestId = url.searchParams.get('request_id');
  } catch {
    // Not a URL — try a lone query string (`request_id=…&origin=…`) as a lenient fallback.
    const q = trimmed.startsWith('?') ? trimmed.slice(1) : trimmed;
    if (q.includes('request_id=')) {
      requestId = new URLSearchParams(q).get('request_id');
    }
  }

  if (!requestId) return null;
  const value = requestId.trim();
  // The server mints request ids as `poauth_<token>`. Require that prefix and a plausible,
  // charset-restricted body so a stray QR (a URL that merely carries a `request_id` param) can't
  // drive a preview. The server is still the authority — an unknown id 404s — this only rejects
  // obvious non-payloads before any network call.
  if (!/^poauth_[A-Za-z0-9_-]{8,128}$/.test(value)) return null;
  return value;
}
