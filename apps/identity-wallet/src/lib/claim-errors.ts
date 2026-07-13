// Shared, presentation-only helpers for rendering claim-flow errors.
//
// The claim screens keep their own `switch` over `ClaimError.code` for context-specific phrasing,
// but the two generic status-classified codes — RATE_LIMITED and SERVER_ERROR — should read the
// same everywhere and are worth testing in isolation. These are pure string functions (no Svelte,
// no IPC), matching the repo's tested-utility pattern (see `deadline.ts`, `appearance.ts`).

/**
 * Turn a `RATE_LIMITED` error's `Retry-After` value into a human sentence.
 *
 * `retryAfter` is the raw HTTP `Retry-After` header the server sent, or null when it sent none. It
 * is most commonly a whole number of seconds; it can also be an HTTP date, which we don't try to
 * parse precisely (we fall back to a generic "try again later"). The point is to tell the user this
 * is a rate limit — a wait — not a connectivity failure.
 */
export function formatRateLimitMessage(retryAfter: string | null): string {
  const lead = 'Your PDS is rate limiting requests.';
  if (retryAfter == null || retryAfter.trim() === '') {
    return `${lead} Please wait a moment and try again.`;
  }
  const seconds = Number(retryAfter.trim());
  if (Number.isInteger(seconds) && seconds > 0) {
    if (seconds < 60) {
      return `${lead} Try again in about ${seconds} second${seconds === 1 ? '' : 's'}.`;
    }
    const minutes = Math.ceil(seconds / 60);
    return `${lead} Try again in about ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  }
  // Non-numeric Retry-After (e.g. an HTTP date) — don't over-parse; keep it honest.
  return `${lead} Please try again later.`;
}

/**
 * Text for a `SERVER_ERROR` — the PDS's own error message, shown verbatim behind a short lead so a
 * third-party PDS's real reason reaches the user. Falls back when the server sent no message.
 */
export function formatServerErrorMessage(message: string): string {
  const trimmed = message.trim();
  return trimmed.length > 0 ? `Your PDS reported: ${trimmed}` : 'Your PDS rejected the request.';
}
