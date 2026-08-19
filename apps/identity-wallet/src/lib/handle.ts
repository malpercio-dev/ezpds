/**
 * Handle assembly helpers for the create-account flow.
 *
 * An AT Protocol handle is a full domain name (`<label>.<domain>`). The user only chooses the
 * leftmost label (e.g. `alice`); the domain comes from the PDS's `availableUserDomains`. The
 * full handle must be assembled BEFORE the DID ceremony so the did:plc genesis op's
 * `alsoKnownAs` carries the real, resolvable handle (`at://alice.ezpds.com`) rather than a bare
 * label that would render as `handle.invalid` on the network.
 */

/**
 * Validate a single handle label (the part the user types, e.g. `alice`).
 *
 * RFC 1035 DNS label: ASCII alphanumerics with internal hyphens only — no leading/trailing
 * hyphen, no dots (a dot would create extra labels), no underscores or whitespace.
 */
export function isValidLabel(label: string): boolean {
  const normalized = label.trim();
  const labelRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
  // Enforce the RFC 1035 single-label limit (63 chars) the server also applies.
  return normalized.length > 0 && normalized.length <= 63 && labelRegex.test(normalized);
}

/**
 * Assemble a full handle from the user's label and the PDS domain, e.g.
 * `composeHandle('alice', 'ezpds.com') === 'alice.ezpds.com'`.
 */
export function composeHandle(label: string, domain: string): string {
  return `${label.trim()}.${domain}`;
}

/**
 * Validate a FULL handle the user typed themselves (the custom-domain path, e.g.
 * `alice.example.com` or an apex like `example.com`), mirroring the server's structural
 * rule so obviously-invalid input fails locally before any network round trip: at least
 * two DNS labels, each a valid RFC 1035 label, at most 253 chars total, and a final
 * label (the effective TLD) that doesn't start with a digit.
 *
 * Surrounding whitespace and a leading `@` are tolerated (the caller normalizes them
 * away before use); interior whitespace is invalid.
 */
export function isValidHandle(handle: string): boolean {
  const h = handle.trim().replace(/^@/, '');
  if (h.length === 0 || h.length > 253 || /\s/.test(h)) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  // isValidLabel trims its input; interior whitespace was already rejected above, so
  // that leniency cannot mask a malformed label here.
  if (!labels.every((label) => isValidLabel(label))) return false;
  return !/^[0-9]/.test(labels[labels.length - 1]);
}

/**
 * Normalize a user-typed full handle to its canonical form: trimmed, no leading `@`,
 * lowercase (handles are case-insensitive; the canonical form is lowercase).
 */
export function normalizeHandle(handle: string): string {
  return handle.trim().replace(/^@/, '').toLowerCase();
}
