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
  const labelRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
  return labelRegex.test(label.trim());
}

/**
 * Assemble a full handle from the user's label and the PDS domain, e.g.
 * `composeHandle('alice', 'ezpds.com') === 'alice.ezpds.com'`.
 */
export function composeHandle(label: string, domain: string): string {
  return `${label.trim()}.${domain}`;
}
