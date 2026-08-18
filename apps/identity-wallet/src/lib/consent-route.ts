// Which identity should answer a consent request that arrived with no identity attached.
//
// A tapped `login-approval` push names its DID (the NSE forwards it from the sealed
// payload), but the Camera-app QR path cannot: the QR is a plain URL carrying only a
// `request_id`, and iOS opens the app with nothing else. A single-identity wallet has an
// obvious answer; a multi-identity wallet has to work out which identity's hosting server
// even knows this request — and, when the request is pre-bound to an account via its
// `login_hint`, which managed identity that is.
//
// The probe is safe by construction: the consent preview is an unauthenticated read (the
// high-entropy request_id is the capability), so asking an identity's PDS about a request it
// has never heard of leaks nothing and costs one failed GET. Pure over an injected preview
// function, so every branch is testable without a server.

export type ConsentIdentityCandidate = {
  did: string;
  /** The identity's handle, when locally known — matched against a handle-form login_hint. */
  handle: string | null;
};

export type ConsentPreviewProbe = (
  did: string,
  requestId: string
) => Promise<{ loginHint: string | null }>;

/**
 * Resolve the managed identity that should open consent request `requestId`, or `null` when
 * no single identity can be chosen — in which case the caller must not navigate, because
 * opening the wrong identity's approval screen would invite approving as the wrong account
 * (the server would refuse a hint-bound request, but the user should never be set up for it).
 *
 * Resolution ladder:
 * 1. One managed identity → it, no network.
 * 2. Probe every identity's hosting PDS for the request (in parallel). Identities whose
 *    server doesn't know the request are out.
 * 3. If the request carries a `login_hint`, the identity matching it (by DID, or by handle
 *    for a handle-form hint) wins.
 * 4. No hint, but exactly one identity's server knows the request → that one.
 * 5. Anything else is genuinely ambiguous → `null`.
 */
export async function resolveConsentIdentity(
  requestId: string,
  identities: ConsentIdentityCandidate[],
  preview: ConsentPreviewProbe
): Promise<string | null> {
  if (identities.length === 0) return null;
  if (identities.length === 1) return identities[0].did;

  const probes = await Promise.allSettled(
    identities.map((identity) => preview(identity.did, requestId))
  );
  const holders = identities.filter((_, index) => probes[index].status === 'fulfilled');
  if (holders.length === 0) return null;

  // All fulfilled probes describe the same server-side request, so any one's hint serves.
  const first = probes.find(
    (probe): probe is PromiseFulfilledResult<{ loginHint: string | null }> =>
      probe.status === 'fulfilled'
  );
  const hint = normalizeHint(first?.value.loginHint ?? null);
  if (hint !== null) {
    const matches = holders.filter(
      (identity) =>
        identity.did.toLowerCase() === hint ||
        (identity.handle !== null && identity.handle.toLowerCase() === hint)
    );
    if (matches.length === 1) return matches[0].did;
    // A hint that matches no managed identity (or, degenerately, several) leaves the
    // request bound to an account this wallet cannot single out — fall through to the
    // holder count rather than guessing among mismatches.
  }

  return holders.length === 1 ? holders[0].did : null;
}

/** Reduce a client-supplied login hint to a comparable form: `at://` and `@` prefixes off,
 *  lowercased. A DID-form hint comes through unchanged apart from case. */
function normalizeHint(raw: string | null): string | null {
  if (raw === null) return null;
  const trimmed = raw.trim();
  if (trimmed === '') return null;
  const withoutAt = trimmed.startsWith('at://') ? trimmed.slice('at://'.length) : trimmed;
  const bare = withoutAt.startsWith('@') ? withoutAt.slice(1) : withoutAt;
  return bare.toLowerCase();
}
