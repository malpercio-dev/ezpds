// The consent seam: drives the PDS's password consent page the way a browser would.
//
// An authorization-code flow needs a human to approve at the authorization server. Since the
// server under test is ours and its consent page is a plain password form, the suite fills
// that form directly instead of running a browser.
//
// This file is the ONLY place that knows the page's markup. Every test goes through
// `approveConsent`, so a change to the page is a one-line fix here rather than a diff across
// the whole suite — and when the markup does change, `parseConsentForm` throws a message
// naming itself, instead of failing later as a confusing "missing parameter" from the server.
//
// Rejected alternative: a test-only auto-approve endpoint. It would be immune to markup
// changes, but it would exercise a code path no real client takes — which is the exact
// failure mode (testing our own assumptions instead of the real contract) that the audit
// this suite came from was about.

/** The hidden fields the consent form round-trips, plus the scope checkboxes. */
export interface ConsentFormFields {
  hidden: Record<string, string>;
  /** One value per `granted_scope` checkbox rendered on the page. */
  grantedScopes: string[];
}

function decodeEntities(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * Extract the consent form's fields from the rendered page.
 *
 * Parses by `name=`/`value=` attribute rather than by position or surrounding markup, so
 * restyling the page does not break the suite; only renaming a field does, which is a real
 * contract change worth failing on.
 */
export function parseConsentForm(html: string): ConsentFormFields {
  const hidden: Record<string, string> = {};
  const hiddenPattern =
    /<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>/g;
  for (const match of html.matchAll(hiddenPattern)) {
    const [, name, value] = match;
    if (name !== undefined) hidden[name] = decodeEntities(value ?? '');
  }

  const grantedScopes: string[] = [];
  const checkboxPattern = /<input[^>]*name="granted_scope"[^>]*value="([^"]*)"[^>]*>/g;
  for (const match of html.matchAll(checkboxPattern)) {
    const [, value] = match;
    if (value !== undefined) grantedScopes.push(decodeEntities(value));
  }

  if (!hidden.client_id || !hidden.redirect_uri || !hidden.code_challenge) {
    throw new Error(
      'consent page markup no longer matches what tools/oauth-conformance/src/consent.ts ' +
        'expects: could not find the hidden client_id/redirect_uri/code_challenge inputs. ' +
        'If the consent page was legitimately changed, update parseConsentForm() here — ' +
        'this is the single place the suite knows the page markup.\n' +
        `Received ${html.length} bytes starting: ${html.slice(0, 200)}`,
    );
  }
  return { hidden, grantedScopes };
}

export interface ApprovalResult {
  status: number;
  /** The `Location` header of the redirect back to the client. */
  location: string;
  /** Authorization-response parameters, read from the query or the fragment. */
  params: URLSearchParams;
}

/** Read the authorization response parameters from a redirect, in either response mode. */
export function parseAuthorizationRedirect(location: string): URLSearchParams {
  const url = new URL(location);
  // A fragment-mode response puts everything after '#'; query mode uses the search string.
  return url.hash ? new URLSearchParams(url.hash.slice(1)) : url.searchParams;
}

/**
 * Approve (or deny) an authorization request as the account owner.
 *
 * `grantedScopes` defaults to every checkbox the page offered — i.e. the user approving
 * everything asked for. Passing a narrower list simulates a user unchecking permissions,
 * which is how a scope-narrowing test is written.
 */
export async function approveConsent(
  baseUrl: string,
  authorizeUrl: string,
  credentials: { identifier: string; password: string },
  opts: { decision?: 'approve' | 'deny'; grantedScopes?: string[] } = {},
): Promise<ApprovalResult> {
  const pageRes = await fetch(authorizeUrl);
  const html = await pageRes.text();
  if (pageRes.status !== 200) {
    throw new Error(
      `consent page returned ${pageRes.status} (expected 200). Body: ${html.slice(0, 400)}`,
    );
  }
  const form = parseConsentForm(html);

  const body = new URLSearchParams();
  for (const [name, value] of Object.entries(form.hidden)) body.append(name, value);
  body.append('identifier', credentials.identifier);
  body.append('password', credentials.password);
  body.append('action', opts.decision ?? 'approve');
  for (const scope of opts.grantedScopes ?? form.grantedScopes) {
    body.append('granted_scope', scope);
  }

  // `redirect: 'manual'` is essential: the authorization response *is* the redirect, and
  // following it would send the code to a callback URL that nothing is listening on.
  const res = await fetch(`${baseUrl}/oauth/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    redirect: 'manual',
  });
  const location = res.headers.get('location');
  if (!location) {
    const text = await res.text();
    throw new Error(
      `consent POST did not redirect (status ${res.status}); the credentials may have been ` +
        `rejected. Body: ${text.slice(0, 400)}`,
    );
  }
  return { status: res.status, location, params: parseAuthorizationRedirect(location) };
}
