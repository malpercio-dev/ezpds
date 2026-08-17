// The consent seam: drives the PDS's consent page the way a browser would.
//
// An authorization-code flow needs a human to approve at the authorization server. The page
// offers two ways to do that, and this file drives the browser's side of both: the password
// form (filled directly, no browser needed) and the wallet path, where the browser's only jobs
// are to display the codes and, once the wallet has approved out of band, to POST the
// completion form. The wallet's own side — the signed approval — is not a browser concern and
// lives in `wallet-consent.ts`.
//
// This file is the ONLY place that knows the page's markup. Every test goes through
// `approveConsent` or `parseWalletPath`, so a change to the page is a one-line fix here rather
// than a diff across the whole suite — and when the markup does change, the parsers throw a
// message naming themselves, instead of failing later as a confusing "missing parameter" from
// the server.
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

/** What the wallet-approval block of the consent page shows the user. */
export interface WalletPathFields {
  /** The poll / handoff / completion key, carried on the block's data attribute. */
  requestId: string;
  /** The human-typeable code the user enters in the wallet. */
  userCode: string;
  /**
   * The two-digit number the page displays, present only when a `login-approval` push was
   * dispatched for this request. `null` on every other channel — and the wallet's own preview
   * is what states whether a number is *required*; this is only what the page shows.
   */
  matchCode: string | null;
}

/**
 * Extract the wallet-approval block's fields from the rendered page.
 *
 * Throws rather than returning `null` when the block is absent: every caller is a test that
 * has just asked the server for a page it expects to carry one, and "the wallet path did not
 * render" is a far more useful failure than a downstream 404 on an undefined user code.
 */
export function parseWalletPath(html: string): WalletPathFields {
  const requestId = /<div[^>]*id="wallet-path"[^>]*data-request-id="([^"]+)"/.exec(html)?.[1];
  const userCode = /<div class="user-code mono">([^<]*)<\/div>/.exec(html)?.[1];
  if (!requestId || !userCode) {
    throw new Error(
      'the consent page rendered no wallet-approval block, or its markup no longer matches ' +
        'what tools/oauth-conformance/src/consent.ts expects (looked for #wallet-path\'s ' +
        'data-request-id and the .user-code element). Note that the block is best-effort in ' +
        'oauth_authorize.rs — a rate-limited or failed pending-request creation degrades the ' +
        'page to password-only.\n' +
        `Received ${html.length} bytes starting: ${html.slice(0, 200)}`,
    );
  }
  const matchCode = /<div class="match-code mono" id="match-code">([^<]*)<\/div>/.exec(html)?.[1];
  return {
    requestId: decodeEntities(requestId),
    userCode: decodeEntities(userCode),
    matchCode: matchCode === undefined ? null : decodeEntities(matchCode),
  };
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

/**
 * Submit the wallet block's completion form — the browser's last act on the wallet path.
 *
 * This is the page's no-JS "I've approved — continue" button; its inline poller submits the
 * identical form on approval, so driving the form covers both. Unlike `approveConsent`, this
 * carries no credential: the approval already happened out of band, and all this does is
 * exchange an approved request for its authorization code.
 *
 * Returns the raw response rather than throwing on a non-redirect, because "completion did not
 * redirect" is a result several tests assert on (a request that is not approved, or was
 * already completed, renders an error page instead).
 */
export async function completeWalletConsent(
  baseUrl: string,
  requestId: string,
): Promise<{ status: number; location: string | null; params: URLSearchParams; body: string }> {
  const res = await fetch(`${baseUrl}/oauth/authorize/complete`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ request_id: requestId }).toString(),
    redirect: 'manual',
  });
  const location = res.headers.get('location');
  return {
    status: res.status,
    location,
    params: location ? parseAuthorizationRedirect(location) : new URLSearchParams(),
    body: location ? '' : await res.text(),
  };
}
