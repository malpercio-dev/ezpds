// Paced, rate-limit-aware HTTP layer. All network traffic from the CLI funnels
// through here so pacing and 429 handling are enforced globally, not per-module.

import { MIN_REQUEST_INTERVAL_MS, MAX_RATE_LIMIT_RETRIES } from './config.js';
import { dpopProof } from './dpop.js';

export class HttpError extends Error {
  constructor(status, body, url) {
    const summary = typeof body === 'string' ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400);
    super(`HTTP ${status} from ${url}: ${summary}`);
    this.status = status;
    this.body = body;
    this.url = url;
  }

  /**
   * The error code from a JSON error body. Handles both envelopes the PDS uses: the flat
   * OAuth/agent shape `{error: "code", error_description}` and the XRPC shape
   * `{error: {code: "Code", message}}`.
   * @returns {string | null}
   */
  get errorCode() {
    if (typeof this.body !== 'object' || this.body === null) return null;
    const err = this.body.error;
    if (typeof err === 'string') return err;
    if (typeof err === 'object' && err !== null && typeof err.code === 'string') return err.code;
    return null;
  }

  /**
   * The human-readable description from a JSON error body, if present.
   * @returns {string | null}
   */
  get errorDescription() {
    if (typeof this.body !== 'object' || this.body === null) return null;
    if (typeof this.body.error_description === 'string') return this.body.error_description;
    const err = this.body.error;
    if (typeof err === 'object' && err !== null && typeof err.message === 'string') return err.message;
    return null;
  }
}

let lastRequestAt = 0;

async function pace(intervalMs) {
  // Reserve the next slot synchronously (before any await) so concurrent
  // callers each get a distinct scheduled time instead of computing the same
  // wait from a stale timestamp and firing back-to-back.
  const now = Date.now();
  const next = Math.max(lastRequestAt + intervalMs, now);
  lastRequestAt = next;
  const wait = next - now;
  if (wait > 0) await sleep(wait);
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform a paced HTTP request, retrying on 429 per Retry-After.
 *
 * @param {string} url
 * @param {{method?: string, headers?: object, body?: any, token?: string, raw?: boolean,
 *          dpop?: {key: object, bind?: string}, minIntervalMs?: number, maxRetries?: number}} options
 *   `body` objects are JSON-encoded; a `URLSearchParams` body is form-encoded instead
 *   (`application/x-www-form-urlencoded`, e.g. an OAuth token-endpoint request); string
 *   and `Uint8Array` bodies pass through as-is. With `raw: true` the Response is returned
 *   unconsumed (for CAR/blob downloads); otherwise JSON (or text) is parsed and
 *   non-2xx throws HttpError.
 *
 *   `dpop` attaches an RFC 9449 proof. With `bind` (a DPoP-bound space credential) the
 *   request also switches to `Authorization: DPoP <bind>` and the proof carries `ath`;
 *   without it the proof is the mint-time kind and `token` still supplies the Bearer
 *   grant — the two shapes `getSpaceCredential` and the credential-authed reads want.
 *
 *   `minIntervalMs`/`maxRetries` override this module's own pacing defaults for callers
 *   (e.g. tools/mcp) that configure their own — every request still funnels through the
 *   one `lastRequestAt` clock, so pacing stays global within the process either way.
 */
export async function request(url, options = {}) {
  const headers = { ...(options.headers ?? {}) };
  const method = options.method ?? 'GET';
  const minIntervalMs = options.minIntervalMs ?? MIN_REQUEST_INTERVAL_MS;
  const maxRetries = options.maxRetries ?? MAX_RATE_LIMIT_RETRIES;
  if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

  let body;
  if (options.body !== undefined) {
    if (options.body instanceof URLSearchParams) {
      headers['Content-Type'] ??= 'application/x-www-form-urlencoded';
      body = options.body.toString();
    } else if (typeof options.body === 'string' || options.body instanceof Uint8Array) {
      headers['Content-Type'] ??= 'application/json';
      body = options.body;
    } else {
      headers['Content-Type'] ??= 'application/json';
      body = JSON.stringify(options.body);
    }
  }

  for (let attempt = 0; ; attempt++) {
    await pace(minIntervalMs);
    // Minted per attempt, not once: a proof's `iat` is good for 60s while a Retry-After
    // wait can be 120s, and the space read seam spends each `jti` once per host — so a
    // reused proof after a rate-limit retry would be rejected as stale *and* as a replay.
    if (options.dpop) {
      if (options.dpop.bind) headers['Authorization'] = `DPoP ${options.dpop.bind}`;
      headers['DPoP'] = await dpopProof(options.dpop.key, { method, url, boundToken: options.dpop.bind });
    }
    let res;
    try {
      res = await fetch(url, { method, headers, body });
    } catch (err) {
      // Undici's bare "fetch failed" hides the useful part (ECONNREFUSED,
      // proxy CONNECT denial, TLS failure) in err.cause.
      const cause = err.cause?.message ?? err.cause?.code;
      throw new Error(`${err.message} for ${new URL(url).host}${cause ? ` (${cause})` : ''}`, { cause: err });
    }

    if (res.status === 429 && attempt < maxRetries) {
      const retryAfter = Number(res.headers.get('retry-after')) || 2 ** attempt * 2;
      const delay = Math.min(retryAfter, 120) * 1000;
      process.stderr.write(`  rate-limited by ${new URL(url).host}; waiting ${delay / 1000}s\n`);
      await res.arrayBuffer().catch(() => {});
      await sleep(delay);
      continue;
    }

    if (options.raw) return res;

    const text = await res.text();
    const contentType = res.headers.get('content-type') ?? '';
    const parsed = contentType.includes('json') && text ? JSON.parse(text) : text;
    if (!res.ok) throw new HttpError(res.status, parsed, url);
    return parsed;
  }
}

/** Convenience: XRPC query/procedure against an arbitrary service base URL. */
export function xrpc(serviceUrl, nsid, { params, ...options } = {}) {
  const url = new URL(`${serviceUrl}/xrpc/${nsid}`);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }
  return request(url.toString(), options);
}
