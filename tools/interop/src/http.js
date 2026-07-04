// Paced, rate-limit-aware HTTP layer. All network traffic from the CLI funnels
// through here so pacing and 429 handling are enforced globally, not per-module.

import { MIN_REQUEST_INTERVAL_MS, MAX_RATE_LIMIT_RETRIES } from './config.js';

export class HttpError extends Error {
  constructor(status, body, url) {
    const summary = typeof body === 'string' ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400);
    super(`HTTP ${status} from ${url}: ${summary}`);
    this.status = status;
    this.body = body;
    this.url = url;
  }
}

let lastRequestAt = 0;

async function pace() {
  const wait = lastRequestAt + MIN_REQUEST_INTERVAL_MS - Date.now();
  if (wait > 0) await sleep(wait);
  lastRequestAt = Date.now();
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform a paced HTTP request, retrying on 429 per Retry-After.
 *
 * @param {string} url
 * @param {{method?: string, headers?: object, body?: any, token?: string, raw?: boolean}} options
 *   `body` objects are JSON-encoded. With `raw: true` the Response is returned
 *   unconsumed (for CAR/blob downloads); otherwise JSON (or text) is parsed and
 *   non-2xx throws HttpError.
 */
export async function request(url, options = {}) {
  const headers = { ...(options.headers ?? {}) };
  if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

  let body;
  if (options.body !== undefined) {
    headers['Content-Type'] ??= 'application/json';
    body = typeof options.body === 'string' || options.body instanceof Uint8Array
      ? options.body
      : JSON.stringify(options.body);
  }

  for (let attempt = 0; ; attempt++) {
    await pace();
    const res = await fetch(url, { method: options.method ?? 'GET', headers, body });

    if (res.status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
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
