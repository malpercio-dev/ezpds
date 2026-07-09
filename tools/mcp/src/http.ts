// Paced, rate-limit-aware HTTP layer, ported from tools/interop/src/http.js.
// All network traffic from the MCP server funnels through here so pacing and
// 429 handling are enforced globally, not per-module.

import { MIN_REQUEST_INTERVAL_MS, MAX_RATE_LIMIT_RETRIES } from './config.ts';

export class HttpError extends Error {
  status: number;
  body: unknown;
  url: string;

  constructor(status: number, body: unknown, url: string) {
    const summary =
      typeof body === 'string' ? body.slice(0, 400) : JSON.stringify(body).slice(0, 400);
    super(`HTTP ${status} from ${url}: ${summary}`);
    this.status = status;
    this.body = body;
    this.url = url;
  }

  /**
   * The error code from a JSON error body. Handles both envelopes the PDS
   * uses: the flat OAuth/agent shape `{error: "code", error_description}` and
   * the XRPC shape `{error: {code: "Code", message}}`.
   */
  get errorCode(): string | null {
    if (typeof this.body !== 'object' || this.body === null) return null;
    const err = (this.body as { error?: unknown }).error;
    if (typeof err === 'string') return err;
    if (typeof err === 'object' && err !== null) {
      const code = (err as { code?: unknown }).code;
      if (typeof code === 'string') return code;
    }
    return null;
  }

  /** The human-readable description from a JSON error body, if present. */
  get errorDescription(): string | null {
    if (typeof this.body !== 'object' || this.body === null) return null;
    const body = this.body as Record<string, unknown>;
    if (typeof body['error_description'] === 'string') return body['error_description'];
    const err = body['error'];
    if (typeof err === 'object' && err !== null) {
      const message = (err as { message?: unknown }).message;
      if (typeof message === 'string') return message;
    }
    return null;
  }
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  token?: string;
  raw?: boolean;
}

let lastRequestAt = 0;

async function pace(): Promise<void> {
  // Reserve the next slot synchronously (before any await) so concurrent
  // callers each get a distinct scheduled time instead of computing the same
  // wait from a stale timestamp and firing back-to-back.
  const now = Date.now();
  const next = Math.max(lastRequestAt + MIN_REQUEST_INTERVAL_MS, now);
  lastRequestAt = next;
  const wait = next - now;
  if (wait > 0) await sleep(wait);
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Perform a paced HTTP request, retrying on 429 per Retry-After.
 *
 * `body` objects are JSON-encoded (string/Uint8Array bodies pass through, and
 * URLSearchParams bodies are form-encoded). With `raw: true` the Response is
 * returned unconsumed; otherwise JSON (or text) is parsed and non-2xx throws
 * HttpError.
 */
export async function request(url: string, options: RequestOptions = {}): Promise<any> {
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

  let body: string | Uint8Array | undefined;
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
    await pace();
    let res: Response;
    try {
      res = await fetch(url, { method: options.method ?? 'GET', headers, body });
    } catch (err: any) {
      // Undici's bare "fetch failed" hides the useful part (ECONNREFUSED,
      // proxy CONNECT denial, TLS failure) in err.cause.
      const cause = err.cause?.message ?? err.cause?.code;
      throw new Error(`${err.message} for ${new URL(url).host}${cause ? ` (${cause})` : ''}`, {
        cause: err,
      });
    }

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
export function xrpc(
  serviceUrl: string,
  nsid: string,
  { params, ...options }: RequestOptions & { params?: Record<string, unknown> } = {},
): Promise<any> {
  const url = new URL(`${serviceUrl}/xrpc/${nsid}`);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }
  return request(url.toString(), options);
}
