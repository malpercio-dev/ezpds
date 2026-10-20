// Paced, rate-limit-aware HTTP layer, thin-wrapping tools/interop/src/http.js so the MCP
// server and the interop CLI share one implementation of pacing, 429 retry, and XRPC
// dispatch instead of maintaining a byte-for-byte TS port. All network traffic from the
// MCP server funnels through here so pacing and 429 handling are enforced globally, not
// per-module; mcp keeps its own MIN_REQUEST_INTERVAL_MS/MAX_RATE_LIMIT_RETRIES (configurable
// via CUSTOS_MCP_PACE_MS) rather than interop's live-network defaults.

import {
  HttpError,
  request as interopRequest,
  sleep,
  xrpc as interopXrpc,
} from 'ezpds-interop/src/http.js';
import type { XrpcMethods } from '../../lexgen/types/index.js';
import { MIN_REQUEST_INTERVAL_MS, MAX_RATE_LIMIT_RETRIES } from './config.ts';

export { HttpError, sleep };

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  token?: string;
  raw?: boolean;
}

/**
 * Perform a paced HTTP request (mcp's own pacing), retrying on 429 per Retry-After. See
 * ezpds-interop/src/http.js for the shared implementation.
 */
export function request(url: string, options: RequestOptions = {}): Promise<any> {
  return interopRequest(url, {
    ...options,
    minIntervalMs: MIN_REQUEST_INTERVAL_MS,
    maxRetries: MAX_RATE_LIMIT_RETRIES,
  });
}

type Known = keyof XrpcMethods;

/**
 * Options for one XRPC call. A vendored NSID (see tools/lexgen) gets its lexicon's params and
 * input types, so a renamed lexicon field fails the type-check; an NSID Custos only proxies
 * (app.bsky.feed.*, uploadBlob, …) has no vendored schema and stays loosely typed.
 */
export type XrpcOptions<N extends string> = Omit<RequestOptions, 'body'> &
  (N extends Known
    ? { params?: XrpcMethods[N]['params']; body?: XrpcMethods[N]['input'] }
    : { params?: Record<string, unknown>; body?: unknown });

export type XrpcResult<N extends string> = N extends Known ? XrpcMethods[N]['output'] : any;

/** Convenience: XRPC query/procedure against an arbitrary service base URL. */
export function xrpc<N extends string>(
  serviceUrl: string,
  nsid: N,
  options: XrpcOptions<N> = {} as XrpcOptions<N>,
): Promise<XrpcResult<N>> {
  return interopXrpc(serviceUrl, nsid, {
    ...options,
    minIntervalMs: MIN_REQUEST_INTERVAL_MS,
    maxRetries: MAX_RATE_LIMIT_RETRIES,
  });
}
