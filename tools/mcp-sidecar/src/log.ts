// Central authorization-material scrubber. ADR-0024: avoiding durable storage is
// not sufficient — logs, traces, errors, and metrics must also redact bearer
// tokens and identity assertions. The stdio server keeps this discipline by
// never writing tokens anywhere; the sidecar handles many callers' tokens, so it
// enforces the same rule centrally and by construction: every log line and every
// client-facing error string is routed through `redact` first.

const REDACTED = '«redacted»';

// A JWT: three base64url segments separated by dots. Access tokens and identity
// assertions both take this shape, so one pattern covers bearer tokens and
// assertions alike, wherever they appear in a string (headers, URLs, JSON).
const JWT = /\b[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g;

// `Authorization: Bearer <token>` (and bare `Bearer <token>`) — catches
// opaque (non-JWT) tokens too, before the JWT rule would miss them.
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;

/**
 * Scrub authorization material from an arbitrary string. Runs the bearer rule
 * first (so `Bearer <jwt>` collapses to one marker, not `Bearer <jwt-marker>`),
 * then the standalone-JWT rule for assertions/tokens that appear without the
 * `Bearer` prefix.
 */
export function redact(input: string): string {
  return input.replace(BEARER, `Bearer ${REDACTED}`).replace(JWT, REDACTED);
}

/**
 * Recursively scrub a value for structured logging: strings via `redact`, and
 * any object key that names an authorization field is dropped entirely (its
 * value never reaches the formatter). Arrays and nested objects are walked.
 */
export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object') {
    // Only recurse into plain objects. `Date`, `Buffer`, `Error`, and other
    // class instances are returned as-is — recursing would flatten a Date to
    // `{}` or explode a Buffer into a per-byte dictionary, degrading log
    // fidelity (they serialize correctly on their own).
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return value;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value)) {
      if (/^(authorization|token|access_?token|assertion|bearer)$/i.test(key)) {
        out[key] = REDACTED;
      } else {
        out[key] = redactValue(v);
      }
    }
    return out;
  }
  return value;
}

/** Scrub an error's message for surfacing to a client (never a raw token). */
export function redactError(err: unknown): string {
  return redact(err instanceof Error ? err.message : String(err));
}

/** Emit one scrubbed log line to stdout (the Railway log stream). */
export function log(message: string): void {
  process.stdout.write(`[custos-mcp-sidecar] ${redact(message)}\n`);
}
