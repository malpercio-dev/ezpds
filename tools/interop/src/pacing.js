// Request pacing, kept apart from config.js so the HTTP layer can be imported without
// evaluating the deployment config. config.js freezes EZPDS_BASE_URL and EZPDS_ADMIN_TOKEN at
// first import, and a hermetic test harness only knows those once it has spawned its PDS: a
// tool that merely imports http.js must not pin them first.

// Minimum gap between HTTP requests, so scripted runs stay far below the
// PDS per-IP limits (global 3000/5min; createSession 30/5min) and are polite to
// public infrastructure (plc.directory, the relay, the AppView).
export const MIN_REQUEST_INTERVAL_MS = Number(process.env.EZPDS_INTEROP_PACE_MS ?? 350);

// How many times to retry a 429 (honoring Retry-After) before giving up.
export const MAX_RATE_LIMIT_RETRIES = 4;
