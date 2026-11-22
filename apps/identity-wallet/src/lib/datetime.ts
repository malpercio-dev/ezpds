const SQLITE_UTC = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

/**
 * The app's single house style for an absolute timestamp: compact, locale-aware,
 * to the minute — no seconds, no year. Every place we show a timestamp (agent
 * activity, an unauthorized-change detection time, a recovery-window deadline) is
 * within a span where month/day/time reads unambiguously, so the heavier
 * `toLocaleString()` (year + seconds) buys nothing and only adds noise.
 *
 * Accepts an ISO 8601 string, a Date (deadlines are already Date objects), or the
 * server's zone-less SQLite `datetime('now')` shape (`YYYY-MM-DD HH:MM:SS`), which is
 * UTC — `new Date()` would otherwise read it as device-local time.
 */
export function formatTimestamp(value: string | Date): string {
  const d =
    value instanceof Date ? value : new Date(SQLITE_UTC.test(value) ? `${value.replace(' ', 'T')}Z` : value);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}
