/**
 * The app's single house style for an absolute timestamp: compact, locale-aware,
 * to the minute — no seconds, no year. Every place we show a timestamp (agent
 * activity, an unauthorized-change detection time, a recovery-window deadline) is
 * within a span where month/day/time reads unambiguously, so the heavier
 * `toLocaleString()` (year + seconds) buys nothing and only adds noise.
 *
 * Accepts an ISO 8601 string or a Date (deadlines are already Date objects).
 */
export function formatTimestamp(value: string | Date): string {
  const d = value instanceof Date ? value : new Date(value);
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}
