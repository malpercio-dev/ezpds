/**
 * PLC recovery-deadline utilities, shared by every alarm surface.
 *
 * A rotation-key recovery override must land within plc.directory's 72-hour window
 * (`RECOVERY_WINDOW_MS` — computed locally here, enforced by the directory itself).
 * `getDeadline` adds the window to an unauthorized operation's ISO 8601 `createdAt`;
 * `getUrgency` maps time remaining onto the app-wide four-state `Urgency` vocabulary
 * (expired at 0, critical under 4h, warning under 24h, safe at 24h and up);
 * `formatCountdown` renders the "Xh Ym remaining" line. Pure; tested by `deadline.test.ts`.
 */
export const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000; // 72 hours

export function getDeadline(createdAt: string): Date {
  const timestamp = new Date(createdAt).getTime();
  if (isNaN(timestamp)) {
    throw new Error(`Invalid createdAt timestamp: ${createdAt}`);
  }
  return new Date(timestamp + RECOVERY_WINDOW_MS);
}

export type Urgency = 'safe' | 'warning' | 'critical' | 'expired';

export function getUrgency(deadline: Date, now: number = Date.now()): Urgency {
  const remaining = deadline.getTime() - now;
  if (remaining <= 0) return 'expired';
  if (remaining < 4 * 60 * 60 * 1000) return 'critical';
  if (remaining < 24 * 60 * 60 * 1000) return 'warning';
  return 'safe';
}

export function formatCountdown(deadline: Date, now: number = Date.now()): string {
  const remaining = deadline.getTime() - now;
  if (remaining <= 0) return 'Expired';
  const hours = Math.floor(remaining / (1000 * 60 * 60));
  const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
  return `${hours}h ${minutes}m remaining`;
}
