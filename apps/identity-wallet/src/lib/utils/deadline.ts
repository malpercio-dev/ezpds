export const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000; // 72 hours

export function getDeadline(createdAt: string): Date {
  return new Date(new Date(createdAt).getTime() + RECOVERY_WINDOW_MS);
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
