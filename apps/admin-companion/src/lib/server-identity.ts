// pattern: Functional Core
//
// Display identity for a paired relay. The nickname is the operator's word for the
// server; the host is the ground truth that disambiguates duplicate nicknames. Both
// are always shown together (text + position — never color) so the operator can tell
// staging from production at a glance on every screen.

import type { Pairing } from './ipc';

export interface ServerIdentity {
  /** Operator-facing name. Falls back to the host when the nickname is empty (a
   * pairing created before nicknames existed). */
  nickname: string;
  /** The relay URL's host (with port when present) — shown in monospace beneath the
   * nickname everywhere. */
  host: string;
}

/** The relay URL's host, or the raw string when it does not parse as a URL — a broken
 * URL should read as itself, not vanish. */
export function hostOf(relayUrl: string): string {
  try {
    return new URL(relayUrl).host;
  } catch {
    return relayUrl.trim();
  }
}

export function serverIdentity(pairing: Pick<Pairing, 'nickname' | 'relayUrl'>): ServerIdentity {
  const host = hostOf(pairing.relayUrl);
  const nickname = pairing.nickname.trim();
  return { nickname: nickname === '' ? host : nickname, host };
}
