/**
 * Labeler-flag presentation logic (Functional Core, unit-tested).
 *
 * The relay reports each flagged account's in-force labels as literal facts
 * (`{val, labelerDid, cts}`); everything about how they read on screen lives here. The
 * flag indicator is always glyph + text (`⚑ spam · did:plc:…xyz · 2026-07-01`), never
 * color alone, per DESIGN.md §2.
 */
import type { AccountFlag, AccountListEntry } from '$lib/ipc';
import { shortenId } from '$lib/format';

/**
 * One rendered flag line: label value · labeler · date. The ⚑ glyph is the caller's
 * (it is decorative for assistive tech; this text carries the meaning).
 */
export function flagLine(flag: AccountFlag): string {
  return `${flag.val} · ${shortenId(flag.labelerDid)} · ${flagDate(flag.cts)}`;
}

/**
 * The calendar-date portion of a label timestamp — the operator triages "when was this
 * flagged" at day granularity. Literal-truth fallback: a timestamp that isn't ISO-shaped
 * is shown verbatim rather than hidden or reformatted into a guess.
 */
export function flagDate(cts: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})/.exec(cts);
  return match ? match[1] : cts;
}

/**
 * Mirror of the relay's account ordering — flagged accounts first, DID order within each
 * group — for the fake harness, so the browser harness renders the same triage view a
 * real relay produces. Pure: returns a new array.
 */
export function sortFlaggedFirst(accounts: AccountListEntry[]): AccountListEntry[] {
  return [...accounts].sort((a, b) => {
    const flagDelta = Number(b.flags.length > 0) - Number(a.flags.length > 0);
    if (flagDelta !== 0) return flagDelta;
    return a.did < b.did ? -1 : a.did > b.did ? 1 : 0;
  });
}
