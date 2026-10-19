// Rich-text facet detection for post text. Without facets an agent's URLs,
// hashtags, and mentions render as dead plain text — the PDS stores records
// verbatim and never derives them, and clients only linkify what the record
// says to linkify.
//
// Pure: no network, no session. Mention *spans* are detected here but the
// handle → DID resolution they need is the caller's (see tools.ts).
//
// Offsets are byte offsets into the UTF-8 encoding of the text, per
// app.bsky.richtext.facet#byteSlice — not JavaScript's UTF-16 indices.

export interface ByteSlice {
  byteStart: number;
  byteEnd: number;
}

export interface Facet {
  index: ByteSlice;
  features: Record<string, unknown>[];
}

export interface MentionSpan {
  handle: string;
  index: ByteSlice;
}

/**
 * Only fully-qualified URLs are detected.
 *
 * ponytail: bare domains ("example.com") are left plain. Telling one from
 * ordinary prose ("tools.ts", "e.g.", "node.js") needs the public-suffix list
 * the official client carries; guessing without it turns filenames into links,
 * which is worse than the missing facet. Add a TLD list if bare domains matter.
 */
const URL_RE = /https?:\/\/[^\s]+/gi;
const TAG_RE = /(^|\s)[#＃](\S+)/gu;
// Handle grammar per the atproto spec's syntax rules: letters, digits, hyphen,
// and the dots separating segments.
const MENTION_RE = /(^|\s|\()@([a-zA-Z0-9.-]+)/g;

/** Trailing punctuation a writer meant as prose, not as part of the URL. */
function trimUrlTail(url: string): string {
  let out = url.replace(/[.,;:!?'"]+$/, '');
  // A closing paren belongs to the URL only if the URL opened one itself:
  // "(see https://ex.com/a)" vs "https://ex.com/wiki/Foo_(bar)".
  while (out.endsWith(')') && !out.includes('(')) out = out.slice(0, -1);
  return out;
}

/**
 * Whether a `#…` span is a hashtag rather than incidental punctuation.
 *
 * Rejects the numeric forms people write in prose ("#1", "#2026") and enforces
 * the 640-byte ceiling AppViews index at.
 */
function isValidTag(tag: string): boolean {
  if (tag.length === 0) return false;
  if (/^\d+$/.test(tag)) return false;
  return Buffer.byteLength(tag, 'utf8') <= 640;
}

/** Byte offset of a UTF-16 index into `text`. */
function byteOffset(text: string, index: number): number {
  return Buffer.byteLength(text.slice(0, index), 'utf8');
}

function slice(text: string, start: number, end: number): ByteSlice {
  return { byteStart: byteOffset(text, start), byteEnd: byteOffset(text, end) };
}

/** Link and hashtag facets — everything detectable without a network call. */
export function detectFacets(text: string): Facet[] {
  const facets: Facet[] = [];

  for (const match of text.matchAll(URL_RE)) {
    const uri = trimUrlTail(match[0]);
    if (!uri) continue;
    const start = match.index;
    facets.push({
      index: slice(text, start, start + uri.length),
      features: [{ $type: 'app.bsky.richtext.facet#link', uri }],
    });
  }

  for (const match of text.matchAll(TAG_RE)) {
    const [, lead = '', body = ''] = match;
    // The span covers "#tag"; the feature value drops the marker.
    const tag = body.replace(/[.,;:!?'"]+$/, '');
    if (!isValidTag(tag)) continue;
    const start = match.index + lead.length;
    facets.push({
      index: slice(text, start, start + 1 + tag.length),
      features: [{ $type: 'app.bsky.richtext.facet#tag', tag }],
    });
  }

  return facets;
}

/**
 * Handle mentions and their spans. Only dotted handles are returned: an
 * undotted "@someone" is not a handle under the atproto grammar, so resolving
 * it would be a guaranteed-failed round trip.
 */
export function detectMentions(text: string): MentionSpan[] {
  const mentions: MentionSpan[] = [];
  for (const match of text.matchAll(MENTION_RE)) {
    const [, lead = '', body = ''] = match;
    const handle = body.replace(/\.+$/, '');
    if (!handle.includes('.')) continue;
    const start = match.index + lead.length;
    mentions.push({ handle, index: slice(text, start, start + 1 + handle.length) });
  }
  return mentions;
}

/** Facets in byte order, as the lexicon's consumers expect to read them. */
export function sortFacets(facets: Facet[]): Facet[] {
  return facets.sort((a, b) => a.index.byteStart - b.index.byteStart);
}
