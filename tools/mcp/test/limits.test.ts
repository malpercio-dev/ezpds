// Lexicon text bounds are pure, so they are tested without a PDS. The unit is
// the part worth pinning: atproto counts UTF-8 bytes and extended grapheme
// clusters, and JavaScript's String.length is neither — a regression shows up
// as a post the tool accepts and the PDS then rejects.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ZodError } from 'zod';
import { lexiconText, graphemeCount } from '../src/tools.ts';

const postText = lexiconText(3000, 300);

/** Every message a failed parse produced, joined for matching. */
function messages(error: ZodError): string {
  return error.issues.map((issue) => issue.message).join(' | ');
}

test('grapheme clusters are counted, not code points', () => {
  // A family emoji is one grapheme built from several code points joined by ZWJ.
  assert.equal(graphemeCount('👨‍👩‍👧‍👦'), 1);
  assert.equal(graphemeCount('é'), 1); // e + combining acute
});

test('post text over 300 graphemes is rejected', () => {
  assert.equal(postText.safeParse('a'.repeat(300)).success, true);

  const tooMany = postText.safeParse('a'.repeat(301));
  assert.equal(tooMany.success, false);
  assert.match(messages(tooMany.error!), /301 graphemes, limit is 300/);
});

test('text within 300 graphemes still fails on the byte bound', () => {
  // 300 clusters of "e" plus six combining acutes: 13 UTF-8 bytes each, so 3900
  // bytes in 300 graphemes and only 2100 UTF-16 units. Counting characters
  // instead of bytes would let this through to the PDS.
  const stacked = ('e' + '́'.repeat(6)).repeat(300);
  assert.equal(graphemeCount(stacked), 300);

  const result = postText.safeParse(stacked);
  assert.equal(result.success, false);
  assert.match(messages(result.error!), /3900 UTF-8 bytes, limit is 3000/);
});
