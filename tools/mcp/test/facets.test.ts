// Facet detection is pure, so it is tested without a PDS. The offsets are the
// part worth pinning: they are UTF-8 byte offsets, and JavaScript's string
// indices are not, so any regression shows up as a link that highlights the
// wrong span rather than as an error.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectFacets, detectMentions, type ByteSlice } from '../src/facets.ts';

/** The substring a facet's byte offsets actually select. */
function selected(text: string, index: ByteSlice): string {
  return Buffer.from(text, 'utf8').subarray(index.byteStart, index.byteEnd).toString('utf8');
}

/** The sole element, asserting there is exactly one. */
function only<T>(items: T[], label = ''): T {
  assert.equal(items.length, 1, `expected exactly one ${label || 'item'}`);
  const [first] = items;
  assert.ok(first);
  return first;
}

test('detects a link and spans exactly the URL', () => {
  const text = 'shipped: https://obsign.org/blog nice';
  const facet = only(detectFacets(text), 'facet');
  assert.deepEqual(facet.features, [
    { $type: 'app.bsky.richtext.facet#link', uri: 'https://obsign.org/blog' },
  ]);
  assert.equal(selected(text, facet.index), 'https://obsign.org/blog');
});

test('byte offsets account for multi-byte text before the match', () => {
  const text = '🔑 café → https://obsign.org';
  const facet = only(detectFacets(text), 'facet');
  assert.equal(selected(text, facet.index), 'https://obsign.org');
  // The emoji alone is 4 bytes, so a UTF-16 index would fall short here.
  assert.ok(facet.index.byteStart > text.indexOf('https'));
});

test('trailing prose punctuation stays out of the URL', () => {
  for (const [text, uri] of [
    ['see https://obsign.org.', 'https://obsign.org'],
    ['(see https://obsign.org)', 'https://obsign.org'],
    ['https://en.wikipedia.org/wiki/Foo_(bar)', 'https://en.wikipedia.org/wiki/Foo_(bar)'],
  ] as const) {
    const facet = only(detectFacets(text), 'facet');
    assert.deepEqual(facet.features, [{ $type: 'app.bsky.richtext.facet#link', uri }], text);
    assert.equal(selected(text, facet.index), uri, text);
  }
});

test('bare domains and filenames are left alone', () => {
  assert.deepEqual(detectFacets('edit tools/mcp/src/facets.ts in example.com style'), []);
});

test('hashtags are detected without the marker, numeric ones ignored', () => {
  const text = 'shipping #Custos today, issue #539';
  const facet = only(detectFacets(text), 'facet');
  assert.deepEqual(facet.features, [{ $type: 'app.bsky.richtext.facet#tag', tag: 'Custos' }]);
  assert.equal(selected(text, facet.index), '#Custos');
});

test('a hash inside a URL is not a second facet', () => {
  const facet = only(detectFacets('https://obsign.org/docs#install'), 'facet');
  assert.deepEqual(facet.features, [
    { $type: 'app.bsky.richtext.facet#link', uri: 'https://obsign.org/docs#install' },
  ]);
});

test('mentions yield dotted handles with the @ inside the span', () => {
  const text = 'thanks @malpercio.dev and @nobody for the help';
  const mention = only(detectMentions(text), 'mention');
  assert.equal(mention.handle, 'malpercio.dev');
  assert.equal(selected(text, mention.index), '@malpercio.dev');
});

test('a sentence-final mention drops the sentence period', () => {
  const text = 'ask @malpercio.dev.';
  const mention = only(detectMentions(text), 'mention');
  assert.equal(mention.handle, 'malpercio.dev');
  assert.equal(selected(text, mention.index), '@malpercio.dev');
});

test('an email address is not a mention', () => {
  assert.deepEqual(detectMentions('write to mal@obsign.org'), []);
});
