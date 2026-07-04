// Firehose (com.atproto.sync.subscribeRepos) client: subscribes over WebSocket,
// decodes the two concatenated DAG-CBOR items per binary frame (header, body),
// and provides a write-then-observe check that a repo commit reaches the stream.

import WebSocket from 'ws';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { decodeFirst } from 'cborg';
import { BASE_URL } from './config.js';
import { createPost, rkeyFromUri } from './records.js';
import { loadState, getAccount } from './state.js';

// Tag 42 = CID (multibase-prefixed bytes). We only need a printable token, not
// a full CID object, for observation purposes.
const decodeOptions = {
  tags: { 42: (bytes) => `cid(${Buffer.from(bytes).toString('base64url').slice(0, 16)}…)` },
  allowBigInt: true,
};

export function decodeFrame(data) {
  const bytes = new Uint8Array(data);
  const [header, rest] = decodeFirst(bytes, decodeOptions);
  const [body] = decodeFirst(rest, decodeOptions);
  return { header, body };
}

export function firehoseUrl(cursor) {
  const url = new URL(`${BASE_URL}/xrpc/com.atproto.sync.subscribeRepos`);
  url.protocol = url.protocol === 'http:' ? 'ws:' : 'wss:';
  if (cursor !== undefined && cursor !== null) url.searchParams.set('cursor', String(cursor));
  return url.toString();
}

export function connectFirehose({ cursor, onFrame, onError }) {
  const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
  const ws = new WebSocket(firehoseUrl(cursor), {
    agent: proxy ? new HttpsProxyAgent(proxy) : undefined,
    handshakeTimeout: 20_000,
  });
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return;
    try {
      onFrame(decodeFrame(data));
    } catch (err) {
      onError?.(err);
    }
  });
  ws.on('error', (err) => onError?.(err));
  return ws;
}

/** Stream frames to stdout for `seconds`. */
export function watchFirehose({ cursor, seconds = 30 }) {
  return new Promise((resolve, reject) => {
    let count = 0;
    const ws = connectFirehose({
      cursor,
      onFrame: ({ header, body }) => {
        count++;
        const summary = {
          t: header.t,
          seq: body.seq,
          repo: body.repo ?? body.did,
          ops: body.ops?.map((op) => `${op.action}:${op.path}`),
          rev: body.rev,
          status: body.status,
          active: body.active,
        };
        console.log(JSON.stringify(summary));
      },
      onError: (err) => console.error(`frame/socket error: ${err.message}`),
    });
    ws.on('open', () => console.error(`connected to ${firehoseUrl(cursor)} for ${seconds}s…`));
    ws.on('close', () => resolve(count));
    ws.on('unexpected-response', (_req, res) => reject(new Error(`handshake rejected: HTTP ${res.statusCode}`)));
    setTimeout(() => ws.close(), seconds * 1000);
  });
}

/**
 * End-to-end firehose check: subscribe live, write a post, and require the
 * matching #commit frame (right repo, right path) within the timeout. The
 * temporary post is deleted afterwards by the caller via the returned rkey.
 */
export async function firehoseWriteCheck(name, { timeoutSeconds = 30 } = {}) {
  const account = getAccount(loadState(), name);

  return new Promise((resolve, reject) => {
    let done = false;
    let created = null;
    const finish = (err, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      ws.close();
      err ? reject(err) : resolve(result);
    };

    const timer = setTimeout(
      () => finish(new Error(`no matching #commit frame within ${timeoutSeconds}s${created ? ` (wrote ${created.uri})` : ''}`)),
      timeoutSeconds * 1000,
    );

    const ws = connectFirehose({
      onFrame: ({ header, body }) => {
        if (header.t !== '#commit' || body.repo !== account.did || !created) return;
        const path = `app.bsky.feed.post/${rkeyFromUri(created.uri)}`;
        const match = (body.ops ?? []).find((op) => op.path === path && op.action === 'create');
        if (match) finish(null, { seq: body.seq, rev: body.rev, uri: created.uri, rkey: rkeyFromUri(created.uri) });
      },
      onError: () => {},
    });
    ws.on('unexpected-response', (_req, res) => finish(new Error(`firehose handshake rejected: HTTP ${res.statusCode}`)));
    ws.on('error', (err) => finish(err));
    ws.on('open', async () => {
      try {
        created = await createPost(name, `ezpds interop firehose check ${new Date().toISOString()}`);
      } catch (err) {
        finish(err);
      }
    });
  });
}
