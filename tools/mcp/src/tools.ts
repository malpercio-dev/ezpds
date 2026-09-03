// The MCP tool surface: a deliberately small set matching the default agent
// scope profile (repo create/update + blob upload + AppView reads). Every tool
// runs as the agent registration the user confirmed — writes are attributed to
// it and visible in the user's audit log.
//
// put_record and delete_record are registered only when the operator sets
// CUSTOS_MCP_ALLOW_DESTRUCTIVE; with it unset they do not appear in the tool
// list at all.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { xrpc, HttpError } from './http.ts';
import { RevokedError, SessionExpiredError, type SessionState } from './auth.ts';
import { ALLOW_DESTRUCTIVE, imageDir } from './config.ts';
import { detectFacets, detectMentions, sortFacets, type Facet } from './facets.ts';

/**
 * The slice of a session the tool surface actually consumes. `AgentSession`
 * (the stdio server's onboarding-and-cache unit) satisfies it structurally, and
 * so does the sidecar's per-request forwarding session — that is what lets both
 * entry points single-source these tool implementations.
 */
export interface SessionLike {
  readonly pdsUrl: string;
  accessToken(): Promise<string>;
  did(): string | null;
  scopes(): string[];
  status(): SessionState;
}

/**
 * Resolves the session a tool call runs as. The stdio server binds one
 * singleton (`() => session`); the sidecar resolves a per-caller forwarding
 * session from the request's authenticated identity (`extra.authInfo`). A tool
 * handler is invoked with the MCP `extra` object, which carries `authInfo` when
 * the transport authenticated the caller.
 */
export type SessionResolver = (extra?: { authInfo?: AuthInfo }) => SessionLike;

const ATTRIBUTION =
  'Runs as this MCP server’s agent registration: the action is attributed to the agent ' +
  'and visible in the account owner’s audit log.';

type ToolResult = {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
};

function ok(data: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

function fail(message: string): ToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/**
 * Translate transport/PDS failures into messages an MCP client can act on —
 * never a stack trace. Scope refusals name the missing permission and the
 * scopes the agent actually holds.
 */
function relayError(err: unknown, session: SessionLike): ToolResult {
  if (err instanceof RevokedError || err instanceof SessionExpiredError) {
    return fail(err.message);
  }
  if (err instanceof HttpError) {
    if (err.status === 403 && err.errorCode === 'InsufficientScope') {
      const scopes = session.scopes();
      return fail(
        `The PDS refused this action as outside the agent's granted scopes ` +
          `(403 InsufficientScope): ${err.errorDescription ?? 'no details'}. ` +
          `Granted scopes: ${scopes.length ? scopes.join(' ') : '(none recorded)'}. ` +
          `Widening what this agent may do requires the PDS operator to change ` +
          `[agent_auth] granted_scopes and the owner to re-confirm a claim ceremony.`,
      );
    }
    return fail(
      `The PDS rejected the request (HTTP ${err.status}` +
        `${err.errorCode ? `, ${err.errorCode}` : ''}): ` +
        `${err.errorDescription ?? 'no details provided'}`,
    );
  }
  return fail(err instanceof Error ? err.message : String(err));
}

/**
 * Confine file reads to the operator-configured directory. Without this, a
 * tool call influenced by untrusted content could publish any file the
 * process can read. Realpaths on both sides so symlinks cannot escape.
 */
function resolveUploadPath(userPath: string): string {
  const configured = imageDir();
  if (!configured) {
    throw new Error(
      'blob uploads are disabled: set CUSTOS_MCP_IMAGE_DIR to the one directory ' +
        'files may be read from',
    );
  }
  const base = fs.realpathSync(path.resolve(configured));
  let resolved: string;
  try {
    resolved = fs.realpathSync(path.resolve(base, userPath));
  } catch {
    throw new Error(`path does not exist under ${base}`);
  }
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error(`path must be inside ${base}`);
  }
  return resolved;
}

/** MIME type by file extension, for an upload that does not declare one. */
function mimeFromExtension(filePath: string): string {
  const mime: Record<string, string> = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
  };
  const ext = path.extname(filePath).toLowerCase();
  const type = mime[ext];
  if (!type) {
    throw new Error(
      `cannot infer a MIME type for "${ext}" — use a png, jpg, gif, or webp file, or ` +
        `upload it with upload_blob's mime_type argument`,
    );
  }
  return type;
}

/**
 * Upload one confined file as a blob. The single upload path: create_post's
 * image attachment and the standalone upload_blob tool both run through it, so
 * the confinement check and MIME handling cannot drift apart.
 */
async function uploadBlob(
  session: SessionLike,
  token: string,
  userPath: string,
  mimeType?: string,
): Promise<any> {
  const filePath = resolveUploadPath(userPath);
  const bytes = fs.readFileSync(filePath);
  return xrpc(session.pdsUrl, 'com.atproto.repo.uploadBlob', {
    method: 'POST',
    token,
    headers: { 'Content-Type': mimeType ?? mimeFromExtension(filePath) },
    body: new Uint8Array(bytes),
  });
}

/**
 * Resolve a record field that takes a blob from whichever form the caller used:
 * a file under CUSTOS_MCP_IMAGE_DIR (uploaded here) or a ref already returned
 * by upload_blob. Returns undefined when the caller named neither, which the
 * callers read as "leave this field alone".
 *
 * The both-at-once check lives here rather than at each call site so a second
 * blob-bearing field cannot be added without it.
 */
async function resolveBlobField(
  session: SessionLike,
  token: string,
  field: string,
  filePath: string | undefined,
  blobRef: unknown,
): Promise<unknown> {
  if (filePath !== undefined && blobRef !== undefined) {
    throw new Error(`pass either ${field}_path or ${field}_blob, not both`);
  }
  if (filePath !== undefined) return (await uploadBlob(session, token, filePath)).blob;
  return blobRef;
}

async function requireDid(session: SessionLike): Promise<{ token: string; did: string }> {
  const token = await session.accessToken();
  const did = session.did();
  if (!did) throw new Error('the agent session has no DID — onboarding did not complete');
  return { token, did };
}

const replyRef = z.object({ uri: z.string(), cid: z.string() });

/**
 * Extended grapheme clusters, the unit atproto counts text in — one family
 * emoji is one grapheme however many bytes and code points it takes.
 */
const GRAPHEMES = new Intl.Segmenter(undefined, { granularity: 'grapheme' });

export function graphemeCount(text: string): number {
  return [...GRAPHEMES.segment(text)].length;
}

/**
 * Text bounded the way an atproto lexicon bounds it: a `maxLength` in UTF-8
 * bytes and a `maxGraphemes` in extended grapheme clusters. JavaScript's
 * `String.length` counts UTF-16 code units, which is neither — so a bare
 * `.max()` accepts text the PDS then refuses with a raw InvalidRequest, after
 * the tool already reported the arguments as valid. The `.max()` survives as
 * the advertised JSON-Schema ceiling (a byte limit always bounds characters
 * too); the refinements below are the limits actually enforced.
 */
export function lexiconText(maxBytes: number, maxGraphemes: number) {
  return z
    .string()
    .max(maxBytes)
    .refine(
      (text) => Buffer.byteLength(text, 'utf8') <= maxBytes,
      (text) => ({
        message: `too long: ${Buffer.byteLength(text, 'utf8')} UTF-8 bytes, limit is ${maxBytes}`,
      }),
    )
    .refine(
      (text) => graphemeCount(text) <= maxGraphemes,
      (text) => ({
        message: `too long: ${graphemeCount(text)} graphemes, limit is ${maxGraphemes}`,
      }),
    );
}


/**
 * The single self-keyed record holding an account's Bluesky profile. Other
 * atproto apps keep their own profile records under their own lexicons, which
 * is why the tool is named for Bluesky rather than for profiles in general.
 */
const BSKY_PROFILE_COLLECTION = 'app.bsky.actor.profile';
const BSKY_PROFILE_RKEY = 'self';

/**
 * Distinct handles resolved for one post. Mentions are the only facet kind
 * needing the network, and post text is caller-supplied: without a ceiling a
 * 3000-character post of @handles becomes hundreds of paced round trips.
 */
const MAX_MENTION_LOOKUPS = 25;

/**
 * Rich-text facets for post text: links and hashtags detected locally, plus a
 * mention facet for every @handle the PDS resolves to a DID.
 *
 * A handle that will not resolve stays plain text rather than failing the
 * post — the mention is cosmetic, the post is not.
 */
async function richTextFacets(session: SessionLike, text: string): Promise<Facet[]> {
  const facets = detectFacets(text);
  const mentions = detectMentions(text);

  const dids = new Map<string, string>();
  const handles = [...new Set(mentions.map((mention) => mention.handle))];
  for (const handle of handles.slice(0, MAX_MENTION_LOOKUPS)) {
    try {
      const resolved = await xrpc(session.pdsUrl, 'com.atproto.identity.resolveHandle', {
        params: { handle },
      });
      if (typeof resolved.did === 'string') dids.set(handle, resolved.did);
    } catch {
      // Unresolvable handle: leave the text as written.
    }
  }

  for (const mention of mentions) {
    const did = dids.get(mention.handle);
    if (did) {
      facets.push({
        index: mention.index,
        features: [{ $type: 'app.bsky.richtext.facet#mention', did }],
      });
    }
  }
  return sortFacets(facets);
}

export function registerTools(server: McpServer, resolveSession: SessionResolver): void {
  server.registerTool(
    'whoami',
    {
      description:
        'Report this MCP server’s onboarding status and identity on the PDS: state ' +
        '(onboarding / ready / revoked / expired), DID, handle, granted scopes, and — while ' +
        'a claim ceremony is pending — the user_code and verification URI the account owner ' +
        'must confirm. Use this first if any other tool reports an auth problem.',
      annotations: { readOnlyHint: true },
    },
    async (extra) => {
      const session = resolveSession(extra);
      const status = session.status();
      const report: Record<string, unknown> = { pds_url: session.pdsUrl, ...status };
      if (status.state === 'onboarding') {
        report.action_needed =
          `Ask the account owner to confirm claim code ${status.userCode} at ` +
          `${status.verificationUri} (or in the Obsign wallet).`;
      }
      if (status.state === 'ready') {
        try {
          const describe = await xrpc(session.pdsUrl, 'com.atproto.repo.describeRepo', {
            params: { repo: status.did },
          });
          report.handle = describe.handle;
        } catch {
          // handle is cosmetic; the status report is still useful without it
        }
      }
      return ok(report);
    },
  );

  server.registerTool(
    'create_post',
    {
      description:
        `Publish an app.bsky.feed.post to the user’s repository — text, optional reply ` +
        `references, optional attached image (uploaded as a blob). URLs, #hashtags, and ` +
        `@mentions in the text are turned into rich-text facets automatically, so they ` +
        `render as links rather than plain text. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
      inputSchema: {
        text: lexiconText(3000, 300).describe(
          'Post text: at most 300 graphemes (and 3000 UTF-8 bytes) — the app.bsky.feed.post ' +
            'limit. Longer text is rejected here rather than by the PDS',
        ),
        reply: z
          .object({ root: replyRef, parent: replyRef })
          .optional()
          .describe('Reply references (uri+cid of the thread root and the parent post)'),
        image_path: z
          .string()
          .optional()
          .describe(
            'Image file to attach (png/jpg/gif/webp), as a path inside the directory ' +
              'configured by CUSTOS_MCP_IMAGE_DIR (attachments are disabled without it)',
          ),
        image_alt: z.string().optional().describe('Alt text for the attached image'),
        langs: z.array(z.string()).optional().describe('BCP-47 language tags'),
        facets: z
          .array(z.record(z.string(), z.unknown()))
          .optional()
          .describe(
            'Explicit app.bsky.richtext.facet entries, replacing automatic detection. ' +
              'Only needed when the link text differs from the URL, or to suppress ' +
              'detection entirely (pass an empty array). Offsets are UTF-8 byte offsets.',
          ),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);

        let embed: Record<string, unknown> | undefined;
        if (args.image_path) {
          const uploaded = await uploadBlob(session, token, args.image_path);
          embed = {
            $type: 'app.bsky.embed.images',
            images: [{ image: uploaded.blob, alt: args.image_alt ?? '' }],
          };
        }

        const record: Record<string, unknown> = {
          $type: 'app.bsky.feed.post',
          text: args.text,
          createdAt: new Date().toISOString(),
        };
        const facets = args.facets ?? (await richTextFacets(session, args.text));
        if (facets.length) record.facets = facets;
        if (args.reply) record.reply = args.reply;
        if (args.langs) record.langs = args.langs;
        if (embed) record.embed = embed;

        const created = await xrpc(session.pdsUrl, 'com.atproto.repo.createRecord', {
          method: 'POST',
          token,
          body: { repo: did, collection: 'app.bsky.feed.post', record },
        });
        return ok(created);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'upload_blob',
    {
      description:
        `Upload a file to the user’s repository as a blob and return its blob ref, for use ` +
        `as an avatar, banner, or any other record field that takes a blob (create_post ` +
        `attaches post images on its own — it does not need this). The file is read from ` +
        `the directory configured by CUSTOS_MCP_IMAGE_DIR; uploads are disabled without it. ` +
        `A blob no record references is temporary and eventually garbage-collected, so write ` +
        `the record that carries the returned ref rather than uploading speculatively. ` +
        `${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
      inputSchema: {
        path: z
          .string()
          .describe('File to upload, as a path inside the CUSTOS_MCP_IMAGE_DIR directory'),
        mime_type: z
          .string()
          .optional()
          .describe(
            'Content type to upload as. Inferred from the extension for png/jpg/gif/webp; ' +
              'required for anything else',
          ),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const token = await session.accessToken();
        const uploaded = await uploadBlob(session, token, args.path, args.mime_type);
        return ok(uploaded);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'update_bluesky_profile',
    {
      description:
        `Update the account’s Bluesky profile record (app.bsky.actor.profile) — display name, ` +
        `description, avatar, and banner. This is the Bluesky app’s profile lexicon; other ` +
        `atproto apps keep their profiles under their own. Read-modify-write: fields you leave ` +
        `out keep their current value, so this cannot clobber the parts of the profile you did ` +
        `not name. Pass an empty string to clear display_name or description. Set an image ` +
        `either by path (uploaded for you) or by a ref from upload_blob. The write is guarded ` +
        `against the CID just read, so a profile edited elsewhere mid-call fails loudly ` +
        `(409 InvalidSwap) rather than silently overwriting — re-read and retry. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
      inputSchema: {
        display_name: lexiconText(640, 64)
          .optional()
          .describe('New display name, at most 64 graphemes; empty string clears it'),
        description: lexiconText(2560, 256)
          .optional()
          .describe('New profile description (bio), at most 256 graphemes; empty string clears it'),
        avatar_path: z
          .string()
          .optional()
          .describe(
            'Avatar image to upload, as a path inside the CUSTOS_MCP_IMAGE_DIR directory. ' +
              'Use avatar_blob instead if you already uploaded it',
          ),
        avatar_blob: z
          .record(z.string(), z.unknown())
          .optional()
          .describe('Avatar as a blob ref from upload_blob, instead of avatar_path'),
        banner_path: z
          .string()
          .optional()
          .describe('Banner image to upload, same directory rule as avatar_path'),
        banner_blob: z
          .record(z.string(), z.unknown())
          .optional()
          .describe('Banner as a blob ref from upload_blob, instead of banner_path'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const named = [
          args.display_name,
          args.description,
          args.avatar_path,
          args.avatar_blob,
          args.banner_path,
          args.banner_blob,
        ].some((value) => value !== undefined);
        if (!named) {
          return fail(
            'nothing to update — pass at least one of display_name, description, ' +
              'avatar_path/avatar_blob, banner_path/banner_blob',
          );
        }

        // Read first so unnamed fields survive, and so the write can be pinned
        // to what was read. An account with no profile yet is the normal
        // first-run case, not an error: swapRecord stays null, which the PDS
        // reads as "the record must still be absent" and closes the race where
        // a profile appears between this read and the write below.
        let existing: Record<string, unknown> = {};
        let swapRecord: string | null = null;
        try {
          const current = await xrpc(session.pdsUrl, 'com.atproto.repo.getRecord', {
            params: { repo: did, collection: BSKY_PROFILE_COLLECTION, rkey: BSKY_PROFILE_RKEY },
          });
          if (current.value && typeof current.value === 'object') {
            existing = current.value as Record<string, unknown>;
          }
          if (typeof current.cid === 'string') swapRecord = current.cid;
        } catch (err) {
          const absent =
            err instanceof HttpError &&
            (err.errorCode === 'NotFound' || err.errorCode === 'RecordNotFound');
          if (!absent) throw err;
        }

        const record: Record<string, unknown> = { ...existing, $type: BSKY_PROFILE_COLLECTION };
        if (args.display_name !== undefined) {
          if (args.display_name === '') delete record.displayName;
          else record.displayName = args.display_name;
        }
        if (args.description !== undefined) {
          if (args.description === '') delete record.description;
          else record.description = args.description;
        }
        const avatar = await resolveBlobField(
          session,
          token,
          'avatar',
          args.avatar_path,
          args.avatar_blob,
        );
        if (avatar !== undefined) record.avatar = avatar;
        const banner = await resolveBlobField(
          session,
          token,
          'banner',
          args.banner_path,
          args.banner_blob,
        );
        if (banner !== undefined) record.banner = banner;
        if (!record.createdAt) record.createdAt = new Date().toISOString();

        const result = await xrpc(session.pdsUrl, 'com.atproto.repo.putRecord', {
          method: 'POST',
          token,
          body: {
            repo: did,
            collection: BSKY_PROFILE_COLLECTION,
            rkey: BSKY_PROFILE_RKEY,
            record,
            swapRecord,
          },
        });
        return ok({ ...result, profile: record });
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'get_record',
    {
      description:
        'Read a single record from the user’s repository (or another repo by DID/handle) ' +
        'by collection and record key.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        collection: z.string().describe('Collection NSID, e.g. app.bsky.feed.post'),
        rkey: z.string().describe('Record key'),
        repo: z
          .string()
          .optional()
          .describe('DID or handle of the repo to read (defaults to the onboarded account)'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const repo = args.repo ?? session.did();
        if (!repo) throw new Error('no repo given and the agent session has no DID yet');
        const record = await xrpc(session.pdsUrl, 'com.atproto.repo.getRecord', {
          params: { repo, collection: args.collection, rkey: args.rkey },
        });
        return ok(record);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'list_records',
    {
      description:
        'List records in a collection of the user’s repository (or another repo by ' +
        'DID/handle), paginated by cursor.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        collection: z.string().describe('Collection NSID, e.g. app.bsky.feed.post'),
        limit: z.number().int().min(1).max(100).optional().describe('Page size (default 50)'),
        cursor: z.string().optional().describe('Cursor from a previous page'),
        repo: z
          .string()
          .optional()
          .describe('DID or handle of the repo to read (defaults to the onboarded account)'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const repo = args.repo ?? session.did();
        if (!repo) throw new Error('no repo given and the agent session has no DID yet');
        const records = await xrpc(session.pdsUrl, 'com.atproto.repo.listRecords', {
          params: {
            repo,
            collection: args.collection,
            limit: args.limit,
            cursor: args.cursor,
          },
        });
        return ok(records);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'search_timeline',
    {
      description:
        'Read the user’s timeline, or search posts when a query is given. Reads are ' +
        'proxied through the PDS to its configured AppView and attributed to the agent.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        query: z
          .string()
          .optional()
          .describe('Search query (app.bsky.feed.searchPosts); omit to read the timeline'),
        limit: z.number().int().min(1).max(100).optional().describe('Number of results'),
        cursor: z.string().optional().describe('Cursor from a previous page'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const token = await session.accessToken();
        const result = args.query
          ? await xrpc(session.pdsUrl, 'app.bsky.feed.searchPosts', {
              token,
              params: { q: args.query, limit: args.limit, cursor: args.cursor },
            })
          : await xrpc(session.pdsUrl, 'app.bsky.feed.getTimeline', {
              token,
              params: { limit: args.limit, cursor: args.cursor },
            });
        return ok(result);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'account_status',
    {
      description:
        'Report the onboarded account’s hosting status on the PDS: activation, repo ' +
        'head/rev, and record/blob counts (com.atproto.server.checkAccountStatus).',
      annotations: { readOnlyHint: true },
    },
    async (extra) => {
      const session = resolveSession(extra);
      try {
        const token = await session.accessToken();
        const status = await xrpc(session.pdsUrl, 'com.atproto.server.checkAccountStatus', {
          token,
        });
        return ok(status);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  // ── Atproto Spaces ─────────────────────────────────────────────────────────
  // Permissioned space repos. Every space tool needs a `space:` grant in the
  // agent's scopes (not part of the default profile), so out of the box each
  // reports a clean InsufficientScope refusal naming what the operator must
  // grant. `space` arguments are canonical space refs:
  // at://{authority-did}/space/{type}/{skey}

  server.registerTool(
    'list_spaces',
    {
      description:
        'List the permissioned spaces the user’s repository has written to (a repo host tracks ' +
        'writers, not memberships), optionally filtered by space type or authority DID. ' +
        'Requires a space: grant in the agent’s scopes.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        type: z.string().optional().describe('Filter to spaces of this type NSID'),
        did: z.string().optional().describe('Filter to spaces under this authority DID'),
        limit: z.number().int().min(1).max(100).optional().describe('Page size (default 50)'),
        cursor: z.string().optional().describe('Cursor from a previous page'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const token = await session.accessToken();
        const spaces = await xrpc(session.pdsUrl, 'com.atproto.space.listSpaces', {
          token,
          params: { type: args.type, did: args.did, limit: args.limit, cursor: args.cursor },
        });
        return ok(spaces);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'space_get_record',
    {
      description:
        'Read a single record from the user’s repo in a permissioned space, by space ref, ' +
        'collection, and record key. Requires a space: grant in the agent’s scopes.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        space: z.string().describe('Canonical space ref, e.g. at://did:plc:…/space/org.example.bucket/main'),
        collection: z.string().describe('Collection NSID'),
        rkey: z.string().describe('Record key'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const record = await xrpc(session.pdsUrl, 'com.atproto.space.getRecord', {
          token,
          params: { space: args.space, repo: did, collection: args.collection, rkey: args.rkey },
        });
        return ok(record);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'space_list_records',
    {
      description:
        'List records in the user’s repo in a permissioned space, values inlined, paginated by ' +
        'cursor. Requires a space: grant in the agent’s scopes.',
      annotations: { readOnlyHint: true },
      inputSchema: {
        space: z.string().describe('Canonical space ref'),
        collection: z.string().optional().describe('Filter to one collection NSID'),
        limit: z.number().int().min(1).max(1000).optional().describe('Page size (default 50)'),
        cursor: z.string().optional().describe('Cursor from a previous page'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const records = await xrpc(session.pdsUrl, 'com.atproto.space.listRecords', {
          token,
          params: {
            space: args.space,
            repo: did,
            collection: args.collection,
            limit: args.limit,
            cursor: args.cursor,
          },
        });
        return ok(records);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'space_create_record',
    {
      description:
        `Create a record in the user’s repo in a permissioned space. Requires a space: grant ` +
        `covering create on the collection. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
      inputSchema: {
        space: z.string().describe('Canonical space ref'),
        collection: z.string().describe('Collection NSID'),
        record: z.record(z.string(), z.unknown()).describe('The full record value (JSON object)'),
        rkey: z.string().optional().describe('Record key (a TID is generated when absent)'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const created = await xrpc(session.pdsUrl, 'com.atproto.space.createRecord', {
          method: 'POST',
          token,
          body: {
            space: args.space,
            repo: did,
            collection: args.collection,
            record: args.record,
            ...(args.rkey ? { rkey: args.rkey } : {}),
          },
        });
        return ok(created);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  if (!ALLOW_DESTRUCTIVE) return;

  server.registerTool(
    'put_record',
    {
      description:
        `Create or overwrite a record at a specific collection + rkey in the user’s ` +
        `repository. Destructive (enabled by CUSTOS_MCP_ALLOW_DESTRUCTIVE). ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      inputSchema: {
        collection: z.string().describe('Collection NSID'),
        rkey: z.string().describe('Record key to write'),
        record: z.record(z.string(), z.unknown()).describe('The full record value (JSON object)'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const result = await xrpc(session.pdsUrl, 'com.atproto.repo.putRecord', {
          method: 'POST',
          token,
          body: { repo: did, collection: args.collection, rkey: args.rkey, record: args.record },
        });
        return ok(result);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'space_put_record',
    {
      description:
        `Create or overwrite a record at a specific collection + rkey in the user’s repo in a ` +
        `permissioned space. Destructive (enabled by CUSTOS_MCP_ALLOW_DESTRUCTIVE); requires a ` +
        `space: grant covering the write. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      inputSchema: {
        space: z.string().describe('Canonical space ref'),
        collection: z.string().describe('Collection NSID'),
        rkey: z.string().describe('Record key to write'),
        record: z.record(z.string(), z.unknown()).describe('The full record value (JSON object)'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const result = await xrpc(session.pdsUrl, 'com.atproto.space.putRecord', {
          method: 'POST',
          token,
          body: {
            space: args.space,
            repo: did,
            collection: args.collection,
            rkey: args.rkey,
            record: args.record,
          },
        });
        return ok(result);
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'space_delete_record',
    {
      description:
        `Delete a record from the user’s repo in a permissioned space. Destructive (enabled by ` +
        `CUSTOS_MCP_ALLOW_DESTRUCTIVE); requires a space: grant covering delete. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      inputSchema: {
        space: z.string().describe('Canonical space ref'),
        collection: z.string().describe('Collection NSID'),
        rkey: z.string().describe('Record key to delete'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const result = await xrpc(session.pdsUrl, 'com.atproto.space.deleteRecord', {
          method: 'POST',
          token,
          body: { space: args.space, repo: did, collection: args.collection, rkey: args.rkey },
        });
        return ok(result ?? { deleted: true });
      } catch (err) {
        return relayError(err, session);
      }
    },
  );

  server.registerTool(
    'delete_record',
    {
      description:
        `Delete a record from the user’s repository. Destructive (enabled by ` +
        `CUSTOS_MCP_ALLOW_DESTRUCTIVE); note the default agent scope profile does not include ` +
        `delete, so the PDS may refuse with 403 unless the operator granted it. ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      inputSchema: {
        collection: z.string().describe('Collection NSID'),
        rkey: z.string().describe('Record key to delete'),
      },
    },
    async (args, extra) => {
      const session = resolveSession(extra);
      try {
        const { token, did } = await requireDid(session);
        const result = await xrpc(session.pdsUrl, 'com.atproto.repo.deleteRecord', {
          method: 'POST',
          token,
          body: { repo: did, collection: args.collection, rkey: args.rkey },
        });
        return ok(result ?? { deleted: true });
      } catch (err) {
        return relayError(err, session);
      }
    },
  );
}
