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
import { xrpc, HttpError } from './http.ts';
import { AgentSession, RevokedError, SessionExpiredError } from './auth.ts';
import { ALLOW_DESTRUCTIVE, imageDir } from './config.ts';

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
function relayError(err: unknown, session: AgentSession): ToolResult {
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
 * Confine image reads to the operator-configured directory. Without this, a
 * tool call influenced by untrusted content could publish any file the
 * process can read. Realpaths on both sides so symlinks cannot escape.
 */
function resolveImagePath(userPath: string): string {
  const configured = imageDir();
  if (!configured) {
    throw new Error(
      'image attachments are disabled: set CUSTOS_MCP_IMAGE_DIR to the one directory ' +
        'images may be read from',
    );
  }
  const base = fs.realpathSync(path.resolve(configured));
  let resolved: string;
  try {
    resolved = fs.realpathSync(path.resolve(base, userPath));
  } catch {
    throw new Error(`image_path does not exist under ${base}`);
  }
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error(`image_path must be inside ${base}`);
  }
  return resolved;
}

/** MIME type for uploaded post images, by file extension. */
function imageMime(filePath: string): string {
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
    throw new Error(`unsupported image type "${ext}" — use png, jpg, gif, or webp`);
  }
  return type;
}

async function requireDid(session: AgentSession): Promise<{ token: string; did: string }> {
  const token = await session.accessToken();
  const did = session.did();
  if (!did) throw new Error('the agent session has no DID — onboarding did not complete');
  return { token, did };
}

const replyRef = z.object({ uri: z.string(), cid: z.string() });

export function registerTools(server: McpServer, session: AgentSession): void {
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
    async () => {
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
        `references, optional attached image (uploaded as a blob). ${ATTRIBUTION}`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
      inputSchema: {
        text: z.string().max(3000).describe('Post text'),
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
      },
    },
    async (args) => {
      try {
        const { token, did } = await requireDid(session);

        let embed: Record<string, unknown> | undefined;
        if (args.image_path) {
          const imagePath = resolveImagePath(args.image_path);
          const mimeType = imageMime(imagePath);
          const bytes = fs.readFileSync(imagePath);
          const uploaded = await xrpc(session.pdsUrl, 'com.atproto.repo.uploadBlob', {
            method: 'POST',
            token,
            headers: { 'Content-Type': mimeType },
            body: new Uint8Array(bytes),
          });
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
    async (args) => {
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
    async (args) => {
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
    async (args) => {
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
    async () => {
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
    async (args) => {
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
    async (args) => {
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
