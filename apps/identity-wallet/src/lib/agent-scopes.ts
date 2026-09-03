/**
 * Plain-language descriptions of the granular OAuth scope tokens an agent is granted.
 *
 * The approval and My-agents screens show a human sentence for every scope, with the raw token
 * underneath (honesty through progressive disclosure — the plain words are for deciding, the
 * token is the ground truth). An unknown token falls back to showing itself, never to a vague
 * "other permission": consent must not paper over grants the wallet cannot explain.
 */

export type ScopeDescription = {
  /** Plain-language sentence, e.g. "Create and edit records in your repository". */
  summary: string;
  /** The raw scope token, always shown alongside the summary. */
  token: string;
  /** True for grants that reach account/identity lifecycle control — worth a visual warning. */
  elevated: boolean;
};

/** Friendly names for well-known record collections. */
const COLLECTION_NAMES: Record<string, string> = {
  'app.bsky.feed.post': 'posts',
  'app.bsky.feed.like': 'likes',
  'app.bsky.feed.repost': 'reposts',
  'app.bsky.graph.follow': 'follows',
  'app.bsky.graph.block': 'blocks',
  'app.bsky.actor.profile': 'your profile',
};

const ACTION_VERBS: Record<string, string> = {
  create: 'create',
  update: 'edit',
  delete: 'delete',
};

function joinWords(words: string[]): string {
  if (words.length <= 1) return words[0] ?? '';
  if (words.length === 2) return `${words[0]} and ${words[1]}`;
  return `${words.slice(0, -1).join(', ')}, and ${words[words.length - 1]}`;
}

function describeRepo(rest: string): string {
  const [target, query] = rest.split('?', 2);
  const actions = new URLSearchParams(query ?? '').getAll('action');
  const verbs = actions.length
    ? joinWords(actions.map((a) => ACTION_VERBS[a] ?? a))
    : 'create, edit, and delete';
  const what =
    target === '*' ? 'any record in your repository' : (COLLECTION_NAMES[target] ?? `${target} records`);
  return `${capitalize(verbs)} ${what}`;
}

/** `read_self` folds into `read`: the distinction is protocol plumbing, not a user decision. */
const SPACE_ACTION_VERBS: Record<string, string> = {
  read: 'read',
  read_self: 'read',
  create: 'create',
  update: 'edit',
  delete: 'delete',
};

/**
 * Describe a `space:` grant (Atproto Spaces — permissioned, non-public data). Mirrors the
 * server grammar's defaults: no `action` means read/create/edit/delete, no `authority` means
 * the user's own spaces, `manage` verbs act on the spaces themselves and are called out
 * separately.
 */
function describeSpace(rest: string): string {
  const [target, query] = rest.split('?', 2);
  const params = new URLSearchParams(query ?? '');
  const actions = params.getAll('action');
  const manage = params.getAll('manage');
  const authority = params.get('authority') ?? 'self';
  const verbs = actions.length
    ? joinWords([...new Set(actions.map((a) => SPACE_ACTION_VERBS[a] ?? a))])
    : 'read, create, edit, and delete';
  const kind = target === '*' ? 'private spaces' : `${target} private spaces`;
  const whose =
    authority === 'self'
      ? `your ${kind}`
      : authority === '*'
        ? `${kind} run by anyone`
        : `${kind} run by ${authority}`;
  let summary = `${capitalize(verbs)} records in ${whose}`;
  if (manage.length) {
    summary += ` — and ${joinWords(manage.map((m) => ACTION_VERBS[m] ?? m))} those spaces themselves`;
  }
  return summary;
}

/** Friendly names for the well-known service audiences an `rpc:` grant names. */
const SERVICE_NAMES: Record<string, string> = {
  'did:web:api.bsky.app': 'the Bluesky app service',
  'did:web:api.bsky.chat': 'the Bluesky chat service',
};

/**
 * Describe an `rpc:` grant — calling a method on another service, which the PDS answers by
 * minting service auth signed by this account's own repo key.
 *
 * The audience is the containment, so it is named rather than summarized away: a known service
 * by its plain name, anything else by its literal DID. `aud=*` is the one unbounded case and
 * says so.
 */
function describeRpc(rest: string): string {
  const [lxm, query] = rest.split('?', 2);
  const aud = new URLSearchParams(query ?? '').get('aud') ?? '*';
  // The server matches audiences on the bare DID, so a `#serviceId` fragment never changes what
  // the grant reaches — strip it before looking up a name.
  const did = aud.split('#')[0];
  const where = aud === '*' ? 'ANY service' : (SERVICE_NAMES[did] ?? did);
  // A wildcard method reads as the service itself; a named one leads with the method.
  return lxm === '*' ? `Call ${where} on your behalf` : `Call ${lxm} on ${where}`;
}

function describeBlob(rest: string): string {
  if (rest === '*/*' || rest === '*') return 'Upload files (any type)';
  if (rest === 'image/*') return 'Upload images';
  if (rest === 'video/*') return 'Upload videos';
  return `Upload ${rest} files`;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Describe one scope token in plain language. */
export function describeScope(token: string): ScopeDescription {
  if (token === 'atproto') {
    return { summary: 'Act as an ATProto client for your account', token, elevated: false };
  }
  if (token === 'com.atproto.access' || token === 'transition:generic') {
    return { summary: 'Full access to your account', token, elevated: true };
  }
  if (token.startsWith('repo:')) {
    return { summary: describeRepo(token.slice('repo:'.length)), token, elevated: false };
  }
  if (token.startsWith('blob:')) {
    return { summary: describeBlob(token.slice('blob:'.length)), token, elevated: false };
  }
  if (token.startsWith('space:')) {
    return { summary: describeSpace(token.slice('space:'.length)), token, elevated: false };
  }
  if (token.startsWith('rpc:')) {
    return { summary: describeRpc(token.slice('rpc:'.length)), token, elevated: false };
  }
  if (token.startsWith('account:')) {
    return { summary: 'Manage your account settings', token, elevated: true };
  }
  if (token.startsWith('identity:')) {
    return { summary: 'Change your handle or identity', token, elevated: true };
  }
  if (token.startsWith('include:')) {
    return { summary: 'A named permission set defined by the server', token, elevated: false };
  }
  // Unknown grammar: show the token itself as the summary — never hide what we can't explain.
  return { summary: token, token, elevated: false };
}

/** Describe a whole scope list, preserving order. */
export function describeScopes(tokens: string[]): ScopeDescription[] {
  return tokens.map(describeScope);
}
