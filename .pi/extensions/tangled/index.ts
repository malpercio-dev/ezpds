import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { execSync } from "node:child_process";

const CONSTELLATION_URL = "https://constellation.microcosm.blue";

export default function (pi: ExtensionAPI) {
  const handle = process.env.TANGLED_HANDLE;
  const appPassword = process.env.TANGLED_APP_PASSWORD;
  const pdsUrl = process.env.TANGLED_PDS_URL || "https://tangled.org";

  if (!handle || !appPassword) {
    pi.on("session_start", (_e, ctx) => {
      ctx.ui.notify("TANGLED_HANDLE / TANGLED_APP_PASSWORD not set", "warning");
    });
    return;
  }

  let accessToken: string | null = null;
  let userDid: string | null = null;
  let resolvedPdsUrl: string | null = null;

  async function getDid(): Promise<string> {
    await getToken();
    if (!userDid) throw new Error("No DID available");
    return userDid;
  }

  async function getPdsUrl(): Promise<string> {
    if (resolvedPdsUrl) return resolvedPdsUrl;
    if (pdsUrl !== "https://tangled.org") {
      resolvedPdsUrl = pdsUrl;
      return pdsUrl;
    }
    try {
      const didRes = await fetch(`https://${handle}/.well-known/did.json`);
      if (didRes.ok) {
        const didDoc = (await didRes.json()) as { service?: Array<{ id: string; serviceEndpoint: string }> };
        const pdsService = didDoc.service?.find((s) => s.id === "#atproto_pds" || s.type === "AtprotoPersonalDataServer");
        if (pdsService?.serviceEndpoint) {
          resolvedPdsUrl = pdsService.serviceEndpoint;
          return resolvedPdsUrl;
        }
      }
    } catch {}
    resolvedPdsUrl = pdsUrl;
    return pdsUrl;
  }

  async function getToken(): Promise<string> {
    if (accessToken) return accessToken;
    const pds = await getPdsUrl();
    const res = await fetch(`${pds}/xrpc/com.atproto.server.createSession`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier: handle, password: appPassword }),
    });
    if (!res.ok) throw new Error(`Auth failed: ${res.status}`);
    const data = (await res.json()) as { accessJwt: string; did: string };
    accessToken = data.accessJwt;
    userDid = data.did;
    return accessToken;
  }

  /** Fetch a record from any PDS by AT-URI */
  async function getRecord(atUri: string): Promise<Record<string, unknown>> {
    const token = await getToken();
    const pds = await getPdsUrl();
    // Parse at://did/collection/rkey
    const parts = atUri.replace("at://", "").split("/");
    const repo = parts[0];
    const collection = parts[1];
    const rkey = parts[2];
    const qs = new URLSearchParams({ repo, collection, rkey });
    const res = await fetch(`${pds}/xrpc/com.atproto.repo.getRecord?${qs}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`getRecord failed: ${res.status}`);
    const data = (await res.json()) as { value: Record<string, unknown> };
    return data.value;
  }

  pi.on("session_start", async (_e, ctx) => {
    try {
      await getToken();
      ctx.ui.notify("Tangled extension loaded", "info");
    } catch (err) {
      ctx.ui.notify(`Tangled auth failed: ${err}`, "error");
    }
  });

  // ── tangled_list_prs ──────────────────────────────────────────────────────

  pi.registerTool({
    name: "tangled_list_prs",
    label: "List Tangled PRs",
    description: "List pull requests targeting a Tangled repository. Uses Constellation to find PRs from all contributors, not just the authenticated user.",
    promptSnippet: "List pull requests for a Tangled repo",
    promptGuidelines: ["Use tangled_list_prs when the user asks about pull requests on a Tangled repo."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name (e.g. malpercio.dev/ezpds)" }),
      limit: Type.Optional(Type.Number({ description: "Max results (default 20)" })),
    }),
    async execute(_id, params) {
      const did = await getDid();
      const repoName = params.repo.split("/")[1];
      const repoAtUri = `at://${did}/sh.tangled.repo/${repoName}`;
      const limit = params.limit ?? 20;

      // Query Constellation for PRs targeting this repo
      const qs = new URLSearchParams({
        subject: repoAtUri,
        source: "sh.tangled.repo.pull:target.repo",
        limit: String(limit),
      });
      const res = await fetch(`${CONSTELLATION_URL}/xrpc/blue.microcosm.links.getBacklinks?${qs}`);
      if (!res.ok) throw new Error(`Constellation query failed: ${res.status}`);
      const data = (await res.json()) as {
        total: number;
        records: Array<{ did: string; collection: string; rkey: string }>;
      };

      if (data.total === 0) {
        return { content: [{ type: "text", text: `No pull requests found for ${params.repo}.` }], details: { count: 0 } };
      }

      // Fetch full PR records to get titles, states, etc.
      const prs: Array<{ rkey: string; title: string; createdAt: string; target: { branch: string }; author: string }> = [];
      for (const ref of data.records) {
        try {
          const atUri = `at://${ref.did}/${ref.collection}/${ref.rkey}`;
          const record = await getRecord(atUri);
          prs.push({
            rkey: ref.rkey,
            title: String(record.title ?? "Untitled"),
            createdAt: String(record.createdAt ?? ""),
            target: (record.target as { branch?: string }) ?? { branch: "" },
            author: ref.did,
          });
        } catch {
          // Skip PRs we can't fetch
        }
      }

      if (prs.length === 0) {
        return { content: [{ type: "text", text: `No pull requests found for ${params.repo}.` }], details: { count: 0 } };
      }

      const lines = prs.map((pr) => `#${pr.rkey} — ${pr.title} → ${pr.target.branch} — ${pr.createdAt}`);
      return { content: [{ type: "text", text: lines.join("\n") }], details: { count: prs.length, total: data.total } };
    },
  });

  // ── tangled_open_pr ───────────────────────────────────────────────────────

  pi.registerTool({
    name: "tangled_open_pr",
    label: "Open Tangled PR",
    description: "Create a new pull request on a Tangled repository. Generates the git patch automatically from the local repo.",
    promptSnippet: "Create a new pull request on Tangled",
    promptGuidelines: ["Use tangled_open_pr when the user asks to create or open a new pull request."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name (e.g. malpercio.dev/ezpds)" }),
      title: Type.String({ description: "PR title" }),
      description: Type.Optional(Type.String({ description: "PR description (Markdown)" })),
      source_branch: Type.String({ description: "Source branch name (must exist locally with commits)" }),
      target_branch: Type.Optional(Type.String({ description: "Target branch (default: main)" })),
      repo_path: Type.Optional(Type.String({ description: "Path to local git repo (default: current directory)" })),
    }),
    async execute(_id, params) {
      const token = await getToken();
      const pds = await getPdsUrl();
      const did = await getDid();
      const repoName = params.repo.split("/")[1];
      const repoAtUri = `at://${did}/sh.tangled.repo/${repoName}`;
      const targetBranch = params.target_branch ?? "main";
      const repoPath = params.repo_path || process.cwd();

      // Generate patch from local git repo
      let patch: string;
      try {
        patch = execSync(
          `git format-patch ${targetBranch}..${params.source_branch} --stdout`,
          { cwd: repoPath, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 },
        );
      } catch (err) {
        throw new Error(`git format-patch failed: ${err}`);
      }
      if (!patch.trim()) {
        throw new Error(`No commits between ${targetBranch} and ${params.source_branch}. Push commits to the source branch first.`);
      }

      const now = new Date().toISOString();

      const record = {
        $type: "sh.tangled.repo.pull",
        target: {
          repo: repoAtUri,
          branch: targetBranch,
        },
        title: params.title,
        body: params.description ?? "",
        patch,
        createdAt: now,
      };

      const res = await fetch(`${pds}/xrpc/com.atproto.repo.createRecord`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          repo: did,
          collection: "sh.tangled.repo.pull",
          validate: false,
          record,
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`createRecord failed: ${res.status} — ${body}`);
      }
      const result = (await res.json()) as { uri: string; cid: string };
      return {
        content: [{ type: "text", text: `PR created: ${params.title}\nURI: ${result.uri}\n\nNote: PR is stored on your PDS and indexed by Constellation. It may not appear in the Tangled web UI immediately (known issue: tangled.org/core#576).` }],
        details: { result },
      };
    },
  });

  // ── tangled_list_issues ───────────────────────────────────────────────────

  pi.registerTool({
    name: "tangled_list_issues",
    label: "List Tangled Issues",
    description: "List issues for a Tangled repository.",
    promptSnippet: "List issues for a Tangled repo",
    promptGuidelines: ["Use tangled_list_issues when the user asks about issues on a Tangled repo."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name (e.g. malpercio.dev/ezpds)" }),
      limit: Type.Optional(Type.Number({ description: "Max results (default 20)" })),
    }),
    async execute(_id, params) {
      const token = await getToken();
      const pds = await getPdsUrl();
      const did = await getDid();
      const limit = params.limit ?? 20;
      const qs = new URLSearchParams({ collection: "sh.tangled.repo.issue", repo: did, limit: String(limit) });
      const res = await fetch(`${pds}/xrpc/com.atproto.repo.listRecords?${qs}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`listRecords failed: ${res.status}`);
      const data = (await res.json()) as { records: Array<{ uri: string; value: Record<string, unknown> }> };

      const repoName = params.repo.split("/")[1];
      const repoAtUri = `at://${did}/sh.tangled.repo/${repoName}`;
      const issues = data.records.filter((r) => {
        const issueRepo = String(r.value.repo ?? "");
        return issueRepo === repoAtUri || issueRepo.endsWith("/" + repoName);
      });

      if (issues.length === 0) {
        return { content: [{ type: "text", text: `No issues found for ${params.repo}.` }], details: { count: 0 } };
      }

      const lines = issues.map((r) => {
        const rkey = r.uri.split("/").pop();
        return `#${rkey} — ${r.value.title ?? "Untitled"} [${r.value.state ?? "?"}] — ${r.value.createdAt ?? ""}`;
      });

      return { content: [{ type: "text", text: lines.join("\n") }], details: { count: issues.length } };
    },
  });

  // ── tangled_create_issue ──────────────────────────────────────────────────

  pi.registerTool({
    name: "tangled_create_issue",
    label: "Create Tangled Issue",
    description: "Create a new issue on a Tangled repository.",
    promptSnippet: "Create a new issue on a Tangled repo",
    promptGuidelines: ["Use tangled_create_issue when the user asks to create or file a new issue."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name (e.g. malpercio.dev/ezpds)" }),
      title: Type.String({ description: "Issue title" }),
      body: Type.Optional(Type.String({ description: "Issue body (Markdown)" })),
    }),
    async execute(_id, params) {
      const token = await getToken();
      const pds = await getPdsUrl();
      const did = await getDid();
      const repoName = params.repo.split("/")[1];
      const repoAtUri = `at://${did}/sh.tangled.repo/${repoName}`;
      const now = new Date().toISOString();

      const res = await fetch(`${pds}/xrpc/com.atproto.repo.createRecord`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          repo: did,
          collection: "sh.tangled.repo.issue",
          validate: false,
          record: {
            $type: "sh.tangled.repo.issue",
            repo: repoAtUri,
            title: params.title,
            body: params.body ?? "",
            createdAt: now,
          },
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`createRecord failed: ${res.status} — ${body}`);
      }
      const result = (await res.json()) as { uri: string; cid: string };
      return {
        content: [{ type: "text", text: `Issue created: ${params.title}\nURI: ${result.uri}` }],
        details: { result },
      };
    },
  });
}
