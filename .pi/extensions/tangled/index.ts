import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

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

  pi.on("session_start", async (_e, ctx) => {
    try {
      await getToken();
      ctx.ui.notify("Tangled extension loaded", "info");
    } catch (err) {
      ctx.ui.notify(`Tangled auth failed: ${err}`, "error");
    }
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
