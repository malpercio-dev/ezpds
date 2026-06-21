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
    // Auto-detect PDS from DID document
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
    // Try DNS TXT record for did:plc handles
    // Fallback to tangled.org
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

  pi.registerTool({
    name: "tangled_list_prs",
    label: "List Tangled PRs",
    description: "List pull requests for a Tangled repository.",
    promptSnippet: "List pull requests for a Tangled repo",
    promptGuidelines: ["Use tangled_list_prs when the user asks about pull requests on a Tangled repo."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name (e.g. malpercio.dev/ezpds)" }),
      state: Type.Optional(Type.String({ description: "Filter: open, merged, closed, all (default open)" })),
      limit: Type.Optional(Type.Number({ description: "Max results (default 20)" })),
    }),
    async execute(_id, params) {
      const token = await getToken();
      const pds = await getPdsUrl();
      const limit = params.limit ?? 20;
      const did = await getDid();
      const qs = new URLSearchParams({ collection: "sh.tangled.pull", repo: did, limit: String(limit) });
      const res = await fetch(`${pds}/xrpc/com.atproto.repo.listRecords?${qs}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`listRecords failed: ${res.status}`);
      const data = (await res.json()) as { records: Array<{ uri: string; value: Record<string, unknown> }> };

      let prs = data.records;
      const stateFilter = params.state ?? "open";
      if (stateFilter !== "all") {
        prs = prs.filter((r) => r.value.state === stateFilter);
      }

      if (prs.length === 0) {
        return { content: [{ type: "text", text: `No ${stateFilter} PRs found.` }], details: { count: 0 } };
      }

      const lines = prs.map((r) => {
        const rkey = r.uri.split("/").pop();
        return `#${rkey} — ${r.value.title ?? "Untitled"} [${r.value.state ?? "?"}] — ${r.value.createdAt ?? ""}`;
      });

      return { content: [{ type: "text", text: lines.join("\n") }], details: { count: prs.length } };
    },
  });

  pi.registerTool({
    name: "tangled_list_issues",
    label: "List Tangled Issues",
    description: "List issues for a Tangled repository.",
    promptSnippet: "List issues for a Tangled repo",
    promptGuidelines: ["Use tangled_list_issues when the user asks about issues on a Tangled repo."],
    parameters: Type.Object({
      repo: Type.String({ description: "Repo handle/name" }),
      limit: Type.Optional(Type.Number({ description: "Max results (default 20)" })),
    }),
    async execute(_id, params) {
      const token = await getToken();
      const pds = await getPdsUrl();
      const limit = params.limit ?? 20;
      const did = await getDid();
      const qs = new URLSearchParams({ collection: "sh.tangled.repo.issue", repo: did, limit: String(limit) });
      const res = await fetch(`${pds}/xrpc/com.atproto.repo.listRecords?${qs}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`listRecords failed: ${res.status}`);
      const data = (await res.json()) as { records: Array<{ uri: string; value: Record<string, unknown> }> };

      const issues = data.records.filter((r) => {
        const issueRepo = String(r.value.repo ?? "");
        return issueRepo === params.repo || issueRepo.endsWith("/" + params.repo.split("/")[1]);
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
}
