/**
 * Linear Extension for Pi
 *
 * Registers tools for interacting with the Linear issue tracker via GraphQL.
 * Requires LINEAR_API_KEY in the environment.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { StringEnum } from "@earendil-works/pi-ai";

// ── Linear GraphQL client ─────────────────────────────────────────────────────

const LINEAR_API = "https://api.linear.app/graphql";

type GraphQLResponse<T = any> = {
  data?: T;
  errors?: Array<{ message: string; extensions?: Record<string, unknown> }>;
};

async function linearQuery<T = any>(
  token: string,
  query: string,
  variables: Record<string, unknown> = {},
): Promise<T> {
  const res = await fetch(LINEAR_API, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: token,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!res.ok) {
    throw new Error(`Linear API HTTP ${res.status}: ${await res.text()}`);
  }

  const body = (await res.json()) as GraphQLResponse<T>;
  if (body.errors?.length) {
    const msgs = body.errors.map((e) => e.message).join("; ");
    throw new Error(`Linear API errors: ${msgs}`);
  }
  if (!body.data) {
    throw new Error("Linear API returned no data");
  }
  return body.data;
}

// ── Formatters ────────────────────────────────────────────────────────────────

function formatIssueShort(issue: {
  identifier: string;
  title: string;
  state?: { name: string };
  assignee?: { name: string } | null;
  priority?: number;
  labels?: { nodes: { name: string }[] };
}): string {
  const parts = [issue.identifier, issue.title];
  if (issue.state?.name) parts.push(`[${issue.state.name}]`);
  if (issue.assignee?.name) parts.push(`(${issue.assignee.name})`);
  if (issue.priority && issue.priority > 0) parts.push(`P${issue.priority}`);
  if (issue.labels?.nodes?.length)
    parts.push(`{${issue.labels.nodes.map((l) => l.name).join(", ")}}`);
  return parts.join(" — ");
}

const PRIORITY_LABELS: Record<number, string> = {
  0: "No priority",
  1: "Urgent",
  2: "High",
  3: "Medium",
  4: "Low",
};

// ── GQL fragments ─────────────────────────────────────────────────────────────

const ISSUE_FIELDS = `
  identifier
  title
  description
  url
  priority
  estimate
  state { name type }
  assignee { name email }
  team { key name }
  project { id name }
  labels { nodes { name } }
  createdAt
  updatedAt
`;

const ISSUE_BRIEF = `
  identifier
  title
  url
  state { name }
  assignee { name }
  priority
  team { key }
  project { id name }
  labels { nodes { name } }
`;

// ── Extension entry point ─────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  const token = process.env.LINEAR_API_KEY;
  if (!token) {
    pi.on("session_start", (_e, ctx) => {
      ctx.ui.notify("LINEAR_API_KEY not set — Linear tools disabled", "warning");
    });
    return;
  }

  // ── linear_list_projects ─────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_list_projects",
    label: "List Linear Projects",
    description: "List all Linear projects with their IDs and names. Use this to find a project ID for filtering issues.",
    promptSnippet: "List all Linear projects with their IDs",
    promptGuidelines: [
      "Use linear_list_projects when the user asks about projects or when you need a project ID to filter issues.",
    ],
    parameters: Type.Object({
      limit: Type.Optional(Type.Number({ description: "Max results (default 50)" })),
    }),
    async execute(_id, params) {
      const limit = params.limit ?? 50;
      const gql = `query Projects($first: Int!) {
        projects(first: $first, filter: { state: { neq: "completed" } }) {
          nodes { id name description state }
        }
      }`;
      const data = await linearQuery(token, gql, { first: limit });
      const projects = data.projects?.nodes ?? [];
      if (projects.length === 0) {
        return {
          content: [{ type: "text", text: "No active projects found." }],
          details: { count: 0 },
        };
      }
      const lines = projects.map(
        (p: any) => `${p.id} — ${p.name} [${p.state}]${p.description ? `: ${p.description}` : ""}`,
      );
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { count: projects.length, projects },
      };
    },
  });

  // ── linear_search_issues ─────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_search_issues",
    label: "Search Linear Issues",
    description: "Search for Linear issues by text query. Returns matching issues with identifiers, titles, status, assignees, and URLs.",
    promptSnippet: "Search Linear for issues matching a query string",
    promptGuidelines: [
      "Use linear_search_issues when the user asks to find, search, or look up Linear issues.",
    ],
    parameters: Type.Object({
      query: Type.String({ description: "Search query (issue title, identifier, label, etc.)" }),
      project_id: Type.Optional(Type.String({ description: "Filter by project ID" })),
      limit: Type.Optional(Type.Number({ description: "Max results (default 20, max 50)" })),
    }),
    async execute(_id, params) {
      const limit = Math.min(params.limit ?? 20, 50);
      const filters: string[] = [];
      if (params.project_id) filters.push(`project: { id: { eq: "${params.project_id}" } }`);
      const filterStr = filters.length > 0 ? `filter: { ${filters.join(", ")} }` : "";

      const gql = `query Search($first: Int!) {
        issues(${filterStr}, first: $first, orderBy: updatedAt) {
          nodes { ${ISSUE_BRIEF} }
        }
      }`;
      const data = await linearQuery(token, gql, { first: limit });
      const allIssues = data.issues?.nodes ?? [];

      // Client-side text filter since the issues query doesn't support full-text search
      const q = params.query.toLowerCase();
      const issues = q
        ? allIssues.filter(
            (i: any) =>
              i.title?.toLowerCase().includes(q) ||
              i.identifier?.toLowerCase().includes(q) ||
              i.labels?.nodes?.some((l: any) => l.name?.toLowerCase().includes(q)),
          )
        : allIssues;

      if (issues.length === 0) {
        return {
          content: [{ type: "text", text: "No issues found." }],
          details: { count: 0 },
        };
      }
      const lines = issues.map(formatIssueShort);
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { count: issues.length, issues },
      };
    },
  });

  // ── linear_get_issue ─────────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_get_issue",
    label: "Get Linear Issue",
    description: "Fetch full details of a Linear issue by its identifier (e.g. ENG-123). Returns title, description, status, assignee, priority, labels, project, and URL.",
    promptSnippet: "Get full details of a Linear issue by identifier (e.g. ENG-123)",
    promptGuidelines: [
      "Use linear_get_issue when the user asks to see or read a specific Linear issue by its identifier.",
    ],
    parameters: Type.Object({
      identifier: Type.String({ description: "Issue identifier, e.g. 'ENG-123'" }),
    }),
    async execute(_id, params) {
      const [teamKey, numberStr] = params.identifier.split("-");
      const number = parseInt(numberStr, 10);
      if (!teamKey || isNaN(number)) {
        throw new Error(`Invalid identifier "${params.identifier}". Expected format: TEAM-123`);
      }
      const gql = `query GetIssue($teamKey: String!, $number: Float!) {
        issues(filter: { team: { key: { eq: $teamKey } }, number: { eq: $number } }, first: 1) {
          nodes { ${ISSUE_FIELDS} }
        }
      }`;
      const data = await linearQuery(token, gql, { teamKey, number });
      const issues = data.issues?.nodes ?? [];
      if (issues.length === 0) {
        return {
          content: [{ type: "text", text: `Issue ${params.identifier} not found.` }],
          details: {},
        };
      }
      const issue = issues[0];
      const parts = [
        `# ${issue.identifier} — ${issue.title}`,
        "",
        `**Status:** ${issue.state?.name ?? "Unknown"}`,
        `**Priority:** ${PRIORITY_LABELS[issue.priority ?? 0] ?? "Unknown"}`,
      ];
      if (issue.assignee) parts.push(`**Assignee:** ${issue.assignee.name} (${issue.assignee.email})`);
      if (issue.team) parts.push(`**Team:** ${issue.team.name} (${issue.team.key})`);
      if (issue.project) parts.push(`**Project:** ${issue.project.name}`);
      if (issue.estimate) parts.push(`**Estimate:** ${issue.estimate}`);
      if (issue.labels?.nodes?.length)
        parts.push(`**Labels:** ${issue.labels.nodes.map((l: any) => l.name).join(", ")}`);
      parts.push(`**Created:** ${issue.createdAt}`);
      parts.push(`**Updated:** ${issue.updatedAt}`);
      parts.push(`**URL:** ${issue.url}`);
      if (issue.description) {
        parts.push("", "## Description", "", issue.description);
      }
      return {
        content: [{ type: "text", text: parts.join("\n") }],
        details: { issue },
      };
    },
  });

  // ── linear_update_issue ──────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_update_issue",
    label: "Update Linear Issue",
    description: "Update fields on a Linear issue. Supports changing title, description, priority, assignee, and status (state). Only send fields you want to change.",
    promptSnippet: "Update a Linear issue's title, description, priority, assignee, or status",
    promptGuidelines: [
      "Use linear_update_issue when the user asks to change, update, or modify a Linear issue.",
      "Use linear_update_issue to change issue status, priority, assignee, title, or description.",
    ],
    parameters: Type.Object({
      identifier: Type.String({ description: "Issue identifier, e.g. 'ENG-123'" }),
      title: Type.Optional(Type.String({ description: "New title" })),
      description: Type.Optional(Type.String({ description: "New description (Markdown supported)" })),
      priority: Type.Optional(Type.Number({ description: "Priority: 0=No priority, 1=Urgent, 2=High, 3=Medium, 4=Low" })),
      state: Type.Optional(
        StringEnum(["Backlog", "Todo", "In Progress", "In Review", "Done", "Canceled"] as const, {
          description: "New workflow state",
        }),
      ),
      assignee_id: Type.Optional(Type.String({ description: "Assignee user ID. Use linear_list_users to find IDs. Pass null to unassign." })),
      estimate: Type.Optional(Type.Number({ description: "Story point estimate" })),
    }),
    async execute(_id, params) {
      // Resolve issue ID from identifier
      const [updTeamKey, updNumberStr] = params.identifier.split("-");
      const updNumber = parseInt(updNumberStr, 10);
      if (!updTeamKey || isNaN(updNumber)) {
        throw new Error(`Invalid identifier "${params.identifier}". Expected format: TEAM-123`);
      }
      const resolveGql = `query ResolveId($teamKey: String!, $number: Float!) {
        issues(filter: { team: { key: { eq: $teamKey } }, number: { eq: $number } }, first: 1) {
          nodes { id identifier team { key } }
        }
      }`;
      const resolveData = await linearQuery(token, resolveGql, { teamKey: updTeamKey, number: updNumber });
      const issues = resolveData.issues?.nodes ?? [];
      if (issues.length === 0) {
        throw new Error(`Issue ${params.identifier} not found`);
      }
      const issue = issues[0];
      const issueId = issue.id;

      // Build input with only provided fields
      const input: Record<string, unknown> = {};
      if (params.title !== undefined) input.title = params.title;
      if (params.description !== undefined) input.description = params.description;
      if (params.priority !== undefined) input.priority = params.priority;
      if (params.estimate !== undefined) input.estimate = params.estimate;
      if (params.assignee_id !== undefined) input.assigneeId = params.assignee_id;

      // Resolve state ID if state change requested
      if (params.state) {
        const teamKey = issue.team?.key;
        if (!teamKey) throw new Error("Cannot resolve team for state lookup");
        const stateGql = `query States($teamKey: String!, $stateName: String!) {
          workflowStates(
            filter: { team: { key: { eq: $teamKey } }, name: { eq: $stateName } }
            first: 1
          ) {
            nodes { id name }
          }
        }`;
        const stateData = await linearQuery(token, stateGql, { teamKey, stateName: params.state });
        const states = stateData.workflowStates?.nodes ?? [];
        if (states.length === 0) {
          throw new Error(`State "${params.state}" not found for team ${teamKey}`);
        }
        input.stateId = states[0].id;
      }

      if (Object.keys(input).length === 0) {
        return {
          content: [{ type: "text", text: "No fields to update." }],
          details: {},
        };
      }

      const updateGql = `mutation UpdateIssue($id: String!, $input: IssueUpdateInput!) {
        issueUpdate(id: $id, input: $input) {
          success
          issue { ${ISSUE_FIELDS} }
        }
      }`;
      const data = await linearQuery(token, updateGql, { id: issueId, input });
      if (!data.issueUpdate?.success) {
        throw new Error("Linear issue update failed");
      }
      const updated = data.issueUpdate.issue;
      return {
        content: [{ type: "text", text: `Updated ${updated.identifier}: ${updated.title} [${updated.state?.name}]` }],
        details: { issue: updated },
      };
    },
  });

  // ── linear_create_comment ────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_create_comment",
    label: "Comment on Linear Issue",
    description: "Add a comment to a Linear issue. Supports Markdown formatting.",
    promptSnippet: "Add a comment to a Linear issue",
    promptGuidelines: [
      "Use linear_create_comment when the user asks to comment on, add a note to, or post feedback on a Linear issue.",
    ],
    parameters: Type.Object({
      identifier: Type.String({ description: "Issue identifier, e.g. 'ENG-123'" }),
      body: Type.String({ description: "Comment text (Markdown supported)" }),
    }),
    async execute(_id, params) {
      const [cmtTeamKey, cmtNumberStr] = params.identifier.split("-");
      const cmtNumber = parseInt(cmtNumberStr, 10);
      if (!cmtTeamKey || isNaN(cmtNumber)) {
        throw new Error(`Invalid identifier "${params.identifier}". Expected format: TEAM-123`);
      }
      const resolveGql = `query ResolveId($teamKey: String!, $number: Float!) {
        issues(filter: { team: { key: { eq: $teamKey } }, number: { eq: $number } }, first: 1) {
          nodes { id identifier title }
        }
      }`;
      const resolveData = await linearQuery(token, resolveGql, { teamKey: cmtTeamKey, number: cmtNumber });
      const issues = resolveData.issues?.nodes ?? [];
      if (issues.length === 0) {
        throw new Error(`Issue ${params.identifier} not found`);
      }
      const issue = issues[0];

      const createGql = `mutation CreateComment($issueId: String!, $body: String!) {
        commentCreate(input: { issueId: $issueId, body: $body }) {
          success
          comment { id body createdAt }
        }
      }`;
      const data = await linearQuery(token, createGql, { issueId: issue.id, body: params.body });
      if (!data.commentCreate?.success) {
        throw new Error("Failed to create comment");
      }
      return {
        content: [{ type: "text", text: `Comment added to ${issue.identifier} (${issue.title})` }],
        details: { comment: data.commentCreate.comment },
      };
    },
  });

  // ── linear_list_users ────────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_list_users",
    label: "List Linear Users",
    description: "List Linear team members. Returns user IDs, names, and emails. Useful for finding assignee IDs when updating issues.",
    promptSnippet: "List Linear team members with their IDs",
    promptGuidelines: [
      "Use linear_list_users when you need to find a user ID to assign an issue or when the user asks about team members.",
    ],
    parameters: Type.Object({
      query: Type.Optional(Type.String({ description: "Filter users by name or email" })),
    }),
    async execute(_id, params) {
      const gql = `query Users {
        users(first: 50) {
          nodes { id name email active }
        }
      }`;
      const data = await linearQuery(token, gql);
      let users = data.users?.nodes ?? [];
      if (params.query) {
        const q = params.query.toLowerCase();
        users = users.filter(
          (u: any) => u.name?.toLowerCase().includes(q) || u.email?.toLowerCase().includes(q),
        );
      }
      if (users.length === 0) {
        return {
          content: [{ type: "text", text: "No users found." }],
          details: { count: 0 },
        };
      }
      const lines = users.map(
        (u: any) => `${u.id} — ${u.name} (${u.email})${u.active ? "" : " [inactive]"}`,
      );
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { count: users.length, users },
      };
    },
  });

  // ── linear_list_teams ────────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_list_teams",
    label: "List Linear Teams",
    description: "List all Linear teams with their keys and names.",
    promptSnippet: "List all Linear teams",
    promptGuidelines: [
      "Use linear_list_teams when the user asks what teams exist or to find a team key.",
    ],
    parameters: Type.Object({}),
    async execute() {
      const gql = `query Teams {
        teams(first: 50) {
          nodes { key name description }
        }
      }`;
      const data = await linearQuery(token, gql);
      const teams = data.teams?.nodes ?? [];
      if (teams.length === 0) {
        return {
          content: [{ type: "text", text: "No teams found." }],
          details: { count: 0 },
        };
      }
      const lines = teams.map(
        (t: any) => `${t.key} — ${t.name}${t.description ? `: ${t.description}` : ""}`,
      );
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { count: teams.length, teams },
      };
    },
  });

  // ── linear_list_issues ───────────────────────────────────────────────────

  pi.registerTool({
    name: "linear_list_issues",
    label: "List Linear Issues",
    description: "List issues with optional filters. Useful for browsing a team's backlog, a project's issues, or seeing what's in progress.",
    promptSnippet: "List issues in a Linear team or project with optional filters",
    promptGuidelines: [
      "Use linear_list_issues when the user asks to see, list, or browse issues for a specific team or project.",
    ],
    parameters: Type.Object({
      team_key: Type.Optional(Type.String({ description: "Team key, e.g. 'MM'" })),
      project_id: Type.Optional(Type.String({ description: "Project ID to filter by" })),
      state: Type.Optional(
        StringEnum(["Backlog", "Todo", "In Progress", "In Review", "Done", "Canceled"] as const, {
          description: "Filter by workflow state",
        }),
      ),
      assignee_id: Type.Optional(Type.String({ description: "Filter by assignee user ID" })),
      priority: Type.Optional(Type.Number({ description: "Filter by priority (0-4)" })),
      limit: Type.Optional(Type.Number({ description: "Max results (default 30, max 100)" })),
    }),
    async execute(_id, params) {
      const limit = Math.min(params.limit ?? 30, 100);

      const filters: string[] = [];
      if (params.team_key) filters.push(`team: { key: { eq: "${params.team_key}" } }`);
      if (params.project_id) filters.push(`project: { id: { eq: "${params.project_id}" } }`);
      if (params.state) filters.push(`state: { name: { eq: "${params.state}" } }`);
      if (params.assignee_id) filters.push(`assignee: { id: { eq: "${params.assignee_id}" } }`);
      if (params.priority !== undefined) filters.push(`priority: { eq: ${params.priority} }`);

      const filterStr = filters.length > 0 ? `filter: { ${filters.join(", ")} }` : "";

      const gql = `query ListIssues {
        issues(${filterStr}, first: ${limit}, orderBy: updatedAt) {
          nodes { ${ISSUE_BRIEF} }
        }
      }`;
      const data = await linearQuery(token, gql);
      const issues = data.issues?.nodes ?? [];
      if (issues.length === 0) {
        return {
          content: [{ type: "text", text: "No issues found." }],
          details: { count: 0 },
        };
      }
      const lines = issues.map(formatIssueShort);
      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: { count: issues.length, issues },
      };
    },
  });

  // ── Notify on load ──────────────────────────────────────────────────────

  pi.on("session_start", (_e, ctx) => {
    ctx.ui.notify("Linear extension loaded — 8 tools registered", "info");
  });
}
