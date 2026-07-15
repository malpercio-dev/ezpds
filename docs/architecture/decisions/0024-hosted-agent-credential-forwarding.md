# ADR-0024: The hosted agent tier forwards credentials

- **Status:** Accepted
- **Date:** 2026-07-15
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0019](0019-authmd-agent-authentication.md) · [ADR-0023](0023-sovereign-child-agent-identities.md) · [hosted Custos MCP plan](../../design-plans/2026-07-14-hosted-custos-mcp.md) · [MM-356](https://linear.app/malpercio/issue/MM-356) · [MM-365](https://linear.app/malpercio/issue/MM-365)

## Context

A multi-tenant hosted MCP tier needs to authenticate every tool call to Custos.
The naive design creates a server-side session per user or agent and stores its
long-lived credential. That turns the tier into a durable secret custodian and,
for acts-as-you delegates, gives the operator continuing authority to act as the
user.

MCP remote authentication already uses OAuth, and Custos already serves as the
authorization server and resource server. Credential custody and process
placement are separate decisions: a Node sidecar or an eventual in-PDS axum
endpoint can both forward credentials.

## Decision

The hosted agent tier will authenticate through OAuth against Custos and forward
the caller's access token on every request. The caller obtains and presents the
token; it rides the corresponding tool call to the PDS. The hosted tier will not
persist user credentials, agent assertions, refresh tokens, access tokens, or
other secrets that grant durable authority.

The tier may retain only request- or session-scoped in-memory state needed for
MCP transport. That state must not outlive its bounded session, survive a
restart, or become a credential cache. This posture applies whether the first
implementation is a separate Node sidecar or the endpoint is later folded into
the PDS.

## Consequences

- Compromising the hosted tier does not yield a durable credential store; the
  attack window is bounded to credentials present in active requests or memory.
- Revocation and scope enforcement remain in Custos's existing OAuth/auth.md
  path rather than being duplicated by the MCP service.
- Hosted acts-as-you remains possible only through this forwarding posture;
  durable custody of such a credential is forbidden by ADR-0023.
- MCP clients must perform remote OAuth and send a credential with each call.
  The hosted tier cannot continue acting after the caller stops authorizing it.
- Logs, traces, errors, and metrics must redact authorization material; avoiding
  database storage alone is not sufficient to meet the no-durable-secret rule.
- Process placement remains reversible: the sidecar can ship first without
  making custody a reason to keep or remove that process boundary.

## Alternatives considered

- **Store long-lived per-caller credentials in the hosted tier.** Rejected
  because it creates a high-value custody service and permits continuing action
  without a credential-bearing caller.
- **Exchange once and cache access tokens durably.** Rejected because token
  lifetime does not make persisted bearer credentials harmless and it weakens
  revocation semantics.
- **Fold MCP into the PDS solely to avoid forwarding.** Rejected because process
  placement does not require credential custody; an in-PDS endpoint may still
  be a later consolidation for operational reasons.
