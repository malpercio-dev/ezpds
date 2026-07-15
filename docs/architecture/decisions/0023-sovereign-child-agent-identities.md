# ADR-0023: Agents may be sovereign child identities

- **Status:** Accepted
- **Date:** 2026-07-15
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0001](0001-client-held-rotation-key-custody.md) · [ADR-0004](0004-pds-signed-repo-commits.md) · [ADR-0019](0019-authmd-agent-authentication.md) · [hosted Custos MCP plan](../../design-plans/2026-07-14-hosted-custos-mcp.md) · [MM-356](https://linear.app/malpercio/issue/MM-356) · [MM-365](https://linear.app/malpercio/issue/MM-365)

## Context

The shipped Custos MCP acts as its user: it writes to the user's repo and its
actions carry the user's identity. That attribution is correct when the user
self-hosts and keeps the durable auth.md `service_auth` credential on their own
machine. It becomes a custody problem when an operator-hosted service retains a
credential that can act durably as the user.

Attribution and hosting are independent choices. Treating a separate agent
identity as a universal replacement would unnecessarily remove the useful
acts-as-you model; treating hosting as permission to custody an acts-as-you
credential would contradict the project's sovereignty guarantees.

## Decision

Agents may be first-class sovereign child identities. A child agent has its own
DID, repo, and handle and is owned by a parent account on the same PDS. Its
rotation/recovery key lives in the parent's Obsign wallet and uses the same
`did:plc` genesis and rotation machinery as the user's identity. The agent's
day-to-day signing capability is delegated, scope-clamped, short-lived, and
revocable. The PDS continues to hold the agent repo-signing key and sign commits
as established by ADR-0004.

The sovereign-child model is the default for operator-hosted agents. The
auth.md acts-as-you delegate model remains first-class and is the default for
self-hosting. The complete policy is a matrix:

| | **Acts as you** (delegate) | **Acts as itself** (sovereign child) |
| --- | --- | --- |
| **Self-hosted** | Default; the user holds the durable credential | Supported when distinct attribution is wanted |
| **Operator-hosted** | Allowed only with strict per-request credential forwarding; never durable operator custody | Default; durable authority cannot act as the parent user |

The only forbidden combination is operator-hosted, acts-as-you, and durable
credential custody.

The key-custody ladder is:

| Key or capability | Custodian | Hosted-tier exposure |
| --- | --- | --- |
| User rotation/recovery key | Obsign Secure Enclave | Never |
| Agent rotation/recovery key | Parent's Obsign wallet | Never |
| Agent day-to-day signing capability | Delegated to the agent | Revocable and disposable |
| Agent access token | Calling client | Ephemeral; five-minute lifetime |

## Consequences

- Hosted-agent actions can be attributed to a distinct principal rather than
  silently appearing as the parent user's actions.
- Compromise or revocation of an agent's delegated authority does not surrender
  the parent identity or the agent's recovery authority to the operator.
- Child creation must prove ownership of a parent account on the same PDS; this
  ownership graph is also the entitlement boundary.
- The wallet must support custody and recovery ceremonies for agent rotation
  keys, and the PDS must support child DID, repo, and handle lifecycle.
- Two supported attribution models remain visible in product and documentation;
  callers must choose based on desired attribution rather than hosting alone.

## Alternatives considered

- **Always act as the user.** Rejected for hosted agents because durable
  operator custody would let a third party act indistinguishably as the user.
- **Always create a sovereign child.** Rejected because it changes attribution
  and needlessly displaces the simple, safe self-hosted delegate model.
- **Let the hosted operator hold the agent recovery key.** Rejected because the
  agent would be operator-custodied rather than sovereign and recoverable by
  its owner.
