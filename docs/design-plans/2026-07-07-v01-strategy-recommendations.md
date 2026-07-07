# v0.1 Strategy Recommendations — Index and Sequencing

Date: 2026-07-07
Status: Approved by maintainer; each linked plan is ready for implementation by an agent.

## Context

A three-track review (v0.1 gap analysis, Wave 8 / auth.md leverage, code-quality audit) found that
the v0.1 *feature* surface is essentially complete: all 25 target federation endpoints plus health,
full OAuth provider (DPoP/PAR/PKCE/JWKS/granular scopes/PRM), durable firehose with Sync v1.1, blob
GC + quotas, appview/chat proxy with read-after-write, Shamir escrow, the provisioning API, and
substantial v1.0-scope work (PDS↔PDS migration, moderation, outbound email) have all landed.

What remains is not feature work. It falls into three buckets, each with its own design plan:

## The plans

1. **[v0.1 Operational Proof](2026-07-07-v01-operational-proof.md)** — the release gate.
   Metrics (`/metrics` + federation-health gauges), a local HTTP integration harness for
   `crates/pds`, and the canonical live bsky.social migration validation run (MM-241).
   *The code is done; the proof is not.*

2. **[Agent Scope Enforcement](2026-07-07-agent-scope-enforcement.md)** — safety-critical,
   do **before** any agent exists in the wild. Today an agent credential functionally grants full
   `com.atproto.access`; per-identity `granted_scopes` are stored but not meaningfully enforced
   through the granular scope grammar.

3. **[Wallet Agent Consent and Audit](2026-07-07-wallet-agent-consent-and-audit.md)** — the
   product-thesis play. Claim-ceremony approval in Obsign, a "My agents" screen with revocation,
   and an immutable agent-action audit log.

4. **[Custos MCP Server](2026-07-07-custos-mcp-server.md)** — the differentiator. A first-party
   MCP server that self-onboards via auth.md and exposes the PDS as agent tools. Also serves as
   the end-to-end integration test for Wave 8, and gives Wave 8 a concrete finish line
   (MM-169/170/173/176 are prerequisites).

5. **[Code Quality Hardening](2026-07-07-code-quality-hardening.md)** — small, cheap-now fixes:
   async blob I/O, `Sensitive`-wrapping `admin_token`, scoped CORS for admin routes, rejection
   sampling in short-code generation, `transfer/accept` rate limiting, and a `cargo-deny` gate.

## Sequencing

```text
Code Quality Hardening ──────────────────────────────┐  (independent, do anytime, small PRs)
                                                     │
Agent Scope Enforcement ──> Wallet Consent & Audit ──┼──> Custos MCP Server
        (server closes the scope hole first)         │      (needs MM-169/170/173/176 +
                                                     │       scope enforcement to be safe)
v0.1 Operational Proof ──────────────────────────────┘  (independent; gates the v0.1 "done" call)
```

- **Agent Scope Enforcement precedes everything agent-facing.** Shipping agent onboarding (MCP,
  claim UI) while agent tokens are full-access would be practice-what-you-preach failure.
- **Operational Proof is independent** and can run in parallel with everything else. It is the
  gate for declaring v0.1 done, not a dependency of the agent work.
- **Code Quality Hardening** items are individually PR-sized and can interleave anywhere.

## Ground rules for implementing agents

These apply to every plan (they restate repo conventions from `AGENTS.md` / `crates/pds/CLAUDE.md`):

- Any new or changed PDS route **must** get a matching `.bru` file in `bruno/` (CI-enforced by
  `just bruno-check`).
- No ticket references (`MM-xxx`) in source code or CLAUDE.md files — traceability lives in
  `docs/` only.
- Routes never import routes; shared logic goes in `auth/`, `db/`, or dedicated modules.
- Tests are colocated `#[cfg(test)]` modules; router-level tests use `tower::ServiceExt::oneshot`
  against the in-memory SQLite `test_state()`.
- Run `just ci` (or `just ci-pds` where iOS crates are excluded) before pushing.
- New dependencies: justify in the PR description; `Cargo.lock` diffs are reviewed.
