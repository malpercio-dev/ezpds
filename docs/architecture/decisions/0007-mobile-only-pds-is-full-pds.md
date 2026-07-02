# ADR-0007: Mobile-only phase — the PDS is a full PDS (four-phase device model)

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled; reconciled in pds-architecture v8)
- **Deciders:** ezpds maintainers
- **Related:** [ADR-0004](0004-pds-signed-repo-commits.md) · [`../../pds-architecture.md`](../../pds-architecture.md) · [`../../unified-milestone-map.md`](../../unified-milestone-map.md)

## Context

The original design imagined the server as a **tunnel + proxy + signer** in front
of a repo hosted on the user's **desktop** — the desktop machine was the real
PDS, and the server relayed and signed for it. The mobile-first reconciliation
found this doesn't hold for the launch audience: mobile-only users have **no
desktop host** for the server to proxy to. If the server is only a tunnel, a
mobile user has no PDS at all.

## Decision

Adopt a **four-phase device-lifecycle model**, and in the first phase the server
**is** the PDS:

- **v0.1 — Mobile-only:** the PDS is a *full* PDS. It holds the repo, signs
  commits (ADR-0004), and emits the firehose natively.
- **v0.2 — Desktop-enrolled:** the PDS acts as proxy + signer in front of a
  desktop-hosted repo.
- **v1.0 — Public launch** · **v2.0+ — later.**

## Consequences

- **The PDS holds user repo data in the mobile-only phase.** This is a real
  custody surface — mitigated not by withholding data but by keeping the
  *identity* keys user-held (ADR-0001) and Shamir-splitting recovery material, so
  the server hosting the repo can never take over the identity.
- **Firehose is emitted natively** in v0.1 (vs proxied in the desktop-enrolled
  phase); the server self-announces genesis repos to the relay.
- **Determines the signing model** (ADR-0004): a full PDS must be the commit
  signer.
- Shamir share *generation* moves early (required at onboarding) because the
  server-as-PDS phase needs recovery material from day one.

## Alternatives considered

- **Server as pure tunnel/proxy always.** Rejected: assumes a desktop host that
  mobile-only users don't have, leaving them with no PDS. The phased model lets
  the server be a full PDS now and shrink to proxy+signer once a desktop host
  exists.
