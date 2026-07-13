# ADR-0005: Functional Core / Imperative Shell workspace architecture

- **Status:** Accepted
- **Date:** 2026-07-02 (backfilled)
- **Deciders:** ezpds maintainers
- **Related:** [`crates/pds/AGENTS.md`](../../../crates/pds/AGENTS.md) · [`crates/crypto/AGENTS.md`](../../../crates/crypto/AGENTS.md)

## Context

The workspace has four crates: `crypto`, `repo-engine`, `common` (logic), and
`pds` (the axum server). We need a discipline for where side effects live. Two
forces push hard here:

- The **crypto** logic (did:plc ops, P-256, DAG-CBOR, Shamir) must be reusable by
  *both* the PDS server and the identity-wallet app, and must be auditable in
  isolation — so it cannot be entangled with a database, HTTP, or a specific
  async runtime.
- Signing sometimes happens with a **non-extractable** key (Apple Secure
  Enclave), so the crypto layer cannot own the private key material or the I/O
  that reaches it.

## Decision

We adopt a **Functional Core / Imperative Shell** split:

- **`pds` is the sole Imperative Shell** — the only crate that touches SQLite,
  handles HTTP, or manages process-level state.
- **`crypto`, `repo-engine`, `common` are pure Functional Cores** — no I/O, no
  DB, no config; they take data in and return data out.
- Inside the shell: **route isolation** (one file per endpoint), **pattern
  comments** marking each module's role, and **`db/` owns SQL** with no business
  logic.
- Where a core needs a secret it must not hold, it takes an **external-signer
  closure** (e.g. `build_did_plc_genesis_op_with_external_signer`), so the wallet
  can sign with the Secure Enclave and the PDS can sign with its key, through the
  same pure function.

## Consequences

- **`crypto` is reused verbatim** by the PDS and the wallet, and can be
  security-reviewed as a unit with no runtime to mock.
- **Cores are trivially testable** (pure in/out; the golden DAG-CBOR tests are
  possible precisely because encoding is a pure function).
- **The external-signer seam** is what makes Secure-Enclave signing and
  PDS-side signing share one code path — it falls directly out of this rule.
- **Cost:** all state must be threaded through the shell; cores may not "reach
  out" for I/O even when it would be convenient. This is deliberate.

## Alternatives considered

- **Layered/service architecture with I/O throughout.** Rejected: it would couple
  `crypto` to a database/runtime, prevent wallet reuse, and make isolated
  security review of the cryptography impossible.
