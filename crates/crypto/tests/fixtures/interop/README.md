# Vendored ATProto interop fixtures (crypto)

Implementation-neutral cryptographic test vectors from
[bluesky-social/atproto-interop-tests](https://github.com/bluesky-social/atproto-interop-tests),
all **CC0-1.0** licensed. Vendored verbatim; refresh by re-downloading from the
`crypto/` directory of that repo.

| File | Source | License |
|---|---|---|
| `signature-fixtures.json` | `crypto/signature-fixtures.json` | CC0-1.0 |

## Consumed by

- `tests/interop_vectors.rs`

`signature-fixtures.json` pins the two atproto signature-verification invariants
this crate implements: **low-S canonicalization** (`high-s` cases must be
rejected on both P-256 and secp256k1) and **raw-r‖s only** (`der-encoded` cases
must be rejected). Each fixture also cross-checks `did:key:` curve detection
(`did_key_curve`) against its declared algorithm, covering both curves.

> The upstream `crypto/w3c_didkey_{P256,K256}.json` vectors are intentionally
> **not** vendored: they carry private-key material (which this crate never
> uses — only the public `did:key` is needed) that secret scanners flag. Curve
> detection is covered by the signature fixtures above, which are public-key
> only.
