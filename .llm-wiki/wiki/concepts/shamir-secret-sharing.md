---
type: concept
domain: engineering
created: 2026-06-22
updated: 2026-06-22
sources: [sources/SRC-2026-06-22-002, sources/SRC-2026-06-22-004]
---

# Shamir Secret Sharing

A cryptographic technique for splitting a secret into multiple shares, where only a threshold number of shares are needed to reconstruct the secret. Used in ezpds for [[concepts/did-plc|DID rotation key]] recovery.

## Scheme

- **3 shares, 2-of-3 threshold**: Any 2 shares can reconstruct the secret; 1 share reveals nothing.
- **Information-theoretic security**: A single share provides zero information about the secret (unlike, say, splitting a key in half).
- **GF(2^8) arithmetic**: Uses the AES irreducible polynomial (0x11b) for finite field operations.

## In ezpds

The [[entities/crypto|Crypto Crate]] provides:
- `split_secret(secret)` → `[ShamirShare; 3]` — Fresh OS RNG polynomial coefficients per call
- `combine_shares(share1, share2)` → `Zeroizing<[u8; 32]>` — Requires 2 distinct indices in [1, 3]

The [[entities/identity-wallet|Identity Wallet]] distributes shares:
- **Share 1**: Stored in iOS Keychain as `"recovery-share-1"` (iCloud Keychain automatic backup)
- **Share 2**: Held by the [[entities/relay|Relay Server]]
- **Share 3**: Returned to the user (displayed as base32, 52 chars)

## Recovery Flow

If the device key is lost, the user can reconstruct the rotation key by combining any 2 of the 3 shares. This allows recovery even if one share is lost or compromised.

## Related

- [[concepts/did-plc|did:plc]]
- [[entities/crypto|Crypto Crate]]
- [[entities/identity-wallet|Identity Wallet]]
- [[sources/SRC-2026-06-22-004]] — Crypto crate API
