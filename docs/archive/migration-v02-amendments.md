# Migration Spec v0.2 Amendments

Changes required to update the Data Migration & Recovery Spec from v0.1 to v0.2. Maps to action items 16–18 from cross-spec-analysis.md.

---

## Changelog Entry

```
v0.2 Changes — Shamir Model Update + Mobile Cross-References

FIX   Shamir share model: Share 3 is user's choice (device-local or BIP-39)
NEW   Cross-references to mobile spec §7 for phone recovery
FIX   Milestone alignment with unified-milestone-map.md
```

---

## Item 16: Update Shamir Share Model

The migration spec's current Shamir share assignments need updating to match the decision made during cross-spec review.

### Current Model (v0.1)

The migration spec describes three shares but the assignment varies by section. Some sections say device/relay/iCloud, others are inconsistent.

### New Model (v0.2)

```
2-of-3 Shamir Secret Sharing for Root Rotation Key:

Share 1: iCloud Keychain (automatic, transparent to user)
Share 2: Relay escrow (encrypted at rest, access-logged)
Share 3: User's choice at account creation:
  Option A: Device-local (stored in Secure Enclave / Keychain)
  Option B: BIP-39 mnemonic (paper backup or USB)

Reconstruction requires any 2 of the 3 shares.

Recovery scenarios:
  - Lost phone, have desktop:  Share 1 (iCloud) + Share 2 (relay) → reconstruct
  - Lost phone, no desktop:    Share 1 (iCloud) + Share 2 (relay) → reconstruct
  - Lost phone + iCloud:       Share 2 (relay) + Share 3 (user) → reconstruct
  - Relay compromised:         Share 1 (iCloud) + Share 3 (user) → reconstruct
  - All three lost:            DID is orphaned (permanent, by design)
```

### Sections to Update

Every section that references Shamir shares should use the Share 1/2/3 naming above. Specifically:

- Section 4 (Unplanned Device Loss): Update share descriptions
- Any table listing share locations: Use the canonical assignment
- Recovery ceremony flow: Reference shares by number and location

---

## Item 17: Cross-Reference Mobile Spec §7

The migration spec covers desktop-to-desktop migration but doesn't reference phone-to-phone migration. The mobile spec §7.2 covers phone recovery using the same Shamir infrastructure.

### Add Cross-Reference Section

Add after the unplanned device loss section:

```
4.x Phone Recovery

Phone-to-phone recovery uses the same Shamir infrastructure as
desktop recovery. The mobile architecture spec (§7) details the
iOS-specific flow:

  1. New phone signs into iCloud → Share 1 is available
  2. User authenticates with relay → Share 2 is available
  3. Relay reconstructs rotation key from 2 shares
  4. Relay re-generates signing key, updates DID document
  5. New phone stores new rotation key in Secure Enclave

The key difference from desktop recovery: in phone recovery, the
relay already holds the repo (it's the PDS in mobile-only mode),
so there's no repo transfer step. Recovery is purely a key
reconstruction + DID update operation.

See: mobile-architecture-spec-v1.2 §7.2 for the complete flow.
```

---

## Item 18: Align Milestone Timing

The migration spec puts "basic Shamir" in v0.1 and "full recovery" in v1.0. This aligns with the unified milestone map, but the language should be explicit.

### Update Section 8 (Implementation Milestones)

```
v0.1 — Basic Migration + Shamir Generation
  - Planned device swap (LAN transfer via Iroh, 6-digit code)
  - Shamir share generation during account creation
  - Share 1 → iCloud Keychain storage
  - Share 2 → relay escrow
  - Share 3 → user's choice (device-local or BIP-39)
  Note: Share GENERATION is v0.1. Share RECOVERY is v1.0.

v1.0 — Full Recovery
  - Unplanned device loss recovery ceremony
  - Shamir reconstruction (2-of-3)
  - DID key rotation after recovery
  - Recovery UI in mobile app
  - Relay-side recovery session management

Later
  - Multi-device sync (share key across devices without migration)
```

Add note:
```
See unified-milestone-map.md for how these milestones align with
the architecture, provisioning API, and mobile spec phases.
```
