# Mobile Architecture Spec — Minor Amendments

Changes required for the Mobile Architecture Spec v1.2. Maps to action items 19–20 from cross-spec-analysis.md. These are minor updates — the mobile spec is canonical and needs the fewest changes.

---

## Item 19: Update Shamir Share 3 — User's Choice

The mobile spec currently specifies Share 3 as BIP-39 mnemonic phrase. Per the cross-spec decision, Share 3 should be the user's choice between device-local storage or BIP-39.

### Section to Update

Find the Shamir share description (likely §3.1 Step 7 or §7) and change:

```
Current:
  Share 3: BIP-39 mnemonic phrase (paper backup)

Change to:
  Share 3: User's choice at account creation
    Option A: Device-local (Secure Enclave / Keychain on a second device)
    Option B: BIP-39 mnemonic phrase (paper backup or USB storage)

  The onboarding flow presents both options with a brief explanation:
    - Device-local is more convenient but requires a second device
    - BIP-39 is more resilient but requires physical safekeeping

  Default recommendation: BIP-39 (safer for users with only one device)
```

---

## Item 20: Cross-Reference Migration Spec

The mobile spec covers phone recovery (§7) but doesn't reference the migration spec's desktop-to-desktop transfer or the planned device swap flow.

### Add Cross-Reference

In §7 (or wherever recovery is discussed), add:

```
For planned device upgrades (e.g., new iPhone), see the Data
Migration & Recovery Spec §3 which covers the Iroh-based peer
transfer with 6-digit verification code. The same transfer
protocol works for phone-to-phone and desktop-to-desktop swaps.

For desktop-specific migration (desktop-to-desktop), see the
Data Migration & Recovery Spec §3.x. The phone acts as the
authorization device during desktop transfers — the user
confirms the transfer from the mobile app.
```
