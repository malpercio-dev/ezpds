---
title: Capability reference
description: Generated list of the capabilities a Custos deployment advertises.
---

> Generated from source for ezpds **v0.9.1**. Do not edit this page by hand.

Custos advertises these under the `custos` extension object of `com.atproto.server.describeServer`, alongside the running version. A client feature-gates on the presence of a name; a server that sends no `custos` object — the reference PDS, rsky-pds, millipds — has none of them, and clients fall back to standard AT Protocol behaviour. See [Capabilities](/operator/capabilities/) for what each one means for your deployment and how to turn it on.

| Capability | What it enables | Controlled by |
| --- | --- | --- |
| `createCeremony` | Custos-native identity creation: the mobile signup, per-account repo signing key issuance, and the client-authored did:plc genesis ceremony. | `signing_key_master_key` |
| `escrow` | Custos holds the account's encrypted Shamir Share 2 and releases it through the delayed, notified recovery gate. | `signing_key_master_key` |
| `sovereignSessions` | Passwordless full-access sessions minted from a fresh proof signed by one of the identity's current PLC rotation keys. | Always offered |
| `agents` | The auth.md agent surface: agent registration, the owner-confirmed claim ceremony, and agent-derived access tokens. | `agent_auth.service_auth_enabled`, `agent_auth.anonymous_enabled`, `agent_auth.trusted_issuers` |
| `walletConsent` | OAuth authorization can be approved in the identity wallet with a device-key-signed decision instead of a browser password. | Always offered |
| `optionalPassword` | An account can be created here with no password at all, authenticating thereafter with its device key. | `accounts.password_optional` |
| `walletAccountDelete` | An account can be permanently deleted with a device-key-signed proof from one of its current rotation keys instead of the account password. | Always offered |
| `didWebHosting` | Custos serves an opted-in account's did:web document at the account's own domain and propagates edits to relays. | Always offered |
| `waitlist` | Public interest-signup waitlist: unauthenticated email (+ optional atproto handle) signups a marketing page can post to, readable back by the operator. | `waitlist.enabled` |
