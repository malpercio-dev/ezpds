# Emphasis surface inventory

Baseline: `fce27c34`. Re-run the route/component inventory before implementation to include additions since this design review. All paths below are repository-relative. “Specimen” means a representative view exists in `preview.html`; it does not mean the entire flow was prototyped.

## Obsign wallet

Entry/router: `apps/identity-wallet/src/routes/+page.svelte`; shared chrome/styles: `src/routes/+layout.svelte` and `src/lib/styles/`. Read `apps/identity-wallet/AGENTS.md` before changing app code. Component paths below are relative to `apps/identity-wallet/src/lib/components/`.

| Family | Source components | Design application and required states |
| --- | --- | --- |
| Identity list and detail | `home/IdentityListHome.svelte`, `home/IdentityScreen.svelte`, `home/SecurityCheckup.svelte`, `home/ProtectionScreen.svelte`, `home/ManageIdentityScreen.svelte` | Identity scope → Emphasis observation → everyday rows → protection/maintenance. Detail specimen exists. Also cover multiple/zero identities, loading, missing key, stale/unavailable and domain identity. |
| Change review and signed operations | `home/AlertDetailScreen.svelte`, `home/RecoveryOverrideScreen.svelte`, `home/RekeyReviewScreen.svelte`, `onboarding/ReviewOperationScreen.svelte` | Carry identity/deadline, before/after and consequences through review. Change-review specimen exists; signed override, in-flight, success, failure and expired-window screens still need real implementation. Preserve confirmation/hold alternatives. |
| Connected apps and agents | `home/OAuthConsentApprovalScreen.svelte`, `home/AppPasswordsScreen.svelte`, `home/MyAgentsScreen.svelte`, `home/AgentDetailScreen.svelte`, `home/AgentClaimApprovalScreen.svelte`, `home/ChildAgentDetailScreen.svelte`, `home/EnableAgentAccountsScreen.svelte` | “Apps & agents” summarizes these destinations; preserve every supported credential kind and action. Show optional/broad/unknown scope details, match-number checks, disabled/pending/denied/expired states, legacy app passwords and child-agent lifecycle. |
| Create identity | `onboarding/{AddIdentityScreen,IdentityMethodScreen,PdsConfigScreen,DestinationCapabilityNote,ClaimCodeScreen,EmailScreen,EmailVerificationScreen,HandleScreen,PasswordScreen,DIDCeremonyScreen,DIDSuccessScreen}.svelte` | Apply the new chrome/type/action system to existing steps. Keep validation, unavailable capabilities, verification pending, key ceremony, and `CreateRegistrationFailedScreen` / `CreateUnavailableScreen` branches. |
| Import and domain identity | `onboarding/{IdentityInputScreen,PdsAuthScreen,SourcePasswordAuthScreen,HandleRegistrationScreen,DidWebDomainScreen,DidWebPathScreen,DidWebCeremonyScreen}.svelte` | Keep the actual import/auth/registration variants; use domain-specific authority and errors. No PLC all-clear or recovery timer on did:web. |
| Key backup and recovery | `onboarding/{ShamirBackupScreen,RecoverStartScreen,RecoverSharesScreen,RecoverVerifyScreen,RecoverEscrowScreen,RecoverEpilogueScreen}.svelte`, `home/SelfHeldKitReviewScreen.svelte` | Prerequisite → input/review → actual outcome, with full share instructions and existing secure disclosure. Cover invalid/insufficient shares, pending escrow, cancellation and lost device. Never place secrets in analytics, URLs or ordinary browser persistence. |
| Moving and disaster recovery | `home/MoveOrRebuildScreen.svelte`, `onboarding/{MigrationStartScreen,MigrationSourceAuthScreen,MigrationReviewScreen,MigrationProgressScreen,DidWebMigrationReviewScreen,DisasterRecoveryStartScreen,DisasterRecoveryProgressScreen,ServerGoneScreen}.svelte` | Keep source/destination and identity visible. Preserve capability checks, actual progress, error/retry and unavailable-host paths; authority recovery and content reconstruction remain distinct. |
| Maintenance and settings | `home/{MediaBackupScreen,EndpointRepairScreen,ChangeHandleScreen,RotateRepoKeyScreen,DIDDocumentScreen,AdvancedToolsScreen,SettingsScreen,RemoveIdentityScreen,PasswordUnlockDialog}.svelte` | Full-width task rows into exact forms and reviews. Retain repository/media distinctions, destructive-action confirmation, unlock cancellation and long literal identifiers. Apply shared states to `onboarding/LoadingScreen.svelte` and `SuccessScreen.svelte`. |

Do not replace `DIDAvatar` or `SealEmblem` with the brand mark when their existing shape/state conveys identity or verification semantics. Audit each use; the new mark identifies the product, not cryptographic assurance.

## Brass Console

Routes are relative to `apps/admin-companion/src/routes/`. Read that app's `AGENTS.md` and keep `PinnedPairingGate`, guarded actions and existing pairing/session seams.

| Family | Routes | Design application and required states |
| --- | --- | --- |
| Server selection and pairing | `+page.svelte`, `pair/+page.svelte` | Explicit server selection, QR/manual pairing, multiple registrations, revoked/unpaired/error states. Keep nickname plus actual hostname visible. |
| Frequent command | `+page.svelte`, UI `CodeOutput.svelte` | Specimen exists. Colored command introduction → issuing server/confirmation → Generate. Output names its original server. Cover pending, biometric cancel/failure, request failure, duplicate prevention and native copy/share. |
| Accounts and access | `accounts/+page.svelte`, `account/+page.svelte`, `codes/+page.svelte`, `devices/+page.svelte`, `spaces/+page.svelte`, `moderation/+page.svelte` | Preserve separate routes, lists/detail, pagination, filters and exact confirmations. Preview groups are not new merged endpoints. Cover empty/missing/forbidden/revoked records and unknown values. |
| Operations | `transfers/+page.svelte`, `audit/+page.svelte`, `status/+page.svelte` | Exact timestamped rows and context. Keep transfer cancellation, degraded observations, partial data and in-flight request pinning. No chart/score substitute for literal data. |
| Settings and developer preview | `settings/+page.svelte`, `preview/+page.svelte` | Apply technical register and accessible controls. Developer previews inherit real tokens and remain developer-only. |

## Web and supporting assets

| Surface | Source | Required coverage beyond the specimen |
| --- | --- | --- |
| Obsign marketing | `sites/marketing/index.html`, `sites/marketing/assets/css/site.css` | Whole current narrative, conditional recovery/backup/migration explanations, FAQ, availability and waitlist. Email required/handle optional; validation, closed-list, submitting, success and failure. |
| Custos marketing | `sites/marketing/custos/index.html` | Complete capabilities and configuration limits, prerequisites, custody boundary, Brass Console, MCP/agents/Spaces discoverability, deploy guide and source. |
| Privacy | `sites/marketing/privacy.html` | Full current disclosures, contacts and policy details. Preserve actual retention/purposes; preview prose is abbreviated. |
| Social, icons and fonts | `sites/marketing/assets/og/{obsign,custos}.src.html`, `sites/marketing/assets/og/render.sh`, each site's head/favicon declarations and app icon sources referenced by each `src-tauri/tauri.conf.json` | Generate raster exports at actual target sizes, inspect small-scale marks, update accessible labels/OG metadata. Preserve both app bundle IDs and Keychain/iCloud identities. The SVG handoff masters are geometry sources, not signed app packages. |
| Docs gateway | `sites/docs/src/content/docs/index.mdx` | Two audience doors, search and responsive navigation; full destination list, not only the preview's example rows. |
| User guides | `sites/docs/src/content/docs/user/` | Getting started, signing in, backup, media backup, recovery, migration, screen guide. Updated real screenshots, links, terminology and audience-local previous/next. |
| Operator guides | `sites/docs/src/content/docs/operator/` | Running a relay, configuration, capabilities, backup, moderation, master-key runbook and screen guide. Preserve canonical runbook ordering and golden rule. |
| Generated reference | `sites/docs/src/content/docs/operator/reference/{api,config,capabilities,ipc}.md` | Real generated tables, anchors and provenance; do not hand-edit generated content to match the specimen. |
| Docs shell and support states | `sites/docs/astro.config.mjs`, `sites/docs/src/components/PageFrame.astro`, `sites/docs/src/styles/theme.css` | Header/sidebar audience scope, fixed-dark operator theme, mobile navigation, search results/no results, 404, code overflow, long tables, print/readability and deep links. |
| PDS public landing | `crates/pds/assets/landing.html`, `crates/pds/src/routes/landing.rs` | Actual hostname, signup policy, domains, version, DID, configured contact; safe escaping, optional/missing metadata and failed health probe. No public account/admin directory. |
| OAuth browser | `crates/pds/src/routes/oauth_templates.rs`, `crates/pds/src/routes/oauth.rs` | Consent, permission groups, broad Spaces warning, unknown tokens, QR/manual/same-device handoff, supported password fallback, pending/denied/expired/failure and no-redirect errors. Keep anti-CSRF/request binding, escaping and validated redirects. |

MCP and the sidecar are protocol/tool services; the notify relay has no HTTP UI. Their explanation and operational guidance belong in the existing marketing/docs scope. Do not invent separate websites for them.

## Completion tracking

During implementation, record each family’s migrated screens and test evidence in the implementation/test plan. Start with the named files, then refresh the inventory with:

```sh
rg --files apps/identity-wallet/src/lib/components apps/admin-companion/src/routes
rg --files sites/marketing sites/docs/src crates/pds/assets
rg -n 'fn (render_|error_page)' crates/pds/src/routes/oauth_templates.rs
```

The inventory preserves functional scope. Any deliberate IA, route or contract change needs its own explicit mapping and regression coverage before it replaces an existing path.
