# Four redesign proposals for Obsign, Custos, and Brass Console

> Historical design evidence. Follow the [selected Emphasis handoff](../../design-plans/2026-09-07-clear-signal-emphasis.md) for implementation. Earlier recommendations and prototype limits below describe their original review round.

Date: 2026-09-06

Status: historical exploration; replaced by the selected Emphasis handoff

Brief: explore broadly beyond the current gold/seal identity while preserving the product's spirit. Cover every existing web surface and both iOS apps.

## Recommendation

**Open Charter is my recommendation.** It gives the ecosystem an ownable public identity, carries long-form documentation well, and offers a substantial redesign without making the wallet's security tasks unfamiliar. **Clear Signal** is the strongest alternative if speed of comprehension outweighs editorial character. **Field Guide** changes task organization most; **Common Ground** makes the ecosystem's unusual custody and delegation relationships most visible, with the highest comprehension risk.

These are alternative systems, not ingredients for one combined theme. Pick a governing layout and interaction language; improvements to truthful status, accessibility, and audience separation belong in all four.

| Direction | Governing idea | Obsign | Brass Console | Main tradeoff | Relative implementation scope |
| --- | --- | --- | --- | --- | --- |
| Open Charter | A clear public record under your authority | Personal folios, plain status, deliberate review | A ruled operations ledger | Can feel bureaucratic if the document metaphor enters task labels | Medium: major visual change, moderate navigation change |
| Clear Signal | Know what is happening and what to do | State first, everyday actions close at hand | Exceptions and commands, with exact observations below | Can resemble a generic security utility unless its layout stays distinctive | Medium: new hierarchy and consolidated state presentation |
| Field Guide | Find the task, follow the procedure | Use / Protect / Move, with resumable journeys | Indexed commands and compact runbooks | Over-guidance could slow expert repeat use | High: flow grouping and recovery of interrupted journeys |
| Common Ground | Understand who can do what | Identity, connections, host, and recovery relationships | Server context with account/device relationships | A relationship view can become an abstract graph | High: resource navigation and relationship summaries |

Relative scope is a design judgment, not a delivery estimate. A selected direction needs a screen-by-screen implementation and test plan.

## What the review established

The live [Obsign](https://obsign.org/) and [Custos](https://obsign.org/custos/) pages devote their first viewport to a modest headline, long copy, and two links. Neither demonstrates the product in that space. There is room for a more memorable composition and for concrete evidence of the mechanism before an extended explanation.

The live [operator docs](https://docs.obsign.org/operator/) show both audiences expanded in the same sidebar, a theme control on the fixed-dark operator register, and a previous-page link back into user migration. Audience boundaries exist in styling but could do more work in navigation. Separate audience homes and local previous/next chains would make the documentation feel purpose-built.

The operator harness confirms that a tall federation report precedes the claim-code action, followed by a long stack of equally prominent navigation buttons. Exact data is valuable; putting the frequent action first would better serve its stated purpose. Server identity and request target pinning are already important invariants in the code and must survive every layout change.

The wallet already has a considered hierarchy: current `IdentityScreen.svelte` leads with state, then sign-in/app passwords/agents, moving or rebuilding, and maintenance. A redesign should develop that work, not claim that it is absent. Screenshot fixtures are useful visual evidence but are not uniformly current: `identity-detail.png` shows a DID-document view, not the current identity landing screen. This proposal uses current components for behavior and treats fixture layouts cautiously.

The current product briefs also contain historical scope language (the root brief calls the wallet the only frontend). The surface inventory below follows actual routes and current source, not that sentence. This task does not repair the briefs as a side effect.

## Shared commitments

- **Human and operator registers remain siblings.** Obsign uses plain language and light as its canonical appearance, with an intentional system-following dark version. Brass Console and operator web content remain dark, exact, and monospace-forward. Shared geometry and semantic tokens connect them; identical skins do not.
- **Security state is evidence, not decoration.** Distinguish checking, verified-at-a-time, stale/unavailable, unauthorized change, unusable device key, and closed recovery window. Display the check time. Never replace these with an invented protection score or treat missing data as a healthy result.
- **Preserve identity-type truth.** The PLC monitoring and 72-hour contest window apply to `did:plc`; `did:web` uses domain control. Do not display a PLC all-clear or countdown for a domain identity. Derive deadlines from authoritative operation data, not from when the app happened to detect a change.
- **State and action are separate.** An alert opens review. Review shows the affected identity, before/after, consequence, deadline, and the signed action. Keep biometric and other existing signing safeguards, explicit denial, and accessible alternatives to gestures. Do not turn a decorative tap on a mark into authorization.
- **Recovery paths stay distinct.** Contesting a PLC change, restoring a key on a new device using shares, moving to another host, and rebuilding missing content are different jobs. Identity recovery never promises that unavailable posts or media will reappear. Backup setup must describe the actual share locations and any-two requirement accurately.
- **Consent stays legible and complete.** Show server origin, requesting client and its actual identifier, affected identity, mandatory base access, optional grants, and broad Spaces warnings. Preserve wallet approval, same-device handoff, QR and typed-code fallback, number matching when applicable, password fallback where supported, and denied/expired/failed/pending states. Unknown permission tokens remain inspectable. Browser and wallet must agree on the chosen grants.
- **Operations remain bound to a server.** Keep nickname plus hostname visible on every screen and confirmation. Pin in-flight requests and outputs to their original server; a later switch cannot relabel them. No automatic active selection when an explicit choice is required. Successful code generation shows which server issued it.
- **Accessibility is a release criterion.** Target AAA text contrast (7:1 normal; 4.5:1 large), with status text plus shape/icon and stable placement. Minimum 44-point app targets, Dynamic Type, VoiceOver, keyboard access on web, clear focus, reduced motion, long strings, and no hover-only actions. The concepts are not an accessibility certification; final token pairs and real-device behavior require measurement.
- **Privacy and performance carry through.** Self-host fonts in the product; keep analytics confined to the existing marketing scope. No trackers or remote assets on auth, docs, or apps. Preserve server-rendered functional forms and readable no-JS auth errors. No new account, service, checkout, or telemetry product is implied.

## Open Charter

### Visual system

A contemporary civic publication: confident serif headlines, spacious white pages, strong horizontal rules, and exact marginal references. Deep oxblood replaces the broad use of wax gold; ink carries the hierarchy. The seal becomes a small abstract signet used at identity and signed-result boundaries, not a shield repeated on every section. This is graphic structure, not parchment, stamps, embossing, or legalistic copy.

Obsign uses Libre Caslon Display for public titles and occasional identity headings, Public Sans for every task, and JetBrains Mono only for identifiers and exact values. Keeping those existing self-hosted families makes the transition practical. Candidate palette: paper `#FFFFFF`, ink `#202327`, oxblood `#722F40`, pale neutral `#F3F3F1`. Brass Console uses blue-black `#141C25`, cool white `#F1F4F6`, and a lifted brass `#E5C786` for commands. Colors are concept swatches; production definitions remain OKLCH semantic tokens with verified pairs.

### All surfaces

| Surface | Complete direction |
| --- | --- |
| Obsign marketing | A large editorial headline, “Your identity. Under your authority.”, faces a personal identity folio demonstrating device / recovery / host roles. Scroll through control, watch, recover, move, then plain answers and the existing TestFlight waitlist. Keep availability and form failure states honest; use the real product instead of generic security imagery. |
| Custos marketing | A dark technical prospectus. “Host the data. Respect the owner.” leads beside a ruled custody hierarchy. Capability rows lead to deploy prerequisites and the canonical deployment guide. Give Brass Console, agents/MCP, and Spaces explicit locations without implying capabilities are enabled on every host. |
| Obsign app | The identity list is a short index of folios. Opening one reveals a handle, current verified state, check time, and a compact action index. Use, protection, moving/rebuilding, and deeper maintenance stay in recognizable groups. Creation/import is a sequence of straightforward forms; the final review resembles a readable document, with cryptographic evidence disclosed below. |
| Brass Console app | A server-bound ledger. Host context tops the page; Generate claim code is the first command. Beneath it are compact observed exceptions and a ruled action directory grouped into Accounts, Access, and Operations. Entity details and audit records use aligned terms and values, not stacks of bordered cards. A minted code appears as a clear output sheet with issuing host, copy/share, and real expiry only when provided. |
| Docs gateway and user docs | The gateway has two explicit doors: Using Obsign and Running Custos. User guides become readable chapters with task summaries, short procedures, relevant app crops, and contextual definitions. The chapter rail stays local to the user audience. |
| Operator docs and reference | Dark technical chapters: prerequisite → action → expected observation → failure branch. Configuration, capability and API tables retain generated provenance. Provide a prominent runbook entry, anchored headings, global search with audience labels, and an audience-local previous/next chain. |
| Browser consent, handoff, errors | A compact authorization document: requester and origin at top, requested access in ruled rows, approval channel below. The browser's number-match code is visually paired with its instruction; the wallet review uses the same order. Denial is a visible action. No-redirect errors state what failed and how to return safely to the initiating app. |
| PDS instance landing | An instance record headed by the actual hostname, with signup policy, user domains, version, DID, configured contact, and explicit health-check state. Human joining instructions precede a disclosed endpoint index. Brand cannot imply that an arbitrary instance is operated or audited by Obsign. |
| Privacy and web support states | A plain disclosure document with a concise data-purpose-retention summary using only existing policy facts. Waitlist validation, closed enrollment, network failure, docs 404, no search results, and empty instance metadata follow the same measured typography. Social previews and app icons use the signet/wordmark grammar, without authority seals or certification claims. |

### Behavior and adaptation

The signature interaction is **reviewing a change as a before/after record**, with one-line consequences before technical values. A successful signed result settles into an ordinary receipt; animation never implies verification ahead of the response. Mobile web moves margin notes into the text flow, preserves a single-column reading measure, and places the demonstrated folio after the main CTA. Phone apps retain native navigation and safe areas; large text converts paired values into stacked rows.

**Main risk:** the civic metaphor can become bureaucratic or imply official certification. Keep product labels like “Sign in” and “Move to another server”; never “Ratify,” “Charter,” or “Execute instrument.” Prove the direction with marketing, wallet unauthorized-change review, code generation, and one dense operator reference page before expanding it.

## Clear Signal

### Visual system

A modern information instrument built around a broad, calm status band and exceptionally clear action placement. The visual signature is a decisive horizontal division between observation and action, not an oversized metric or dashboard grid. Public Sans takes the lead at a more assertive scale; a consistent drawn icon vocabulary gives state shape. JetBrains Mono holds observations and literal output.

Obsign uses white, deep navy `#172847`, and an action cobalt `#234BA6`; pale blue supports neutral information, never an unearned all-clear. Brass Console uses navy-black `#101B2C`, cool white, and a pale blue action accent `#B9D7FF`. True warning/critical/expired states have independent semantic palettes. This intentionally leaves the gold/seal system behind while retaining calm, humane assurance.

### All surfaces

| Surface | Complete direction |
| --- | --- |
| Obsign marketing | “Know when something changes.” leads alongside a large product demonstration with a visible toggle between a checked identity and an unauthorized change. The primary TestFlight CTA remains visible without interacting. Below: what was checked, what an alert means, the conditional recovery path, backup and moving, plain answers, waitlist. Demonstration states are labeled examples. |
| Custos marketing | “Run your server. Read its state.” uses an actual operator observation specimen rather than KPI claims. An adjacent custody explanation separates availability, federation, and identity authority. Follow with capabilities, operational requirements, deploy guide and source. |
| Obsign app | Identities remain the primary scope. The selected identity opens with state + last check + one relevant action. A small everyday action strip handles sign-in and connected access; protection and maintenance follow. Alerts take priority without erasing other identities. A missing device key, offline directory, and unauthorized operation look and read differently. |
| Brass Console app | Host selector, Generate claim code, then an exception list tied to specific observations. Federation lag and stale sweep reports are compact rows, opening detailed evidence on tap. Navigation becomes a persistent small set of destinations: Actions, Accounts, Operations, Settings; devices/codes/Spaces/moderation remain explicit within those groups. Do not invent a combined “health” score. |
| Docs gateway and user docs | A task index emphasizing “Set up,” “Sign in,” “Recover,” and “Move.” Recovery pages begin with the relevant state and next action, then explain the mechanism. Search results label user/operator content; no all-audience sidebar. |
| Operator docs and reference | Procedure headings use the same observation vocabulary as console output. Each troubleshooting page starts with the symptom, the exact source observation, then checks and remedies. Configuration/API tables remain conventional and dense; diagrams are used only when they explain a relationship. |
| Browser consent, handoff, errors | A stable top band reads “Review access,” “Waiting for Obsign,” “Denied,” or “Request expired.” Request identity and grant details remain visible under it. Approval does not animate through success until the server confirms. Keep channel fallbacks accessible within the same request and show match numbers without a theatrical countdown. |
| PDS instance landing | Hostname and explicit observation state first, then joining policy and verified configuration facts. “Could not check” is a full state, not a red outage claim. Endpoint details live below. No uptime percentage or response-time boast from a one-off health probe. |
| Privacy and web support states | Direct, readable disclosure sections, accessible form feedback, inline waitlist retry, readable no-JS paths and 404/search-empty states. Identity iconography has a fixed shape per state; brand mark stays separate so the brand itself never means “safe.” |

### Behavior and adaptation

The signature is **observation → action → verified result** in a stable page region. Text persists through loading; fresh data updates the observation time. On narrow layouts the band becomes a stacked heading and explanation, with no fixed height. The action rail moves into natural document flow at large text sizes. Reduced motion uses instant state replacement. Dark Obsign remains a readable inverse, not the console palette pasted onto a consumer app.

**Main risk:** a handsome utility with little identity of its own, or a false impression of real-time monitoring. Enforce the broad state/action composition, precise check timestamps, and brand/status separation. Validate with stale directory data, a lost key, a PLC deadline crossing, and degraded server observations.

## Field Guide

### Visual system

A contemporary field manual and public wayfinding system: unmistakable task titles, short procedure rails, compact diagrams, and generous places to stop and check. The material reference is an excellent instruction system, not camping equipment, paper grain, badges, or survival drama.

Obsign uses white, dark evergreen `#173E37`, and forest action ink `#245B4A`. Black-on-white navigation remains primary; the neutral “Protect” category is never painted with the success color simply because of its name. Brass Console uses graphite-green `#14201E`, cool white, and muted lime `#D4E4A2` only for selected commands. Public Sans leads navigation, Libre Caslon Display gives long-form guides their reading voice, and JetBrains Mono identifies literal procedures and output.

### All surfaces

| Surface | Complete direction |
| --- | --- |
| Obsign marketing | “A clear way to keep your identity.” opens with three visible journeys: bring an account, protect it, recover or move when needed. A short illustrated procedure explains the product next to the TestFlight CTA; the explanation works without animation or selection. Continue through prerequisites, example recovery, backup responsibilities, answers and waitlist. |
| Custos marketing | A deployment field guide with the service boundary, real prerequisites, and routes into run/operate/restore documentation. A small console specimen proves that the pocket command loop exists. No pasted “one command” installation that hides persistent storage or production requirements. |
| Obsign app | Within the active identity, three durable sections—Use, Protect, Move—organize the current surface. Advanced identifiers and key operations live under clearly named details. Setup, import, share backup, new-device recovery and migration each show “what you need / next step / result.” Experienced users can go directly to a known action; routine sign-in is not wrapped in a tutorial. |
| Brass Console app | A compact command index for the selected host: issue access, manage accounts, manage devices, inspect operations. Frequent Generate claim code stays above the index. Commands reveal prerequisites only when relevant, then a single review and literal result. Runbook help is adjacent to a failed command, not a permanent novice layer. |
| Docs gateway and user docs | Help mirrors Use / Protect / Move. Every procedure names its starting condition, what to have ready, the steps, how to know it worked, and what to do if it did not. Long background explanations are separate linked chapters. Recovery pages remain directly addressable without answering a wizard. |
| Operator docs and reference | Task runbooks and reference are clearly different reading modes. Runbooks preserve the canonical disaster ordering and golden rule verbatim where parity requires it. Reference pages retain searchable generated tables; steps never replace the API contract. |
| Browser consent, handoff, errors | A short sequence: identify the app → review its access → approve using Obsign. The screen always names the current stage and retains Deny. QR, typed code and supported password paths are alternate channels, not three extra steps. Request expiry says to restart from the client; invalid redirect errors never offer an unvalidated destination. |
| PDS instance landing | “Joining this server” leads to the real prerequisites: this host's enrollment policy and, when required, an operator-issued claim code entered in Obsign. Below it, an operator path exposes facts and endpoints. Do not add a fake browser registration form. |
| Privacy and web support states | Privacy reads as a straightforward guide to the existing data practices. Empty and failure states explain the next available action and preserve entered non-secret form data when safe. Offline reading and print styles make recovery documentation usable beyond the happy path; printable material excludes secrets by default. |

### Behavior and adaptation

The signature is **a journey that resumes at the correct step**. Resume labels are based on existing persisted state; new persistence is a separately scoped implementation requirement, never browser storage for keys or recovery shares. Destructive actions retain their own confirmation rather than disappearing into “Next.” A left procedure rail on wide web becomes an ordinary step heading on mobile. Completed steps show factual outcomes, not achievement badges. Motion is one modest between-step transition with an instant alternative.

**Main risk:** turning a pocket instrument into a course. Measure the repeat-user sign-in and code-generation paths, and permit direct entry to known tasks. This direction requires more flow work than changing tokens and navigation labels.

## Common Ground

### Visual system

A designed relationship index in the tradition of excellent transit information and public directories. Strong names, connecting rules, and direct labels explain the boundaries between a person, their apps, their host, and their recovery options. It never becomes a pan-and-zoom node graph. On the phone, relationships are text rows with ordinary navigation.

Obsign uses white, plum-black `#30243F`, plum action ink `#633A78`, and a very pale lilac field for relationship context. A restrained coral is reserved for optional illustration accents, never competing with the alarm palette. Brass Console uses blue-black `#171D2B`, near-white, and pale lavender `#D6C5F1` for selection. Public Sans dominates; JetBrains Mono distinguishes endpoints, identities and permissions. A simple paired-line mark replaces the seal, with distinct terminal shapes for the two products.

### All surfaces

| Surface | Complete direction |
| --- | --- |
| Obsign marketing | “Your account can change homes. It stays yours.” pairs a clear identity → host relationship specimen with visible labels for device authority and recovery. An optional host-change demonstration keeps the identity fixed; it is explicitly conceptual and does not promise universal migration or content availability. Continue through connected apps, custody, monitoring/recovery, backup, availability and waitlist. |
| Custos marketing | A responsibility diagram: wallet controls identity; PDS hosts/signs repository data; network distributes it. Below, textual capability groups explain accounts, federation, agent/MCP access and Spaces. Technical relationships have named edges, never decorative animated traffic. Operator guide and source remain the actions. |
| Obsign app | Open an identity into an overview with four labeled groups: Identity, Connected access, Host & content, Recovery. Status remains first. Apps, agents and child identities sit under connected access with distinct kinds and permitted actions; moving/rebuilding sits with the host and backup. Details remain ordinary lists. This reorganizes the app around entities and relationships, not one giant map. |
| Brass Console app | An explicit server roster leads into the selected server's accounts, devices, codes and operational records. Within an account, relationships to credentials, sessions and Spaces appear as labeled rows, with exact identifiers one disclosure away or visible where operators need them. Server switching remains explicit and every pending operation stays pinned. Claim-code generation remains immediately available in the selected server context. |
| Docs gateway and user docs | A small custody diagram orients newcomers, then directs them to concrete tasks. User docs explain “your device,” “your host,” “your backup,” and “connected apps” through the same labels as the wallet. Every diagram has a linear equivalent. |
| Operator docs and reference | Diagrams document responsibility boundaries and credential flows before handing off to procedures and exact reference. Node/edge labels reference real concepts from the source; they are not a second invented architecture. Deep links connect entities to existing API/configuration tables. |
| Browser consent, handoff, errors | The strongest consent fit: requester → identity → permitted resources. Scope rows group resources, capabilities and authority; wildcard warnings are prominent and raw tokens remain available. The browser and wallet use identical ordering and names. Channel controls and denial remain conventional; connecting lines do not imply cryptographic verification of client-supplied display names. |
| PDS instance landing | A public server profile clearly separates the instance's operator/configuration from the Obsign project. Show host, joining policy, public metadata and documentation connections. Expose only the facts already intended to be public, not a directory of hosted people or admin devices. |
| Privacy and web support states | A simple data-flow illustration supplements full policy text: browser → marketing analytics, waitlist → Custos storage, with existing limits and purposes. It is explanatory, not a new promise about deletion or retention. Missing and unavailable relationships use text states; no broken-line-only errors. |

### Behavior and adaptation

The signature is **changing context while keeping the affected identity visible**. Opening a host or app relationship retains the identity in the header and shows the specific permission or operation below. Mobile becomes one column; relationship lines disappear when they cannot help. Screen readers receive subject, relationship, and object as text. No drag-only control, animated network background, or secret-bearing graph is introduced.

**Main risk:** introducing conceptual work where someone needs a simple action. Test whether a nontechnical person can find sign-in, explain who controls the account, and distinguish recovering an identity from restoring content. If the diagram requires explanation, simplify it to a labeled list rather than teaching graph navigation.

## Full functional coverage

The visual explorer contains representative concepts, not every implemented screen. The table below makes the remaining coverage explicit. All four proposals carry these functions and states; their grouping differs as described above.

| Existing surface family | Retained content and edge cases | Location in the four proposals (Charter / Signal / Guide / Ground) |
| --- | --- | --- |
| Wallet entry and creation | Welcome; add identity; server selection/capability note; claim code; email/verification; handle/password where applicable; key ceremony; registration failure; unavailable creation | Folio setup / Setup / Start a journey / Add identity |
| Wallet import and identity methods | Existing PLC import; source authentication; review; `did:web` domain/path/ceremony; handle registration; DID success | Add folio / Add identity / Bring an identity / Add identity |
| Wallet home and identity | Multi-identity list; protection overview; per-identity status; refresh, stale/offline, load error; unusable key; settings | Index → folio / Identities → state / Identities → Use / Identities → overview |
| Connected access | OAuth code/QR approval; number matching; scope reduction; legacy app passwords; agents, claims, child identities; enabling/deleting child access as supported | Use / Access / Use / Connected access |
| Wallet protection and recovery | Unauthorized change review; PLC override; expired window; rekey review; share backup; share input/verification; escrow pending; disaster recovery and server gone | Protection chapter / State → review / Protect / Recovery |
| Wallet hosting and maintenance | Move/rebuild; migration source/destination/review/progress; did:web migration review; repository/media backup and settings; endpoint repair; handle change; repo-key rotation; DID document; advanced tools; self-held recovery kit; remove identity | Move + maintenance / Host + details / Move + advanced details / Host & content + identity details |
| Console entry and frequent action | Pair QR/manual; unpaired; multiple hosts; explicit active-host selection; pairing failure/revocation; biometric cancel/error; mint/copy/share; pending and issued codes | Host ledger / Actions / Command index / Selected server |
| Console accounts and trust | Accounts/detail; device management; codes; moderation; Spaces; account preview; exact action confirmation; unknown/missing/forbidden data | Accounts + access / Accounts + operations / Accounts + access commands / Server relationships |
| Console operations | Transfers and cancellation; audit; status/metrics; degraded health; stale observations; diagnostic settings; per-host request pinning | Operations ledger / Operations / Inspect commands / Server operations |
| Public marketing | Obsign home; Custos home; waitlist; errors; policy disclosure; footer; social preview/favicon | Editorial record / State demonstration / Task journeys / Custody relationships |
| Documentation | Shared gateway; user guide set; operator guide set; generated API/config/capability/IPC reference; search, 404, mobile sidebar, pagination | Chapters / Task and symptom index / Procedures + reference / Concept orientation + tasks |
| PDS browser HTML | Instance root; rendered contact/signup/domain/version/DID; health fallback; consent/password/wallet paths; inline errors; untrusted redirect refusal | Instance/authorization record / Observation/decision state / Join/review procedures / Profile/access relationships |

MCP and MCP-sidecar are protocol/tool surfaces, not separate browser applications in the inspected source. Their discoverability, concepts and setup belong on Custos marketing and operator docs. The notify relay has no HTTP surface; its enrollment and operations belong in the existing console/docs scope where supported. Developer-only preview/harness screens should inherit the chosen tokens and gain realistic states; they do not become new public products.

## Responsive, content, and delivery plan

1. **Choose one system using a common evidence set.** Compare marketing at desktop and mobile, a wallet identity with an unauthorized change, routine console code generation, a dense operator document, and browser/wallet consent. Evaluate equal content, not one direction's friendly welcome against another's hardest screen.
2. **Define the two registers and shared semantics.** Create token specifications for light/dark Obsign and dark operator surfaces; preserve user/operator separation. Consolidate typography, spacing, focus and status semantics across the five font/token consumers. Store documented and tested tokens rather than manually letting app, marketing, docs and auth forks diverge.
3. **Pilot the critical flows.** Use the existing browser harnesses for healthy, stale, critical, expired, unpaired, multi-host, degraded, failed and empty states. Include long identifiers and translated-length text. Use native iOS checks for Dynamic Type, VoiceOver, safe areas, biometrics, share sheet, camera permission and notification handling; a browser harness cannot certify them.
4. **Extend by surface family.** Implement shared app primitives, then wallet/console families, marketing/instance pages, docs and consent together with their screenshots and copy. Retain existing information and routes unless a deliberate migration is documented. Authentication labels can change only while preserving scope and wire semantics.
5. **Validate the selected design at its actual scope.** Verify app checks and UI token/capability gates; docs/font parity; appropriate Rust/OAuth conformance when templates change; runbook parity when docs change; no-JS browser paths and analytics boundaries. Audit contrast on actual surfaces and large text behavior. Regenerate deterministic docs screenshots after navigation changes and verify that filenames/captions show the intended screen.

Success criteria are observable: people identify the product and its next action from the first marketing viewport; routine console minting requires no scroll on a standard phone; user and operator documentation do not cross audiences in local navigation; an unverified reading never looks verified; all prior functions remain reachable; and a person under alarm can identify the affected account, deadline, and review action without opening technical details.

## Evidence and limits

Reviewed live marketing and operator documentation; ran the operator app's fake browser harness; inspected both apps' product/design briefs, current route/component structure, token systems, and committed screenshot fixtures; inspected PDS landing and OAuth rendering source. A separate wallet harness was started but exited after exhausting the Node heap; wallet behavior is grounded in current source and committed fixtures rather than a successful live wallet walkthrough. The visual explorer was checked in the browser at desktop and contained 390-pixel phone layouts, including direction/surface selection and example states. No live credential grants or submissions were performed. The main branch was clean at the initial inspection.

Primary local sources: [Obsign product brief](../../../PRODUCT.md), [Obsign design](../../../DESIGN.md), [operator product brief](../../../apps/admin-companion/PRODUCT.md), [operator design](../../../apps/admin-companion/DESIGN.md), [wallet identity surface](../../../apps/identity-wallet/src/lib/components/home/IdentityScreen.svelte), [operator home](../../../apps/admin-companion/src/routes/+page.svelte), [marketing](../../../sites/marketing/README.md), [docs](../../../sites/docs/README.md), [consent templates](../../../crates/pds/src/routes/oauth_templates.rs), [instance template](../../../crates/pds/assets/landing.html).

Entire is enabled; a relevant checkpoint named in the git history was unavailable locally. Behavioral conclusions above come from current source and rendered evidence, not a reconstructed session transcript. These are design hypotheses and comparative judgments, not user-testing findings. Concept copy, sample identities, match numbers and operational observations in the visual explorer are illustrative; no uptime, security certification, commercial availability or migration guarantee is invented.
